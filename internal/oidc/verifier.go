package oidc

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/errors"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
	"golang.org/x/sync/singleflight"
)

// Timeouts bounding outbound requests to an issuer. They are variables so tests
// can shorten them; see export_test.go.
//
//nolint:gochecknoglobals
var (
	// discoveryTimeout bounds a single OIDC discovery document fetch.
	discoveryTimeout = 30 * time.Second
	// jwksTimeout bounds waiting for an issuer's JWKS. Exceeding it fails the
	// request closed rather than blocking a handler indefinitely.
	jwksTimeout = 10 * time.Second
	// refreshCooldown is the minimum interval between forced JWKS refreshes for an
	// issuer. Without it, an unauthenticated caller could send tokens bearing
	// arbitrary key IDs and have cachew hammer the issuer with one fetch per
	// request.
	refreshCooldown = time.Minute
)

// Verifier verifies bearer tokens against a fixed set of trusted issuers.
type Verifier struct {
	issuers map[string]*issuer
	cache   *jwk.Cache
	client  *http.Client

	// mu guards resolution of JWKS URIs, which happens lazily so that an issuer
	// that is unreachable at startup does not prevent the process from booting,
	// and the fetch cooldowns.
	mu              sync.Mutex
	resolved        map[string]string
	lastRefresh     map[string]time.Time
	discoveryFailed map[string]time.Time

	// discovery and refresh collapse concurrent work for the same issuer into a
	// single request. Besides sparing the issuer a stampede, this is required for
	// correctness under load: concurrent forced refreshes of one JWKS contend
	// inside the cache and time out rather than all succeeding.
	discovery singleflight.Group
	refresh   singleflight.Group
}

// NewVerifier validates configs and prepares JWKS fetching for each issuer.
//
// Configuration errors are returned: a malformed issuer URL, a missing audience
// list or an unusable algorithm can never authenticate anyone, so the caller
// should treat them as fatal. Network failures are not returned — JWKS resolution
// happens lazily and is retried, so a transient outage at the issuer cannot stop
// the process from starting. While keys are unavailable, Verify fails closed.
func NewVerifier(ctx context.Context, configs []Config, client *http.Client) (*Verifier, error) {
	// No issuers means no verification. A nil Verifier is meaningful: Middleware
	// treats it as a pass-through, so the zero-configuration case costs nothing.
	if len(configs) == 0 {
		return nil, nil //nolint:nilnil
	}
	if client == nil {
		client = http.DefaultClient
	}

	issuers := make(map[string]*issuer, len(configs))
	for _, cfg := range configs {
		iss, err := cfg.validate()
		if err != nil {
			return nil, err
		}
		if _, exists := issuers[iss.name]; exists {
			return nil, errors.Errorf("oidc-issuer %q: duplicate issuer", iss.name)
		}
		issuers[iss.name] = iss
	}

	cache, err := jwk.NewCache(ctx, httprc.NewClient(httprc.WithHTTPClient(client)))
	if err != nil {
		return nil, errors.Errorf("create JWKS cache: %w", err)
	}

	v := &Verifier{
		issuers:         issuers,
		cache:           cache,
		client:          client,
		resolved:        map[string]string{},
		lastRefresh:     map[string]time.Time{},
		discoveryFailed: map[string]time.Time{},
	}

	// Pre-resolve issuers with an explicitly configured JWKS URI; these need no
	// network access, so registering them now means the first request does not
	// pay for it.
	for name, iss := range issuers {
		if iss.jwksURI == "" {
			continue
		}
		if err := v.register(ctx, name, iss.jwksURI); err != nil {
			return nil, err
		}
	}

	return v, nil
}

// Issuers returns the configured issuer URLs, for logging.
func (v *Verifier) Issuers() []string {
	names := make([]string, 0, len(v.issuers))
	for name := range v.issuers {
		names = append(names, name)
	}
	return names
}

// Recognizes reports whether raw parses as a JWT whose issuer is one of the
// configured issuers.
//
// The middleware uses this to decide whether a Bearer credential is addressed to
// cachew at all: tokens for other services (an Artifactory access token, a GitHub
// PAT) must pass through untouched so strategies can forward them upstream, while
// anything claiming a configured issuer MUST verify — a forgery naming a trusted
// issuer is still rejected, because recognition reads the unverified payload only
// to route, never to authenticate.
func (v *Verifier) Recognizes(raw string) bool {
	unverified, err := jwt.ParseInsecure([]byte(raw))
	if err != nil {
		return false
	}
	name, ok := unverified.Issuer()
	if !ok {
		return false
	}
	_, trusted := v.issuers[name]
	return trusted
}

// Verify parses and verifies a raw compact JWS token, returning its claims.
//
// Every failure mode returns an error; there is no path on which an unverified
// token yields claims. In particular an unavailable JWKS is an error rather than
// a reason to skip verification.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Claims, error) {
	alg, kid, err := protectedHeader(raw)
	if err != nil {
		return nil, err
	}

	// Peek at the issuer without verifying anything, purely to decide which
	// configured issuer's keys and rules to apply.
	unverified, err := jwt.ParseInsecure([]byte(raw))
	if err != nil {
		return nil, errors.Errorf("parse token: %w", err)
	}
	name, ok := unverified.Issuer()
	if !ok || name == "" {
		return nil, errors.New("token has no iss claim")
	}
	iss, ok := v.issuers[name]
	if !ok {
		return nil, errors.Errorf("untrusted issuer %q", name)
	}

	// Enforce the algorithm allow-list against the token's own header before
	// verifying. The algorithm is then passed explicitly to jwt.WithKey below, so
	// this check is the only thing that decides which algorithms are usable — and
	// because the list is asymmetric-only, an HMAC token signed with the public
	// key cannot be substituted.
	if !iss.allowsAlgorithm(alg) {
		return nil, errors.Errorf("issuer %q does not allow signature algorithm %q", name, alg)
	}

	key, err := v.lookupKey(ctx, iss, kid)
	if err != nil {
		return nil, err
	}

	// Passing the key directly rather than the whole set means the JWK does not
	// need to carry an "alg" field, which some providers omit.
	// exp is required explicitly: jwx's expiry validator is a no-op when the claim
	// is absent, so without this a correctly signed token with no expiry would be
	// accepted forever.
	token, err := jwt.Parse([]byte(raw),
		jwt.WithKey(alg, key),
		jwt.WithValidate(true),
		jwt.WithIssuer(name),
		jwt.WithRequiredClaim(jwt.ExpirationKey),
		jwt.WithAcceptableSkew(iss.clockSkew),
	)
	if err != nil {
		return nil, errors.Errorf("verify token: %w", err)
	}

	audience, _ := token.Audience()
	if !iss.acceptsAudience(audience) {
		return nil, errors.Errorf("token audience %v matches none of the audiences configured for issuer %q", audience, name)
	}

	return newClaims(token)
}

// protectedHeader extracts the algorithm and key ID from a compact JWS token.
//
// A key ID is required: without it jwx would have to try every key in the set,
// and we would lose the guarantee that the signature was made by the specific
// key the issuer advertised for it.
func protectedHeader(raw string) (jwa.SignatureAlgorithm, string, error) {
	var empty jwa.SignatureAlgorithm

	// Reject the JSON serialisations up front. Only compact tokens are valid in
	// an Authorization header, and accepting multi-signature forms would mean
	// reasoning about which signature was verified.
	if strings.Count(raw, ".") != 2 {
		return empty, "", errors.New("token is not in JWS compact serialization")
	}
	msg, err := jws.Parse([]byte(raw), jws.WithCompact())
	if err != nil {
		return empty, "", errors.Errorf("parse token signature: %w", err)
	}
	signatures := msg.Signatures()
	if len(signatures) != 1 {
		return empty, "", errors.Errorf("expected exactly one signature, got %d", len(signatures))
	}

	headers := signatures[0].ProtectedHeaders()
	alg, ok := headers.Algorithm()
	if !ok {
		return empty, "", errors.New("token has no alg header")
	}
	kid, ok := headers.KeyID()
	if !ok || kid == "" {
		return empty, "", errors.New("token has no kid header")
	}
	return alg, kid, nil
}

// lookupKey returns the issuer's verification key with the given key ID.
//
// The cached JWKS is consulted first. A cache miss on the key ID triggers one
// forced refresh, so a key the issuer has just rotated in is picked up on the next
// request rather than only after the background refresh interval elapses.
func (v *Verifier) lookupKey(ctx context.Context, iss *issuer, kid string) (jwk.Key, error) {
	uri, err := v.jwksURI(ctx, iss)
	if err != nil {
		return nil, err
	}

	lookupCtx, cancel := context.WithTimeout(ctx, jwksTimeout)
	defer cancel()

	// A Lookup error also covers the case where no fetch has succeeded yet, so
	// fall through to a forced refresh rather than failing.
	haveKeys := false
	if set, err := v.cache.Lookup(lookupCtx, uri); err == nil {
		haveKeys = true
		if key, ok := set.LookupKeyID(kid); ok {
			return key, nil
		}
	}

	// One cooldown covers both the unknown-kid path (attacker controlled, must
	// not become per-request load on the issuer) and the cold path (during an
	// issuer outage, per-request fetches would hold every handler for the full
	// timeout and hammer the recovering issuer).
	set, err := v.refreshKeys(ctx, uri)
	if errors.Is(err, errRefreshRateLimited) {
		if haveKeys {
			// The key ID is unknown and we declined to re-fetch; report that
			// rather than the rate limit, which is an internal detail.
			return nil, errors.Errorf("issuer %q has no key with kid %q", iss.name, kid)
		}
		return nil, errors.Errorf("JWKS for issuer %q is unavailable, retry pending", iss.name)
	}
	if err != nil {
		return nil, errors.Errorf("fetch JWKS for issuer %q: %w", iss.name, err)
	}
	key, ok := set.LookupKeyID(kid)
	if !ok {
		return nil, errors.Errorf("issuer %q has no key with kid %q", iss.name, kid)
	}
	return key, nil
}

// errRefreshRateLimited reports that the cooldown blocked a forced JWKS fetch.
var errRefreshRateLimited = errors.New("JWKS refresh rate limited") //nolint:gochecknoglobals

// refreshKeys forces a JWKS fetch, collapsing concurrent callers for the same URI
// into one request.
//
// The fetch runs on a context detached from any single caller's, so that one
// client disconnecting does not cancel the work every other caller is waiting on.
func (v *Verifier) refreshKeys(ctx context.Context, uri string) (jwk.Set, error) {
	result, err, _ := v.refresh.Do(uri, func() (any, error) {
		if !v.reserveRefresh(uri) {
			return nil, errRefreshRateLimited
		}
		fetchCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), jwksTimeout)
		defer cancel()
		return v.cache.Refresh(fetchCtx, uri)
	})
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return result.(jwk.Set), nil //nolint:errcheck
}

// reserveRefresh claims the right to force a JWKS fetch for uri, returning whether
// the caller may proceed.
//
// The check and the record are one locked operation: splitting them would let a
// burst of concurrent unknown-key requests all observe an expired cooldown and
// stampede the issuer, which is exactly what the cooldown exists to prevent. The
// very first fetch is always allowed because the zero time is beyond any cooldown.
func (v *Verifier) reserveRefresh(uri string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	if time.Since(v.lastRefresh[uri]) < refreshCooldown {
		return false
	}
	v.lastRefresh[uri] = time.Now()
	return true
}

// jwksURI returns the cached JWKS URI for iss, discovering it if necessary.
func (v *Verifier) jwksURI(ctx context.Context, iss *issuer) (string, error) {
	v.mu.Lock()
	uri, ok := v.resolved[iss.name]
	v.mu.Unlock()
	if ok {
		return uri, nil
	}

	resolved, err, _ := v.discovery.Do(iss.name, func() (any, error) {
		// Re-check inside the group: a concurrent caller may have resolved this
		// issuer while we were queued behind it. The failure cooldown makes an
		// unreachable issuer fail fast instead of holding every handler for the
		// discovery timeout and retrying the issuer once per request.
		v.mu.Lock()
		cached, cachedOK := v.resolved[iss.name]
		failedAt := v.discoveryFailed[iss.name]
		v.mu.Unlock()
		if cachedOK {
			return cached, nil
		}
		if since := time.Since(failedAt); since < refreshCooldown {
			return "", errors.Errorf("OIDC discovery for issuer %q failed %s ago, retry pending", iss.name, since.Round(time.Second))
		}

		// Detached from the calling request for the same reason as refreshKeys:
		// one client giving up must not cancel the shared discovery.
		discoveryCtx := context.WithoutCancel(ctx)
		discovered, err := v.discover(discoveryCtx, iss.name)
		if err != nil {
			v.mu.Lock()
			v.discoveryFailed[iss.name] = time.Now()
			v.mu.Unlock()
			return "", err
		}
		if err := v.register(discoveryCtx, iss.name, discovered); err != nil {
			return "", err
		}
		return discovered, nil
	})
	if err != nil {
		return "", errors.WithStack(err)
	}
	return resolved.(string), nil //nolint:errcheck
}

// register records the JWKS URI for an issuer and asks the cache to keep it fresh.
func (v *Verifier) register(ctx context.Context, name, uri string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	if _, ok := v.resolved[name]; ok {
		return nil
	}
	// WithWaitReady(false) because the default blocks until the first fetch
	// succeeds, which would hang startup (and every request) while an issuer is
	// unreachable. Lookup is bounded separately and fails closed instead.
	err := v.cache.Register(ctx, uri,
		jwk.WithMinInterval(DefaultMinRefreshInterval),
		jwk.WithMaxInterval(DefaultMaxRefreshInterval),
		jwk.WithWaitReady(false),
	)
	if err != nil {
		return errors.Errorf("register JWKS %q for issuer %q: %w", uri, name, err)
	}
	v.resolved[name] = uri
	return nil
}

// discoveryDocument is the subset of the OIDC discovery document we need.
type discoveryDocument struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

// discover fetches {issuer}/.well-known/openid-configuration and returns its
// jwks_uri. The advertised issuer must match the one we asked for, otherwise a
// compromised or misconfigured discovery endpoint could redirect verification at
// keys belonging to somebody else.
func (v *Verifier) discover(ctx context.Context, name string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	endpoint := strings.TrimSuffix(name, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", errors.Errorf("build discovery request for issuer %q: %w", name, err)
	}
	resp, err := v.client.Do(req)
	if err != nil {
		return "", errors.Errorf("fetch OIDC discovery document for issuer %q: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", errors.Errorf("fetch OIDC discovery document for issuer %q: unexpected status %s", name, resp.Status)
	}

	var doc discoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return "", errors.Errorf("decode OIDC discovery document for issuer %q: %w", name, err)
	}
	if doc.Issuer != name {
		return "", errors.Errorf("OIDC discovery document for issuer %q advertises issuer %q", name, doc.Issuer)
	}
	if err := requireHTTPS(doc.JWKSURI, "jwks_uri"); err != nil {
		return "", errors.Errorf("OIDC discovery document for issuer %q: %w", name, err)
	}
	return doc.JWKSURI, nil
}
