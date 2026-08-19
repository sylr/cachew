package oidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/block/cachew/internal/logging"
)

// testIssuer is a fake OIDC provider serving a discovery document and a JWKS over
// TLS, so that tests exercise the real https-only code path.
type testIssuer struct {
	t      *testing.T
	server *httptest.Server

	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey

	// keys is the JWKS served to clients. Swapping it simulates key rotation.
	keys atomic.Pointer[jwk.Set]

	// jwksRequests and discoveryRequests count fetches, to prove caching,
	// rotation and request-collapsing behaviour.
	jwksRequests      atomic.Int64
	discoveryRequests atomic.Int64

	// jwksBroken and discoveryBroken make the respective endpoints fail,
	// simulating an unreachable issuer.
	jwksBroken      atomic.Bool
	discoveryBroken atomic.Bool

	// omitJWKAlg drops the "alg" field from published keys, as some real
	// providers do; verification must still work.
	omitJWKAlg atomic.Bool

	// discoveryIssuer overrides the issuer advertised by the discovery document.
	discoveryIssuer atomic.Pointer[string]
}

const (
	testRSAKeyID = "rsa-1"
	testECKeyID  = "ec-1"
)

func newTestIssuer(t *testing.T) *testIssuer {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	assert.NoError(t, err)

	ti := &testIssuer{t: t, rsaKey: rsaKey, ecKey: ecKey}
	ti.setKeys(map[string]any{testRSAKeyID: rsaKey.Public(), testECKeyID: ecKey.Public()})

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", ti.serveDiscovery)
	mux.HandleFunc("/jwks.json", ti.serveJWKS)
	ti.server = httptest.NewTLSServer(mux)
	t.Cleanup(ti.server.Close)

	return ti
}

// URL is the issuer identifier, which doubles as the discovery base URL.
func (ti *testIssuer) URL() string { return ti.server.URL }

// Client returns an http.Client trusting the fake issuer's certificate.
func (ti *testIssuer) Client() *http.Client { return ti.server.Client() }

// setKeys replaces the published JWKS with public keys keyed by kid.
func (ti *testIssuer) setKeys(keys map[string]any) {
	ti.t.Helper()
	set := jwk.NewSet()
	for kid, pub := range keys {
		key, err := jwk.Import(pub)
		assert.NoError(ti.t, err)
		assert.NoError(ti.t, key.Set(jwk.KeyIDKey, kid))
		switch pub.(type) {
		case *rsa.PublicKey:
			assert.NoError(ti.t, key.Set(jwk.AlgorithmKey, jwa.RS256()))
		case *ecdsa.PublicKey:
			assert.NoError(ti.t, key.Set(jwk.AlgorithmKey, jwa.ES384()))
		}
		assert.NoError(ti.t, set.AddKey(key))
	}
	ti.keys.Store(&set)
}

func (ti *testIssuer) serveDiscovery(w http.ResponseWriter, _ *http.Request) {
	ti.discoveryRequests.Add(1)
	if ti.discoveryBroken.Load() {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}
	issuer := ti.server.URL
	if override := ti.discoveryIssuer.Load(); override != nil {
		issuer = *override
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{ //nolint:errcheck
		"issuer":   issuer,
		"jwks_uri": ti.server.URL + "/jwks.json",
	})
}

func (ti *testIssuer) serveJWKS(w http.ResponseWriter, _ *http.Request) {
	ti.jwksRequests.Add(1)
	if ti.jwksBroken.Load() {
		http.Error(w, "unavailable", http.StatusInternalServerError)
		return
	}

	set := *ti.keys.Load()
	encoded, err := json.Marshal(set)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if ti.omitJWKAlg.Load() {
		encoded = stripJWKField(ti.t, encoded, "alg")
	}

	// No caching, so that rotation tests observe a fresh fetch.
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(encoded) //nolint:errcheck
}

// stripJWKField removes a field from every key in a serialised JWKS.
func stripJWKField(t *testing.T, encoded []byte, field string) []byte {
	t.Helper()
	var doc struct {
		Keys []map[string]any `json:"keys"`
	}
	assert.NoError(t, json.Unmarshal(encoded, &doc))
	for _, key := range doc.Keys {
		delete(key, field)
	}
	out, err := json.Marshal(doc)
	assert.NoError(t, err)
	return out
}

// tokenOptions describes a token to mint. The zero value produces a valid token
// for the given issuer and audience.
type tokenOptions struct {
	Issuer    string
	Audience  []string
	Subject   string
	IssuedAt  time.Time
	NotBefore time.Time
	ExpiresAt time.Time
	Claims    map[string]any

	// Algorithm and Key select the signing algorithm and key. Defaults to RS256
	// with the issuer's RSA key.
	Algorithm jwa.SignatureAlgorithm
	Key       any
	KeyID     string

	// OmitKeyID suppresses the kid header.
	OmitKeyID bool

	// OmitExpiry suppresses the exp claim, producing a token that never expires.
	OmitExpiry bool
}

// mint builds and signs a token according to opts.
func (ti *testIssuer) mint(opts tokenOptions) string {
	ti.t.Helper()

	now := time.Now()
	builder := jwt.NewBuilder()

	issuer := opts.Issuer
	if issuer == "" {
		issuer = ti.server.URL
	}
	builder = builder.Issuer(issuer)

	if opts.Audience != nil {
		builder = builder.Audience(opts.Audience)
	}
	subject := opts.Subject
	if subject == "" {
		subject = "arn:aws:iam::123456789012:role/cachew-admin"
	}
	builder = builder.Subject(subject)

	issuedAt := opts.IssuedAt
	if issuedAt.IsZero() {
		issuedAt = now
	}
	builder = builder.IssuedAt(issuedAt)

	if !opts.OmitExpiry {
		expiresAt := opts.ExpiresAt
		if expiresAt.IsZero() {
			expiresAt = now.Add(5 * time.Minute)
		}
		builder = builder.Expiration(expiresAt)
	}

	if !opts.NotBefore.IsZero() {
		builder = builder.NotBefore(opts.NotBefore)
	}
	for name, value := range opts.Claims {
		builder = builder.Claim(name, value)
	}

	token, err := builder.Build()
	assert.NoError(ti.t, err)

	alg := opts.Algorithm
	key := opts.Key
	kid := opts.KeyID
	if alg.String() == "" {
		alg = jwa.RS256()
	}
	if key == nil {
		switch alg {
		case jwa.ES384():
			key, kid = ti.ecKey, testECKeyID
		default:
			key, kid = ti.rsaKey, testRSAKeyID
		}
	}
	if opts.KeyID != "" {
		kid = opts.KeyID
	}

	headers := jws.NewHeaders()
	if !opts.OmitKeyID {
		assert.NoError(ti.t, headers.Set(jws.KeyIDKey, kid))
	}

	signed, err := jwt.Sign(token, jwt.WithKey(alg, key, jws.WithProtectedHeaders(headers)))
	assert.NoError(ti.t, err)
	return string(signed)
}

// newRequest builds a request carrying a logger, as the middleware expects.
func newRequest(target, authorization string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, target, nil)
	if authorization != "" {
		r.Header.Set("Authorization", authorization)
	}
	r.RemoteAddr = "10.0.0.1:1234"
	return r.WithContext(logging.ContextWithLogger(r.Context(), slog.Default()))
}
