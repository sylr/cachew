// Package tokensource mints the OIDC bearer tokens the cachew client presents to
// a cachew server.
package tokensource

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/alecthomas/errors"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Source produces a bearer token, minting or refreshing it as needed.
//
// Implementations must be safe for concurrent use: the client issues many
// requests in parallel when downloading snapshots.
type Source interface {
	Token(ctx context.Context) (string, error)
}

// Config describes how a client context obtains a token. Exactly one of AWSSTS,
// Exec or Static must be set.
type Config struct {
	Audience           []string      `hcl:"audience,optional" help:"Token audiences, which must match an audience the server accepts."`
	SigningAlgorithm   string        `hcl:"signing-algorithm,optional" default:"RS256" help:"Signing algorithm to request: RS256 or ES384."`
	Duration           time.Duration `hcl:"duration,optional" default:"15m" help:"Requested token lifetime."`
	Cache              bool          `hcl:"cache,optional" help:"Cache minted tokens on disk between invocations."`
	CacheRefreshBefore time.Duration `hcl:"cache-refresh-before,optional" default:"2m" help:"Refresh a cached token this long before it expires."`

	AWSSTS *AWSSTSConfig `hcl:"aws-sts,block,optional"`
	Exec   *ExecConfig   `hcl:"exec,block,optional"`
	Static *StaticConfig `hcl:"static,block,optional"`
}

// Validate checks that exactly one token source is configured. It is called by
// New, and separately at config load time so a mistake is reported before the
// first request rather than during one.
func (c Config) Validate() error {
	configured := make([]string, 0, 3)
	if c.AWSSTS != nil {
		configured = append(configured, "aws-sts")
	}
	if c.Exec != nil {
		configured = append(configured, "exec")
	}
	if c.Static != nil {
		configured = append(configured, "static")
	}
	switch len(configured) {
	case 1:
	case 0:
		return errors.New("oidc: one of aws-sts, exec or static must be set")
	default:
		return errors.Errorf("oidc: only one token source may be set, got %s", strings.Join(configured, " and "))
	}

	// A refresh margin at or beyond the token's whole lifetime means no minted
	// token is ever considered fresh, silently degrading to one blocking mint per
	// request — reject it up front instead. Static sources ignore both fields
	// (they never mint or cache), so the check would only reject configs whose
	// values are inert.
	if c.Static == nil && c.Duration > 0 && c.CacheRefreshBefore >= c.Duration {
		return errors.Errorf("oidc: cache-refresh-before (%s) must be less than duration (%s), otherwise every request mints a new token", c.CacheRefreshBefore, c.Duration)
	}
	return nil
}

// New builds the token source described by cfg. The name identifies the client
// context and is used to name the on-disk cache entry.
func New(ctx context.Context, name string, cfg Config) (Source, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	switch {
	case cfg.Static != nil:
		// Deliberately not cached. Reading a file or environment variable is
		// cheap, and memoising it would defeat the rotation that token-file
		// exists for: a Kubernetes projected service-account token is replaced
		// in place long before the old one expires.
		return newStatic(*cfg.Static)

	case cfg.Exec != nil:
		source, err := newExec(*cfg.Exec)
		if err != nil {
			return nil, err
		}
		return newCache(name, source, cfg.Cache, cfg.CacheRefreshBefore, fingerprint(cfg)), nil

	default:
		source, err := newAWSSTS(ctx, cfg, *cfg.AWSSTS)
		if err != nil {
			return nil, err
		}
		return newCache(name, source, cfg.Cache, cfg.CacheRefreshBefore, fingerprint(cfg)), nil
	}
}

// fingerprintLength is the hex length of a config fingerprint in cache filenames.
const fingerprintLength = 12

// identityEnvVars are the ambient environment variables that select which AWS
// identity the default credential chain resolves when the context does not pin
// one. They are folded into the fingerprint so switching profile or role between
// invocations cannot reuse a token minted for the previous principal. Raw
// credential values (AWS_ACCESS_KEY_ID and friends) are deliberately excluded:
// they rotate for the same identity, so including them would defeat the cache.
//
//nolint:gochecknoglobals
var identityEnvVars = []string{"AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"}

// fingerprint digests the token-source configuration into the disk-cache key, so
// that editing a context — a new audience, role chain or profile — or switching
// the ambient AWS identity invalidates the entry instead of silently reusing a
// still-fresh token minted under the old settings. Never empty, so cache
// filenames always carry a fingerprint segment.
func fingerprint(cfg Config) string {
	var digest bytes.Buffer
	// Field names are only digest input here, so the default JSON encoding is
	// fine and tags would add noise.
	if encoded, err := json.Marshal(cfg); err == nil { //nolint:musttag
		digest.Write(encoded)
	}
	if cfg.AWSSTS != nil {
		for _, name := range identityEnvVars {
			digest.WriteString("\x00" + name + "=" + os.Getenv(name))
		}
	}
	sum := sha256.Sum256(digest.Bytes())
	return hex.EncodeToString(sum[:fingerprintLength/2])
}

// tokenExpiry reads the "exp" claim of a JWT without verifying it.
//
// The client has no way to verify a token it was just handed — only the server
// holds the issuer's keys — and does not need to: the expiry is used solely to
// decide when to mint a replacement. A token whose expiry cannot be read is
// treated as already expired by callers. jwx does the parsing so the client and
// the server-side verifier agree on what constitutes a well-formed token.
func tokenExpiry(token string) (time.Time, error) {
	parsed, err := jwt.ParseInsecure([]byte(token))
	if err != nil {
		return time.Time{}, errors.Errorf("parse token: %w", err)
	}
	expiry, ok := parsed.Expiration()
	if !ok {
		return time.Time{}, errors.New("token has no exp claim")
	}
	return expiry, nil
}
