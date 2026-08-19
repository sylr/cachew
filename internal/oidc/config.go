// Package oidc verifies OIDC-issued JWT bearer tokens on inbound HTTP requests
// and exposes the verified claims to downstream authorization policy.
package oidc

import (
	"net/url"
	"slices"
	"time"

	"github.com/alecthomas/errors"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

// DefaultAlgorithms are the signature algorithms accepted when a Config does not
// restrict them. These are the two algorithms AWS STS GetWebIdentityToken can
// issue. Only asymmetric algorithms are ever allowed: an HMAC algorithm would let
// anyone holding the (public) JWKS mint valid tokens.
//
//nolint:gochecknoglobals
var DefaultAlgorithms = []string{"RS256", "ES384"}

// DefaultClockSkew is the schema default for Config.ClockSkew, applied by the HCL
// `default` tag when the attribute is absent. An explicit "0s" is honoured.
const DefaultClockSkew = 30 * time.Second

// Bounds for background JWKS refresh.
const (
	DefaultMinRefreshInterval = 15 * time.Minute
	DefaultMaxRefreshInterval = 24 * time.Hour
)

// Config describes a single trusted OIDC issuer. Issuer must exactly match the
// "iss" claim of tokens minted by that issuer.
//
// For AWS STS GetWebIdentityToken the issuer is account-specific and looks like
// https://<id>.tokens.sts.global.api.aws — it is not a regional STS endpoint.
// Mint a token and read its "iss" claim rather than guessing.
type Config struct {
	Issuer     string        `hcl:"issuer,label" help:"Issuer URL, matched against the token's iss claim."`
	Audiences  []string      `hcl:"audiences" help:"Accepted audiences. A token matching none of these is rejected."`
	JWKSURI    string        `hcl:"jwks-uri,optional" help:"JWKS URI, bypassing OIDC discovery."`
	Algorithms []string      `hcl:"algorithms,optional" help:"Accepted JWS signature algorithms."`
	ClockSkew  time.Duration `hcl:"clock-skew,optional" default:"30s" help:"Tolerated clock skew for exp/nbf/iat."`
}

// issuer is a validated Config with algorithms resolved to jwa types.
type issuer struct {
	name       string
	audiences  []string
	jwksURI    string
	algorithms []jwa.SignatureAlgorithm
	clockSkew  time.Duration
}

// allowsAlgorithm reports whether alg is in the issuer's allow-list. The list is
// always non-empty, so an unrecognised algorithm can never be accepted.
func (i *issuer) allowsAlgorithm(alg jwa.SignatureAlgorithm) bool {
	return slices.Contains(i.algorithms, alg)
}

// acceptsAudience reports whether any configured audience appears in aud. This is
// deliberately "any of" rather than "all of": a token carries the audiences it was
// minted for, and requiring every configured audience would reject valid tokens.
func (i *issuer) acceptsAudience(aud []string) bool {
	for _, want := range i.audiences {
		if slices.Contains(aud, want) {
			return true
		}
	}
	return false
}

// validate converts a Config into an issuer, rejecting configuration that could
// never authenticate anyone. These are startup errors by design: booting with an
// issuer that cannot match is worse than refusing to boot.
func (c Config) validate() (*issuer, error) {
	if err := requireHTTPS(c.Issuer, "issuer"); err != nil {
		return nil, err
	}
	if len(c.Audiences) == 0 {
		return nil, errors.Errorf("oidc-issuer %q: audiences is required, otherwise a token minted for any other service would be accepted", c.Issuer)
	}
	if slices.Contains(c.Audiences, "") {
		return nil, errors.Errorf("oidc-issuer %q: audiences must not contain an empty string", c.Issuer)
	}
	if c.JWKSURI != "" {
		if err := requireHTTPS(c.JWKSURI, "jwks-uri"); err != nil {
			return nil, err
		}
	}

	names := c.Algorithms
	if len(names) == 0 {
		names = DefaultAlgorithms
	}
	algorithms := make([]jwa.SignatureAlgorithm, 0, len(names))
	for _, name := range names {
		alg, ok := jwa.LookupSignatureAlgorithm(name)
		if !ok {
			return nil, errors.Errorf("oidc-issuer %q: unknown signature algorithm %q", c.Issuer, name)
		}
		if !isAsymmetric(alg) {
			return nil, errors.Errorf("oidc-issuer %q: algorithm %q is not asymmetric and cannot be used to verify tokens against a public JWKS", c.Issuer, name)
		}
		algorithms = append(algorithms, alg)
	}

	// A zero skew is honoured as written: the schema default covers the absent
	// case, so substituting a default here would silently invert an explicit
	// clock-skew = "0s" hardening into 30 seconds of grace.
	skew := c.ClockSkew
	if skew < 0 {
		return nil, errors.Errorf("oidc-issuer %q: clock-skew must not be negative", c.Issuer)
	}

	return &issuer{
		name:       c.Issuer,
		audiences:  c.Audiences,
		jwksURI:    c.JWKSURI,
		algorithms: algorithms,
		clockSkew:  skew,
	}, nil
}

// requireHTTPS rejects anything that is not an absolute https URL. Verifying a
// token against keys fetched over plaintext HTTP offers no security at all.
func requireHTTPS(raw, field string) error {
	if raw == "" {
		return errors.Errorf("oidc-issuer: %s is required", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.Errorf("oidc-issuer %q: invalid %s: %w", raw, field, err)
	}
	if u.Scheme != "https" {
		return errors.Errorf("oidc-issuer %q: %s must be an https URL, got scheme %q", raw, field, u.Scheme)
	}
	if u.Host == "" {
		return errors.Errorf("oidc-issuer %q: %s must include a host", raw, field)
	}
	return nil
}

// isAsymmetric reports whether alg uses a key pair, so that the public JWKS cannot
// also be used to sign. "none" and the HS* family are excluded.
func isAsymmetric(alg jwa.SignatureAlgorithm) bool {
	switch alg {
	case jwa.RS256(), jwa.RS384(), jwa.RS512(),
		jwa.PS256(), jwa.PS384(), jwa.PS512(),
		jwa.ES256(), jwa.ES384(), jwa.ES512(), jwa.EdDSA():
		return true
	default:
		return false
	}
}
