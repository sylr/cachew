package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/block/cachew/internal/oidc"
)

const testAudience = "https://cachew.example.com"

// newVerifier builds a verifier trusting ti with the given audiences.
func newVerifier(t *testing.T, ti *testIssuer, audiences ...string) *oidc.Verifier {
	t.Helper()
	if len(audiences) == 0 {
		audiences = []string{testAudience}
	}
	v, err := oidc.NewVerifier(t.Context(), []oidc.Config{{
		Issuer:    ti.URL(),
		Audiences: audiences,
	}}, ti.Client())
	assert.NoError(t, err)
	return v
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	otherKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	tests := []struct {
		Name  string
		Token func() string
		Error string
	}{
		{
			Name:  "WrongAudience",
			Token: func() string { return ti.mint(tokenOptions{Audience: []string{"https://elsewhere.example.com"}}) },
			Error: "matches none of the audiences",
		},
		{
			Name:  "NoAudience",
			Token: func() string { return ti.mint(tokenOptions{}) },
			Error: "matches none of the audiences",
		},
		{
			Name: "UnknownIssuer",
			Token: func() string {
				return ti.mint(tokenOptions{Issuer: "https://not-trusted.example.com", Audience: []string{testAudience}})
			},
			Error: "untrusted issuer",
		},
		{
			Name: "Expired",
			Token: func() string {
				return ti.mint(tokenOptions{
					Audience:  []string{testAudience},
					IssuedAt:  time.Now().Add(-time.Hour),
					ExpiresAt: time.Now().Add(-30 * time.Minute),
				})
			},
			Error: "verify token",
		},
		{
			Name: "NotYetValid",
			Token: func() string {
				return ti.mint(tokenOptions{
					Audience:  []string{testAudience},
					NotBefore: time.Now().Add(time.Hour),
					ExpiresAt: time.Now().Add(2 * time.Hour),
				})
			},
			Error: "verify token",
		},
		{
			Name: "SignedByUnknownKey",
			Token: func() string {
				return ti.mint(tokenOptions{
					Audience: []string{testAudience},
					Key:      otherKey,
					KeyID:    testRSAKeyID,
				})
			},
			Error: "verify token",
		},
		{
			Name: "UnknownKeyID",
			Token: func() string {
				return ti.mint(tokenOptions{Audience: []string{testAudience}, KeyID: "nope"})
			},
			Error: "no key with kid",
		},
		{
			Name: "MissingKeyID",
			Token: func() string {
				return ti.mint(tokenOptions{Audience: []string{testAudience}, OmitKeyID: true})
			},
			Error: "no kid header",
		},
		{
			Name: "DisallowedAlgorithm",
			Token: func() string {
				return ti.mint(tokenOptions{
					Audience:  []string{testAudience},
					Algorithm: jwa.RS512(),
					Key:       ti.rsaKey,
					KeyID:     testRSAKeyID,
				})
			},
			Error: "does not allow signature algorithm",
		},
		{
			// The classic algorithm-confusion attack: re-sign the token with the
			// public modulus as an HMAC secret and claim it is HS256.
			Name: "HMACSignedWithPublicKey",
			Token: func() string {
				return ti.mint(tokenOptions{
					Audience:  []string{testAudience},
					Algorithm: jwa.HS256(),
					Key:       ti.rsaKey.PublicKey.N.Bytes(),
					KeyID:     testRSAKeyID,
				})
			},
			Error: "does not allow signature algorithm",
		},
		{
			// jwx's expiry validator is a no-op when exp is absent, so without an
			// explicit requirement this token would never expire.
			Name: "NoExpiry",
			Token: func() string {
				return ti.mint(tokenOptions{Audience: []string{testAudience}, OmitExpiry: true})
			},
			Error: "verify token",
		},
		{
			Name:  "Garbage",
			Token: func() string { return "not-a-token" },
			Error: "compact serialization",
		},
		{
			Name: "TamperedPayload",
			Token: func() string {
				parts := strings.Split(ti.mint(tokenOptions{Audience: []string{testAudience}}), ".")
				parts[1] = "eyJpc3MiOiJodHRwczovL2V2aWwuZXhhbXBsZS5jb20ifQ"
				return strings.Join(parts, ".")
			},
			Error: "untrusted issuer",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			claims, err := verifier.Verify(t.Context(), test.Token())
			assert.Error(t, err)
			assert.Zero(t, claims)
			assert.Contains(t, err.Error(), test.Error)
		})
	}
}

func TestVerifyAcceptsValidTokens(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti, testAudience, "https://second.example.com")

	tests := []struct {
		Name string
		Opts tokenOptions
	}{
		{"RS256", tokenOptions{Audience: []string{testAudience}}},
		{"ES384", tokenOptions{Audience: []string{testAudience}, Algorithm: jwa.ES384()}},
		{
			// Only one configured audience needs to match, not all of them.
			Name: "AnyConfiguredAudienceMatches",
			Opts: tokenOptions{Audience: []string{"https://second.example.com"}},
		},
		{
			Name: "ExtraTokenAudienceIgnored",
			Opts: tokenOptions{Audience: []string{"https://unrelated.example.com", testAudience}},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			claims, err := verifier.Verify(t.Context(), ti.mint(test.Opts))
			assert.NoError(t, err)
			assert.Equal(t, ti.URL(), claims.Issuer)
			assert.Equal(t, "arn:aws:iam::123456789012:role/cachew-admin", claims.Subject)
		})
	}
}

func TestVerifyPreservesNestedClaims(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	const namespace = "https://sts.amazonaws.com/"
	raw := ti.mint(tokenOptions{
		Audience: []string{testAudience},
		Claims: map[string]any{namespace: map[string]any{
			"aws_account":   "123456789012",
			"source_region": "eu-west-1",
			"principal_tags": map[string]any{
				"team": "platform",
			},
		}},
	})

	claims, err := verifier.Verify(t.Context(), raw)
	assert.NoError(t, err)

	nested, ok := claims.Raw[namespace].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "123456789012", nested["aws_account"])
	tags, ok := nested["principal_tags"].(map[string]any)
	assert.True(t, ok)
	assert.Equal(t, "platform", tags["team"])
}

func TestVerifyNormalisesClaimsToJSONTypes(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	claims, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)

	for name, value := range claims.Raw {
		switch value.(type) {
		case string, float64, bool, nil, map[string]any, []any:
		default:
			t.Fatalf("claim %q normalised to non-JSON type %T", name, value)
		}
	}
	assert.False(t, claims.ExpiresAt.IsZero())
}

func TestVerifyWithJWKSMissingAlg(t *testing.T) {
	ti := newTestIssuer(t)
	ti.omitJWKAlg.Store(true)
	verifier := newVerifier(t, ti)

	claims, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)
	assert.Equal(t, ti.URL(), claims.Issuer)
}

func TestVerifyFailsClosedWhenJWKSUnavailable(t *testing.T) {
	t.Cleanup(oidc.SetTimeoutsForTest(time.Second, time.Second))
	t.Cleanup(oidc.SetRefreshCooldownForTest(0))

	ti := newTestIssuer(t)
	ti.jwksBroken.Store(true)

	verifier, err := oidc.NewVerifier(t.Context(), []oidc.Config{{
		Issuer:    ti.URL(),
		Audiences: []string{testAudience},
	}}, ti.Client())
	assert.NoError(t, err, "an unreachable issuer must not be a construction error")

	claims, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.Error(t, err)
	assert.Zero(t, claims)

	// Once the issuer recovers, verification succeeds without restarting.
	ti.jwksBroken.Store(false)
	claims, err = verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)
	assert.Equal(t, ti.URL(), claims.Issuer)
}

func TestVerifyPicksUpRotatedKeys(t *testing.T) {
	t.Cleanup(oidc.SetRefreshCooldownForTest(0))

	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	claims, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)
	assert.Equal(t, ti.URL(), claims.Issuer)

	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)
	ti.setKeys(map[string]any{"rsa-2": rotated.Public()})

	raw := ti.mint(tokenOptions{
		Audience: []string{testAudience},
		Key:      rotated,
		KeyID:    "rsa-2",
	})
	claims, err = verifier.Verify(t.Context(), raw)
	assert.NoError(t, err)
	assert.Equal(t, ti.URL(), claims.Issuer)
}

func TestVerifyRateLimitsForcedJWKSRefresh(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	// Prime the cache with a successful verification.
	_, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)
	primed := ti.jwksRequests.Load()

	for range 20 {
		_, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{
			Audience: []string{testAudience},
			KeyID:    "attacker-chosen",
		}))
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "no key with kid")
	}
	assert.Equal(t, primed, ti.jwksRequests.Load(), "unknown key IDs must not trigger a JWKS fetch each")

	// With the cooldown elapsed, a genuine rotation is still picked up.
	restore := oidc.SetRefreshCooldownForTest(0)
	defer restore()
	_, err = verifier.Verify(t.Context(), ti.mint(tokenOptions{
		Audience: []string{testAudience},
		KeyID:    "still-unknown",
	}))
	assert.Error(t, err)
	assert.True(t, ti.jwksRequests.Load() > primed)
}

func TestVerifyFailsFastDuringJWKSOutage(t *testing.T) {
	t.Cleanup(oidc.SetTimeoutsForTest(time.Second, time.Second))

	ti := newTestIssuer(t)
	ti.jwksBroken.Store(true)
	verifier := newVerifier(t, ti)
	token := ti.mint(tokenOptions{Audience: []string{testAudience}})

	// The first request pays for a real fetch attempt and starts the cooldown.
	_, err := verifier.Verify(t.Context(), token)
	assert.Error(t, err)
	attempts := ti.jwksRequests.Load()

	// Requests within the cooldown fail fast without touching the issuer,
	// instead of holding a handler for the fetch timeout per request.
	for range 10 {
		_, err := verifier.Verify(t.Context(), token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "retry pending")
	}
	assert.Equal(t, attempts, ti.jwksRequests.Load())
}

func TestVerifyFailsFastDuringDiscoveryOutage(t *testing.T) {
	t.Cleanup(oidc.SetTimeoutsForTest(time.Second, time.Second))

	ti := newTestIssuer(t)
	ti.discoveryBroken.Store(true)
	verifier := newVerifier(t, ti)
	token := ti.mint(tokenOptions{Audience: []string{testAudience}})

	_, err := verifier.Verify(t.Context(), token)
	assert.Error(t, err)
	attempts := ti.discoveryRequests.Load()

	for range 10 {
		_, err := verifier.Verify(t.Context(), token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "retry pending")
	}
	assert.Equal(t, attempts, ti.discoveryRequests.Load())

	// Once the cooldown lapses and the issuer recovers, verification succeeds
	// without a restart.
	restore := oidc.SetRefreshCooldownForTest(0)
	defer restore()
	ti.discoveryBroken.Store(false)
	claims, err := verifier.Verify(t.Context(), token)
	assert.NoError(t, err)
	assert.Equal(t, ti.URL(), claims.Issuer)
}

func TestVerifyHonoursZeroClockSkew(t *testing.T) {
	ti := newTestIssuer(t)
	verifier, err := oidc.NewVerifier(t.Context(), []oidc.Config{{
		Issuer:    ti.URL(),
		Audiences: []string{testAudience},
		ClockSkew: 0,
	}}, ti.Client())
	assert.NoError(t, err)

	// Expired seconds ago: a substituted 30s default would accept this.
	raw := ti.mint(tokenOptions{
		Audience:  []string{testAudience},
		IssuedAt:  time.Now().Add(-time.Minute),
		ExpiresAt: time.Now().Add(-5 * time.Second),
	})
	_, err = verifier.Verify(t.Context(), raw)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "verify token")
}

func TestVerifyRateLimitsForcedRefreshConcurrently(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	_, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)
	primed := ti.jwksRequests.Load()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			_, err := verifier.Verify(context.Background(), ti.mint(tokenOptions{
				Audience: []string{testAudience},
				KeyID:    fmt.Sprintf("attacker-%d", i),
			}))
			assert.Error(t, err)
		})
	}
	wg.Wait()

	assert.Equal(t, primed, ti.jwksRequests.Load(),
		"concurrent unknown key IDs must not each trigger a JWKS fetch")
}

func TestVerifyCollapsesConcurrentDiscovery(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	var wg sync.WaitGroup
	for range 25 {
		wg.Go(func() {
			claims, err := verifier.Verify(context.Background(), ti.mint(tokenOptions{
				Audience: []string{testAudience},
			}))
			assert.NoError(t, err)
			assert.Equal(t, ti.URL(), claims.Issuer)
		})
	}
	wg.Wait()

	assert.Equal(t, int64(1), ti.discoveryRequests.Load(),
		"discovery must be performed once, not per concurrent request")
}

func TestVerifyRejectsMismatchedDiscoveryIssuer(t *testing.T) {
	ti := newTestIssuer(t)
	other := "https://evil.example.com"
	ti.discoveryIssuer.Store(&other)
	verifier := newVerifier(t, ti)

	_, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "advertises issuer")
}

func TestVerifyWithExplicitJWKSURI(t *testing.T) {
	ti := newTestIssuer(t)
	other := "https://evil.example.com"
	ti.discoveryIssuer.Store(&other)

	verifier, err := oidc.NewVerifier(t.Context(), []oidc.Config{{
		Issuer:    ti.URL(),
		Audiences: []string{testAudience},
		JWKSURI:   ti.URL() + "/jwks.json",
	}}, ti.Client())
	assert.NoError(t, err)

	claims, err := verifier.Verify(t.Context(), ti.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)
	assert.Equal(t, ti.URL(), claims.Issuer)
}

func TestVerifyToleratesClockSkew(t *testing.T) {
	ti := newTestIssuer(t)
	verifier, err := oidc.NewVerifier(t.Context(), []oidc.Config{{
		Issuer:    ti.URL(),
		Audiences: []string{testAudience},
		ClockSkew: time.Minute,
	}}, ti.Client())
	assert.NoError(t, err)

	raw := ti.mint(tokenOptions{
		Audience:  []string{testAudience},
		IssuedAt:  time.Now().Add(-2 * time.Minute),
		ExpiresAt: time.Now().Add(-30 * time.Second),
	})
	_, err = verifier.Verify(t.Context(), raw)
	assert.NoError(t, err)
}

func TestVerifyRejectsJSONSerialization(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	token, err := jwt.NewBuilder().Issuer(ti.URL()).Audience([]string{testAudience}).
		Expiration(time.Now().Add(time.Minute)).Build()
	assert.NoError(t, err)
	payload, err := json.Marshal(token)
	assert.NoError(t, err)
	serialized, err := jws.Sign(payload, jws.WithJSON(), jws.WithKey(jwa.RS256(), ti.rsaKey))
	assert.NoError(t, err)

	_, err = verifier.Verify(t.Context(), string(serialized))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "compact serialization")
}

func TestNewVerifierValidatesConfig(t *testing.T) {
	tests := []struct {
		Name   string
		Config oidc.Config
		Error  string
	}{
		{
			Name:   "NoAudiences",
			Config: oidc.Config{Issuer: "https://issuer.example.com"},
			Error:  "audiences is required",
		},
		{
			Name:   "EmptyAudience",
			Config: oidc.Config{Issuer: "https://issuer.example.com", Audiences: []string{""}},
			Error:  "must not contain an empty string",
		},
		{
			Name:   "PlaintextIssuer",
			Config: oidc.Config{Issuer: "http://issuer.example.com", Audiences: []string{testAudience}},
			Error:  "must be an https URL",
		},
		{
			Name:   "MissingIssuer",
			Config: oidc.Config{Audiences: []string{testAudience}},
			Error:  "issuer is required",
		},
		{
			Name:   "IssuerWithoutHost",
			Config: oidc.Config{Issuer: "https://", Audiences: []string{testAudience}},
			Error:  "must include a host",
		},
		{
			Name:   "PlaintextJWKSURI",
			Config: oidc.Config{Issuer: "https://issuer.example.com", Audiences: []string{testAudience}, JWKSURI: "http://issuer.example.com/jwks"},
			Error:  "must be an https URL",
		},
		{
			Name:   "UnknownAlgorithm",
			Config: oidc.Config{Issuer: "https://issuer.example.com", Audiences: []string{testAudience}, Algorithms: []string{"RS255"}},
			Error:  "unknown signature algorithm",
		},
		{
			Name:   "SymmetricAlgorithm",
			Config: oidc.Config{Issuer: "https://issuer.example.com", Audiences: []string{testAudience}, Algorithms: []string{"HS256"}},
			Error:  "is not asymmetric",
		},
		{
			Name:   "NoneAlgorithm",
			Config: oidc.Config{Issuer: "https://issuer.example.com", Audiences: []string{testAudience}, Algorithms: []string{"none"}},
			Error:  "is not asymmetric",
		},
		{
			Name:   "NegativeClockSkew",
			Config: oidc.Config{Issuer: "https://issuer.example.com", Audiences: []string{testAudience}, ClockSkew: -time.Second},
			Error:  "clock-skew must not be negative",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			verifier, err := oidc.NewVerifier(t.Context(), []oidc.Config{test.Config}, nil)
			assert.Error(t, err)
			assert.Zero(t, verifier)
			assert.Contains(t, err.Error(), test.Error)
		})
	}
}

func TestNewVerifierRejectsDuplicateIssuers(t *testing.T) {
	cfg := oidc.Config{Issuer: "https://issuer.example.com", Audiences: []string{testAudience}}
	_, err := oidc.NewVerifier(t.Context(), []oidc.Config{cfg, cfg}, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "duplicate issuer")
}

func TestNewVerifierWithoutIssuers(t *testing.T) {
	verifier, err := oidc.NewVerifier(t.Context(), nil, nil)
	assert.NoError(t, err)
	assert.Zero(t, verifier)
}

func TestVerifySelectsAmongMultipleIssuers(t *testing.T) {
	first := newTestIssuer(t)
	second := newTestIssuer(t)

	verifier, err := oidc.NewVerifier(t.Context(), []oidc.Config{
		{Issuer: first.URL(), Audiences: []string{testAudience}},
		{Issuer: second.URL(), Audiences: []string{"https://other.example.com"}},
	}, first.Client())
	assert.NoError(t, err)
	assert.Equal(t, 2, len(verifier.Issuers()))

	claims, err := verifier.Verify(t.Context(), first.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.NoError(t, err)
	assert.Equal(t, first.URL(), claims.Issuer)

	// The second issuer's audience is scoped to it alone, so the first issuer's
	// audience must not be accepted there.
	_, err = verifier.Verify(t.Context(), second.mint(tokenOptions{Audience: []string{testAudience}}))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "matches none of the audiences")
}
