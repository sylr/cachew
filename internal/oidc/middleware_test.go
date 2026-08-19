package oidc_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/oidc"
)

func TestMiddleware(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)

	valid := ti.mint(tokenOptions{Audience: []string{testAudience}})
	wrongAudience := ti.mint(tokenOptions{Audience: []string{"https://elsewhere.example.com"}})
	untrustedIssuer := ti.mint(tokenOptions{Issuer: "https://upstream.example.com", Audience: []string{testAudience}})
	// A forgery naming the trusted issuer but carrying a broken signature.
	tampered := func() string {
		parts := strings.Split(valid, ".")
		parts[2] = "AAAA"
		return strings.Join(parts, ".")
	}()

	tests := []struct {
		Name           string
		Authorization  string
		ExpectedStatus int
		ExpectClaims   bool
	}{
		{"NoHeader", "", http.StatusOK, false},
		{"ValidBearer", "Bearer " + valid, http.StatusOK, true},
		{"LowercaseScheme", "bearer " + valid, http.StatusOK, true},
		// Credentials not addressed to cachew pass through claimless so that
		// strategies forwarding client credentials upstream keep working: other
		// schemes, opaque Bearer tokens, and JWTs from unconfigured issuers.
		// Policy still denies /api and /admin because they yield no input.token.
		{"BasicAuthPassesThrough", "Basic dXNlcjpwYXNz", http.StatusOK, false},
		{"EmptyBearerPassesThrough", "Bearer ", http.StatusOK, false},
		{"OpaqueBearerPassesThrough", "Bearer not-a-token", http.StatusOK, false},
		{"UntrustedIssuerPassesThrough", "Bearer " + untrustedIssuer, http.StatusOK, false},
		// Anything claiming a configured issuer MUST verify.
		{"WrongAudience", "Bearer " + wrongAudience, http.StatusUnauthorized, false},
		{"TamperedSignature", "Bearer " + tampered, http.StatusUnauthorized, false},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var sawClaims bool
			next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				_, sawClaims = oidc.ClaimsFromContext(r.Context())
			})

			w := httptest.NewRecorder()
			oidc.Middleware(verifier, next).ServeHTTP(w, newRequest("/admin/log/level", test.Authorization))

			assert.Equal(t, test.ExpectedStatus, w.Code)
			assert.Equal(t, test.ExpectClaims, sawClaims)
		})
	}
}

func TestMiddlewarePreservesPassedThroughHeader(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)
	upstream := "Bearer " + ti.mint(tokenOptions{Issuer: "https://upstream.example.com"})

	var forwarded string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		// Strategies like artifactory forward this verbatim; it must survive.
		forwarded = r.Header.Get("Authorization")
	})
	w := httptest.NewRecorder()
	oidc.Middleware(verifier, next).ServeHTTP(w, newRequest("/artifactory/repo/thing", upstream))

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, upstream, forwarded)
}

func TestMiddlewareSetsWWWAuthenticate(t *testing.T) {
	ti := newTestIssuer(t)
	verifier := newVerifier(t, ti)
	wrongAudience := ti.mint(tokenOptions{Audience: []string{"https://elsewhere.example.com"}})

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {
		t.Fatal("next handler must not run for a rejected token")
	})
	w := httptest.NewRecorder()
	oidc.Middleware(verifier, next).ServeHTTP(w, newRequest("/admin/log/level", "Bearer "+wrongAudience))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, `Bearer error="invalid_token"`, w.Header().Get("WWW-Authenticate"))
}

func TestMiddlewareWithoutVerifier(t *testing.T) {
	var called bool
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		called = true
		_, ok := oidc.ClaimsFromContext(r.Context())
		assert.False(t, ok)
	})

	w := httptest.NewRecorder()
	oidc.Middleware(nil, next).ServeHTTP(w, newRequest("/admin/log/level", "Bearer anything"))

	assert.True(t, called)
	assert.Equal(t, http.StatusOK, w.Code)
}
