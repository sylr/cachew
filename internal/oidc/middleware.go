package oidc

import (
	"net/http"
	"strings"

	"github.com/block/cachew/internal/logging"
)

const bearerPrefix = "bearer "

// Middleware verifies an Authorization: Bearer token and attaches the resulting
// claims to the request context for downstream authorization policy.
//
// Only tokens the verifier recognises — JWTs naming a configured issuer — are
// verified; those are rejected with 401 on any failure and never reach policy, so
// policy only ever sees cryptographically verified claims. Everything else passes
// through unchanged and claimless: requests without an Authorization header,
// non-Bearer schemes, and Bearer credentials for other services, which strategies
// like artifactory and github-releases forward upstream (see
// internal/strategy/artifactory.go). A passed-through credential yields no
// input.token, so policy still denies /api and /admin.
//
// A nil verifier returns next unchanged, so configuring no issuers costs nothing.
func Middleware(verifier *Verifier, next http.Handler) http.Handler {
	if verifier == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok || !verifier.Recognizes(raw) {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := verifier.Verify(r.Context(), raw)
		if err != nil {
			logging.FromContext(r.Context()).Warn("Rejected bearer token", "error", err,
				"method", r.Method, "path", r.URL.Path, "remote_addr", r.RemoteAddr)
			w.Header().Set("WWW-Authenticate", `Bearer error="invalid_token"`)
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r.WithContext(ContextWithClaims(r.Context(), claims)))
	})
}

// bearerToken extracts the token from an Authorization: Bearer header. The scheme
// is case-insensitive per RFC 7235.
func bearerToken(r *http.Request) (string, bool) {
	header := r.Header.Get("Authorization")
	if len(header) < len(bearerPrefix) || !strings.EqualFold(header[:len(bearerPrefix)], bearerPrefix) {
		return "", false
	}
	token := strings.TrimSpace(header[len(bearerPrefix):])
	return token, token != ""
}
