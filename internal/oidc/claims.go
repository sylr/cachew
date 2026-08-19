package oidc

import (
	"context"
	"encoding/json"
	"time"

	"github.com/alecthomas/errors"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Claims are the verified contents of a JWT bearer token.
//
// Raw holds every claim in the token, JSON-normalised. Authorization policy is
// evaluated against it, so it must contain only plain JSON types — Rego compares
// against JSON values, and a time.Time or a library-internal type produces a rule
// that silently never matches. Nested claims are preserved structurally: AWS STS
// nests all of its identity and session claims under a single
// "https://sts.amazonaws.com/" claim, so flattening would lose them.
type Claims struct {
	Issuer    string
	Subject   string
	Audience  []string
	ExpiresAt time.Time
	Raw       map[string]any
}

// newClaims extracts Claims from a verified token, normalising the raw claim set
// through encoding/json so downstream policy only ever sees JSON types.
func newClaims(token jwt.Token) (*Claims, error) {
	encoded, err := json.Marshal(token)
	if err != nil {
		return nil, errors.Errorf("marshal token claims: %w", err)
	}
	var raw map[string]any
	if err := json.Unmarshal(encoded, &raw); err != nil {
		return nil, errors.Errorf("normalise token claims: %w", err)
	}

	issuer, _ := token.Issuer()
	subject, _ := token.Subject()
	audience, _ := token.Audience()
	expiresAt, _ := token.Expiration()

	return &Claims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  audience,
		ExpiresAt: expiresAt,
		Raw:       raw,
	}, nil
}

type claimsContextKey struct{}

// ContextWithClaims returns ctx carrying the verified claims.
func ContextWithClaims(ctx context.Context, claims *Claims) context.Context {
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext returns the verified claims attached to ctx, if any. Claims
// are absent for unauthenticated requests, which is what lets authorization
// policy fail closed without needing to consult a separate validity flag.
func ClaimsFromContext(ctx context.Context) (*Claims, bool) {
	claims, ok := ctx.Value(claimsContextKey{}).(*Claims)
	return claims, ok && claims != nil
}
