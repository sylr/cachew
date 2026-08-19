package opa_test

import (
	"bytes"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/logging"
	"github.com/block/cachew/internal/oidc"
	"github.com/block/cachew/internal/opa"
)

// awsPolicy is the worked example from the README. It is exercised here, and its
// Rego tests are run by TestAWSPolicyRegoTests, so the documented policy cannot
// drift from working behaviour.
const awsPolicy = `package cachew.authz

default allow := false

allow if startswith(input.remote_addr, "127.0.0.1:")
allow if not input.path[0] in {"api", "admin"}

aws := input.token.claims["https://sts.amazonaws.com/"]

is_pprof if {
	input.path[0] == "admin"
	input.path[1] == "pprof"
}

allow if {
	input.path[0] == "api"
	input.token.subject in {
		"arn:aws:iam::123456789012:role/cachew-ci",
		"arn:aws:iam::123456789012:role/cachew-admin",
	}
}

allow if {
	input.path[0] == "admin"
	not is_pprof
	aws.aws_account == "123456789012"
	aws.principal_tags.team == "platform"
}
`

const awsPolicyTests = `package cachew.authz_test

import data.cachew.authz

remote := "10.0.0.1:1234"

admin := {
	"subject": "arn:aws:iam::123456789012:role/cachew-admin",
	"claims": {"https://sts.amazonaws.com/": {
		"aws_account": "123456789012",
		"principal_tags": {"team": "platform"},
	}},
}

ci := {
	"subject": "arn:aws:iam::123456789012:role/cachew-ci",
	"claims": {"https://sts.amazonaws.com/": {
		"aws_account": "123456789012",
		"principal_tags": {"team": "builds"},
	}},
}

test_admin_token_allows_admin if authz.allow with input as {
	"remote_addr": remote, "path": ["admin", "log", "level"], "token": admin,
}

test_admin_token_denied_pprof if not authz.allow with input as {
	"remote_addr": remote, "path": ["admin", "pprof", "profile"], "token": admin,
}

test_ci_token_allows_api if authz.allow with input as {
	"remote_addr": remote, "path": ["api", "v1", "stats"], "token": ci,
}

test_ci_token_denied_admin if not authz.allow with input as {
	"remote_addr": remote, "path": ["admin", "log", "level"], "token": ci,
}

test_no_token_denied_api if not authz.allow with input as {
	"remote_addr": remote, "path": ["api"],
}

test_no_token_allows_strategy if authz.allow with input as {
	"remote_addr": remote, "path": ["git", "github.com", "org", "repo"],
}
`

// adminClaims and ciClaims mirror the shapes AWS STS produces: the subject is the
// IAM principal ARN and identity claims are nested under a namespaced claim.
func awsClaims(subject, team string) *oidc.Claims {
	return &oidc.Claims{
		Issuer:   "https://abc123.tokens.sts.global.api.aws",
		Subject:  subject,
		Audience: []string{"https://cachew.example.com"},
		Raw: map[string]any{
			"sub": subject,
			"https://sts.amazonaws.com/": map[string]any{
				"aws_account":    "123456789012",
				"principal_tags": map[string]any{"team": team},
			},
		},
	}
}

func TestPolicyWithVerifiedClaims(t *testing.T) {
	admin := awsClaims("arn:aws:iam::123456789012:role/cachew-admin", "platform")
	ci := awsClaims("arn:aws:iam::123456789012:role/cachew-ci", "builds")

	tests := []struct {
		Name           string
		Path           string
		Claims         *oidc.Claims
		ExpectedStatus int
	}{
		{"AdminTokenAllowsAdmin", "/admin/log/level", admin, http.StatusOK},
		{"AdminTokenAllowsAPI", "/api/v1/stats", admin, http.StatusOK},
		// pprof is excluded for every caller, however privileged.
		{"AdminTokenDeniedPprofIndex", "/admin/pprof/", admin, http.StatusForbidden},
		{"AdminTokenDeniedPprofSubpath", "/admin/pprof/profile", admin, http.StatusForbidden},
		{"CITokenAllowsAPI", "/api/v1/stats", ci, http.StatusOK},
		{"CITokenDeniedAdmin", "/admin/log/level", ci, http.StatusForbidden},
		// Without claims the token rules are undefined, so default deny applies.
		{"NoTokenDeniedAdmin", "/admin/log/level", nil, http.StatusForbidden},
		{"NoTokenDeniedAPI", "/api/v1/stats", nil, http.StatusForbidden},
		{"NoTokenAllowsStrategy", "/git/github.com/org/repo", nil, http.StatusOK},
	}

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	handler, err := opa.Middleware(t.Context(), opa.Config{Policy: awsPolicy}, true, next)
	assert.NoError(t, err)

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			r := newRequest(http.MethodGet, test.Path)
			r.RemoteAddr = "10.0.0.1:9999"
			if test.Claims != nil {
				r = r.WithContext(oidc.ContextWithClaims(r.Context(), test.Claims))
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			assert.Equal(t, test.ExpectedStatus, w.Code)
		})
	}
}

func TestAWSPolicyRegoTests(t *testing.T) {
	passed, err := opa.RunTests(t.Context(), opa.Config{Policy: awsPolicy, Test: awsPolicyTests})
	assert.NoError(t, err)
	assert.Equal(t, 6, passed)
}

func TestAuthorizationHeaderWithheldWhenOIDCConfigured(t *testing.T) {
	policy := `package cachew.authz
default allow := false
allow if input.headers["authorization"]
`
	tests := []struct {
		Name           string
		OIDCConfigured bool
		ExpectedStatus int
	}{
		{"HeaderVisibleWithoutOIDC", false, http.StatusOK},
		{"HeaderWithheldWithOIDC", true, http.StatusForbidden},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
			handler, err := opa.Middleware(t.Context(), opa.Config{Policy: policy}, test.OIDCConfigured, next)
			assert.NoError(t, err)

			r := newRequest(http.MethodGet, "/admin/log/level")
			r.Header.Set("Authorization", "Basic dXNlcjpwYXNz")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			assert.Equal(t, test.ExpectedStatus, w.Code)
		})
	}
}

func TestWarnsWhenPolicyReadsAuthorizationHeader(t *testing.T) {
	headerPolicy := `package cachew.authz
default allow := false
allow if input.headers["authorization"]
`
	spacedPolicy := `package cachew.authz
default allow := false
allow if input.headers[ "authorization" ]
`
	dotPolicy := `package cachew.authz
default allow := false
allow if input.headers.authorization
`
	indirectPolicy := `package cachew.authz
default allow := false
allow if {
	h := input.headers
	h["authorization"]
}
`

	tests := []struct {
		Name           string
		OIDCConfigured bool
		Policy         string
		ExpectWarning  bool
	}{
		{"WarnsWithOIDC", true, headerPolicy, true},
		{"WarnsOnSpacedBrackets", true, spacedPolicy, true},
		{"WarnsOnDotForm", true, dotPolicy, true},
		{"WarnsOnIndirection", true, indirectPolicy, true},
		{"SilentWithoutOIDC", false, headerPolicy, false},
		{"SilentWhenPolicyIgnoresHeader", true, "package cachew.authz\ndefault allow := false\n", false},
	}

	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			var buf bytes.Buffer
			ctx := logging.ContextWithLogger(t.Context(), slog.New(slog.NewTextHandler(&buf, nil)))

			_, err := opa.Middleware(ctx, opa.Config{Policy: test.Policy}, test.OIDCConfigured, next)
			assert.NoError(t, err)
			assert.Equal(t, test.ExpectWarning, strings.Contains(buf.String(), "withheld"))
		})
	}
}

func TestOtherHeadersStillVisibleWhenOIDCConfigured(t *testing.T) {
	policy := `package cachew.authz
default allow := false
allow if input.headers["x-trace"] == "yes"
`
	next := http.HandlerFunc(func(_ http.ResponseWriter, _ *http.Request) {})
	handler, err := opa.Middleware(t.Context(), opa.Config{Policy: policy}, true, next)
	assert.NoError(t, err)

	r := newRequest(http.MethodGet, "/admin/log/level")
	r.Header.Set("Authorization", "Bearer x")
	r.Header.Set("X-Trace", "yes")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	assert.Equal(t, http.StatusOK, w.Code)
}
