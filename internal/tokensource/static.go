package tokensource

import (
	"context"
	"os"
	"strings"

	"github.com/alecthomas/errors"
)

// StaticConfig takes a token minted elsewhere. TokenFile is re-read on every call
// so that a rotated file — a Kubernetes projected service-account token, say — is
// picked up without restarting.
type StaticConfig struct {
	Token     string `hcl:"token,optional" help:"Token value."`
	TokenFile string `hcl:"token-file,optional" help:"File to read the token from, re-read on each use."`
	TokenEnv  string `hcl:"token-env,optional" help:"Environment variable to read the token from."`
}

type staticSource struct {
	token     string
	tokenFile string
	tokenEnv  string
}

func newStatic(cfg StaticConfig) (Source, error) {
	set := 0
	for _, value := range []string{cfg.Token, cfg.TokenFile, cfg.TokenEnv} {
		if value != "" {
			set++
		}
	}
	if set != 1 {
		return nil, errors.New("oidc: static requires exactly one of token, token-file or token-env")
	}
	return &staticSource{token: cfg.Token, tokenFile: cfg.TokenFile, tokenEnv: cfg.TokenEnv}, nil
}

func (s *staticSource) Token(_ context.Context) (string, error) {
	switch {
	case s.token != "":
		return s.token, nil

	case s.tokenFile != "":
		contents, err := os.ReadFile(s.tokenFile)
		if err != nil {
			return "", errors.Errorf("read token file: %w", err)
		}
		token := strings.TrimSpace(string(contents))
		if token == "" {
			return "", errors.Errorf("token file %q is empty", s.tokenFile)
		}
		return token, nil

	default:
		token := strings.TrimSpace(os.Getenv(s.tokenEnv))
		if token == "" {
			return "", errors.Errorf("environment variable %q is unset or empty", s.tokenEnv)
		}
		return token, nil
	}
}
