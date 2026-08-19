package tokensource

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/alecthomas/errors"
)

// DefaultExecTimeout bounds a token-minting command.
const DefaultExecTimeout = 30 * time.Second

// ExecConfig mints tokens by running a command and reading the token from its
// standard output. It covers any issuer without additional dependencies, for
// example `aws sts get-web-identity-token ... --query WebIdentityToken --output text`.
type ExecConfig struct {
	Command []string          `hcl:"command" help:"Command and arguments to run. Its stdout is used as the token."`
	Env     map[string]string `hcl:"env,optional" help:"Extra environment variables for the command."`
	Timeout time.Duration     `hcl:"timeout,optional" default:"30s" help:"Maximum time the command may run."`
}

type execSource struct {
	command []string
	env     []string
	timeout time.Duration
}

func newExec(cfg ExecConfig) (Source, error) {
	if len(cfg.Command) == 0 {
		return nil, errors.New("oidc: exec requires a command")
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultExecTimeout
	}

	env := os.Environ()
	for key, value := range cfg.Env {
		env = append(env, key+"="+value)
	}

	return &execSource{command: cfg.Command, env: env, timeout: timeout}, nil
}

func (s *execSource) Token(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, s.command[0], s.command[1:]...) //nolint:gosec
	cmd.Env = s.env
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		// stderr is where a CLI explains itself, so surface it rather than just
		// reporting a non-zero exit status.
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return "", errors.Errorf("run token command %q: %w: %s", s.command[0], err, message)
		}
		return "", errors.Errorf("run token command %q: %w", s.command[0], err)
	}

	token := strings.TrimSpace(stdout.String())
	if token == "" {
		return "", errors.Errorf("token command %q produced no output", s.command[0])
	}
	return token, nil
}
