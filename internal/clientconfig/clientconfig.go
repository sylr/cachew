// Package clientconfig loads the cachew client configuration file, which holds
// named contexts describing a server and how to authenticate to it.
package clientconfig

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/alecthomas/errors"
	"github.com/alecthomas/hcl/v2"

	"github.com/block/cachew/internal/tokensource"
)

// DefaultURL is used when neither a flag, an environment variable nor the selected
// context supplies one.
const DefaultURL = "http://127.0.0.1:8080"

// Config is the contents of the client configuration file.
type Config struct {
	DefaultContext string    `hcl:"default-context,optional" help:"Context to use when none is named."`
	Contexts       []Context `hcl:"context,block,optional"`
}

// Context describes one cachew server and how to authenticate to it.
type Context struct {
	Name        string              `hcl:"name,label" help:"Context name."`
	URL         string              `hcl:"url,optional" help:"Cache server URL."`
	Description string              `hcl:"description,optional" help:"Human-readable description."`
	OIDC        *tokensource.Config `hcl:"oidc,block,optional"`
}

// Path returns the configuration file path, honouring an explicit override, then
// CACHEW_CONFIG, then the XDG config directory. explicit reports whether the user
// named the file themselves rather than it being the implicit default location —
// callers use it to decide whether a missing file is an error.
func Path(override string) (path string, explicit bool, err error) {
	if override != "" {
		return override, true, nil
	}
	if fromEnv := os.Getenv("CACHEW_CONFIG"); fromEnv != "" {
		return fromEnv, true, nil
	}
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "cachew", "config.hcl"), false, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", false, errors.Errorf("locate home directory: %w", err)
	}
	return filepath.Join(home, ".config", "cachew", "config.hcl"), false, nil
}

// Load reads the configuration file at path.
//
// When mustExist is false a missing file yields an empty Config and no error:
// cachew has always worked with no configuration at all, and requiring a file at
// the default location would break every existing invocation. A file the user
// explicitly pointed at (mustExist true) is different — silently ignoring a typo'd
// --config path would send requests to the wrong server — and a file that exists
// but cannot be parsed is always an error.
func Load(path string, mustExist bool) (Config, error) {
	var cfg Config
	contents, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) && !mustExist {
			return cfg, nil
		}
		return cfg, errors.Errorf("read client config: %w", err)
	}
	// Implicit blocks are deliberately not hydrated: doing so would materialise
	// every optional token-source block, and `exec` has a required attribute, so
	// any config at all would fail to load.
	if err := hcl.Unmarshal(contents, &cfg); err != nil {
		return cfg, errors.Errorf("parse client config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return cfg, errors.Errorf("client config %s: %w", path, err)
	}
	return cfg, nil
}

// validate rejects a config that names contexts ambiguously or incompletely.
func (c Config) validate() error {
	seen := map[string]bool{}
	for _, context := range c.Contexts {
		if context.Name == "" {
			return errors.New("context requires a name")
		}
		if seen[context.Name] {
			return errors.Errorf("duplicate context %q", context.Name)
		}
		seen[context.Name] = true

		if context.OIDC != nil {
			if err := context.OIDC.Validate(); err != nil {
				return errors.Errorf("context %q: %w", context.Name, err)
			}
		}
	}
	if c.DefaultContext != "" && !seen[c.DefaultContext] {
		return errors.Errorf("default-context %q does not match any context", c.DefaultContext)
	}
	return nil
}

// Resolve selects the context to use.
//
// An explicitly named context must exist. Otherwise default-context is used, and
// failing that a lone context is taken as implicit. Returning no context is not an
// error: it simply means no configuration applies.
func (c Config) Resolve(name string) (*Context, error) {
	if name == "" {
		name = os.Getenv("CACHEW_CONTEXT")
	}

	if name != "" {
		for i, context := range c.Contexts {
			if context.Name == name {
				return &c.Contexts[i], nil
			}
		}
		return nil, errors.Errorf("unknown context %q (configured: %s)", name, strings.Join(c.names(), ", "))
	}

	if c.DefaultContext != "" {
		for i, context := range c.Contexts {
			if context.Name == c.DefaultContext {
				return &c.Contexts[i], nil
			}
		}
	}

	// A single context is unambiguous, so requiring default-context as well would
	// be busywork for the common one-server setup.
	if len(c.Contexts) == 1 {
		return &c.Contexts[0], nil
	}

	// No context selected is a normal outcome, not a failure: cachew falls back to
	// flags and environment variables exactly as it did before contexts existed.
	return nil, nil //nolint:nilnil
}

func (c Config) names() []string {
	names := make([]string, 0, len(c.Contexts))
	for _, context := range c.Contexts {
		names = append(names, context.Name)
	}
	return names
}

// ResolveURL applies URL precedence: an explicit flag wins, then the environment,
// then the selected context, then the built-in default.
func ResolveURL(flag, env string, context *Context) string {
	if flag != "" {
		return flag
	}
	if env != "" {
		return env
	}
	if context != nil && context.URL != "" {
		return context.URL
	}
	return DefaultURL
}
