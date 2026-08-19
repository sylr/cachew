package clientconfig_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/clientconfig"
)

// write puts contents into a temporary config file and returns its path.
func write(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.hcl")
	assert.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

const twoContexts = `
default-context = "prod"

context "prod" {
  url = "https://cachew.example.com"
  oidc {
    audience = ["https://cachew.example.com"]
    aws-sts {
      region = "eu-west-1"
    }
  }
}

context "local" {
  url = "http://127.0.0.1:9000"
}
`

func TestLoad(t *testing.T) {
	cfg, err := clientconfig.Load(write(t, twoContexts), false)
	assert.NoError(t, err)
	assert.Equal(t, "prod", cfg.DefaultContext)
	assert.Equal(t, 2, len(cfg.Contexts))

	prod := cfg.Contexts[0]
	assert.Equal(t, "prod", prod.Name)
	assert.Equal(t, "https://cachew.example.com", prod.URL)
	assert.NotZero(t, prod.OIDC)
	assert.Equal(t, []string{"https://cachew.example.com"}, prod.OIDC.Audience)
	assert.NotZero(t, prod.OIDC.AWSSTS)
	assert.Equal(t, "eu-west-1", prod.OIDC.AWSSTS.Region)

	// Defaults come from the struct tags rather than being hardcoded at use sites.
	assert.Equal(t, "RS256", prod.OIDC.SigningAlgorithm)
	assert.Equal(t, 15*time.Minute, prod.OIDC.Duration)
	assert.Equal(t, 2*time.Minute, prod.OIDC.CacheRefreshBefore)

	assert.Zero(t, cfg.Contexts[1].OIDC)
}

func TestLoadMissingFile(t *testing.T) {
	cfg, err := clientconfig.Load(filepath.Join(t.TempDir(), "absent.hcl"), false)
	assert.NoError(t, err)
	assert.Zero(t, cfg)
}

func TestLoadExplicitMissingFileErrors(t *testing.T) {
	_, err := clientconfig.Load(filepath.Join(t.TempDir(), "typo.hlc"), true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "read client config")
}

func TestLoadErrors(t *testing.T) {
	tests := []struct {
		Name     string
		Contents string
		Error    string
	}{
		{"Unparseable", "context {", "parse client config"},
		{
			Name:     "DuplicateContext",
			Contents: "context \"a\" {}\ncontext \"a\" {}\n",
			Error:    "duplicate context",
		},
		{
			Name:     "UnknownDefaultContext",
			Contents: "default-context = \"nope\"\ncontext \"a\" {}\n",
			Error:    "does not match any context",
		},
		{
			Name:     "NoTokenSource",
			Contents: "context \"a\" {\n  oidc {\n    audience = [\"x\"]\n  }\n}\n",
			Error:    "one of aws-sts, exec or static must be set",
		},
		{
			Name:     "TwoTokenSources",
			Contents: "context \"a\" {\n  oidc {\n    audience = [\"x\"]\n    aws-sts { region = \"eu-west-1\" }\n    static { token = \"t\" }\n  }\n}\n",
			Error:    "only one token source may be set",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			_, err := clientconfig.Load(write(t, test.Contents), false)
			assert.Error(t, err)
			assert.Contains(t, err.Error(), test.Error)
		})
	}
}

func TestResolve(t *testing.T) {
	cfg, err := clientconfig.Load(write(t, twoContexts), false)
	assert.NoError(t, err)

	tests := []struct {
		Name      string
		Requested string
		Env       string
		Expected  string
		Error     string
	}{
		{Name: "Explicit", Requested: "local", Expected: "local"},
		{Name: "FallsBackToDefaultContext", Expected: "prod"},
		{Name: "FromEnvironment", Env: "local", Expected: "local"},
		{Name: "FlagBeatsEnvironment", Requested: "prod", Env: "local", Expected: "prod"},
		{Name: "Unknown", Requested: "nope", Error: "unknown context"},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Setenv("CACHEW_CONTEXT", test.Env)
			resolved, err := cfg.Resolve(test.Requested)
			if test.Error != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.Error)
				return
			}
			assert.NoError(t, err)
			assert.NotZero(t, resolved)
			assert.Equal(t, test.Expected, resolved.Name)
		})
	}
}

func TestResolveImplicit(t *testing.T) {
	t.Setenv("CACHEW_CONTEXT", "")

	single, err := clientconfig.Load(write(t, "context \"only\" {\n  url = \"https://only.example.com\"\n}\n"), false)
	assert.NoError(t, err)
	resolved, err := single.Resolve("")
	assert.NoError(t, err)
	assert.Equal(t, "only", resolved.Name)

	var empty clientconfig.Config
	resolved, err = empty.Resolve("")
	assert.NoError(t, err)
	assert.Zero(t, resolved)
}

func TestResolveAmbiguous(t *testing.T) {
	t.Setenv("CACHEW_CONTEXT", "")
	cfg, err := clientconfig.Load(write(t, "context \"a\" {}\ncontext \"b\" {}\n"), false)
	assert.NoError(t, err)

	resolved, err := cfg.Resolve("")
	assert.NoError(t, err)
	assert.Zero(t, resolved)
}

func TestResolveURL(t *testing.T) {
	withURL := &clientconfig.Context{Name: "prod", URL: "https://context.example.com"}
	withoutURL := &clientconfig.Context{Name: "prod"}

	tests := []struct {
		Name     string
		Flag     string
		Env      string
		Context  *clientconfig.Context
		Expected string
	}{
		{"FlagWins", "https://flag.example.com", "https://env.example.com", withURL, "https://flag.example.com"},
		{"EnvBeatsContext", "", "https://env.example.com", withURL, "https://env.example.com"},
		{"ContextUsed", "", "", withURL, "https://context.example.com"},
		{"DefaultWhenContextHasNoURL", "", "", withoutURL, clientconfig.DefaultURL},
		{"DefaultWithoutContext", "", "", nil, clientconfig.DefaultURL},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			assert.Equal(t, test.Expected, clientconfig.ResolveURL(test.Flag, test.Env, test.Context))
		})
	}
}

func TestPath(t *testing.T) {
	t.Run("Override", func(t *testing.T) {
		t.Setenv("CACHEW_CONFIG", "/from/env.hcl")
		path, explicit, err := clientconfig.Path("/explicit.hcl")
		assert.NoError(t, err)
		assert.Equal(t, "/explicit.hcl", path)
		assert.True(t, explicit)
	})

	t.Run("Environment", func(t *testing.T) {
		t.Setenv("CACHEW_CONFIG", "/from/env.hcl")
		path, explicit, err := clientconfig.Path("")
		assert.NoError(t, err)
		assert.Equal(t, "/from/env.hcl", path)
		assert.True(t, explicit)
	})

	t.Run("XDGConfigHome", func(t *testing.T) {
		t.Setenv("CACHEW_CONFIG", "")
		t.Setenv("XDG_CONFIG_HOME", "/xdg")
		path, explicit, err := clientconfig.Path("")
		assert.NoError(t, err)
		assert.Equal(t, filepath.Join("/xdg", "cachew", "config.hcl"), path)
		assert.False(t, explicit)
	})

	t.Run("HomeDirectory", func(t *testing.T) {
		t.Setenv("CACHEW_CONFIG", "")
		t.Setenv("XDG_CONFIG_HOME", "")
		home := t.TempDir()
		t.Setenv("HOME", home)
		path, explicit, err := clientconfig.Path("")
		assert.NoError(t, err)
		assert.Equal(t, filepath.Join(home, ".config", "cachew", "config.hcl"), path)
		assert.False(t, explicit)
	})
}
