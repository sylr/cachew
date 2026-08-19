package tokensource_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alecthomas/assert/v2"

	"github.com/block/cachew/internal/tokensource"
)

// makeToken builds an unsigned JWT-shaped string with the given expiry. The client
// only ever reads "exp" from a token, and never verifies it, so a real signature is
// unnecessary here.
func makeToken(t *testing.T, expiry time.Time, extra string) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims := map[string]any{"sub": "arn:aws:iam::123456789012:role/cachew" + extra}
	if !expiry.IsZero() {
		claims["exp"] = expiry.Unix()
	}
	encoded, err := json.Marshal(claims)
	assert.NoError(t, err)
	payload := base64.RawURLEncoding.EncodeToString(encoded)
	return header + "." + payload + ".c2ln"
}

// useTempCacheDir points os.UserCacheDir at a temporary directory.
func useTempCacheDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	// os.UserCacheDir consults XDG_CACHE_HOME on Unix and $HOME/Library/Caches on
	// darwin, so set both to keep the test portable.
	t.Setenv("XDG_CACHE_HOME", dir)
	t.Setenv("HOME", dir)
	if runtime.GOOS == "darwin" {
		return filepath.Join(dir, "Library", "Caches", "cachew", "tokens")
	}
	return filepath.Join(dir, "cachew", "tokens")
}

func TestNewValidatesSources(t *testing.T) {
	tests := []struct {
		Name   string
		Config tokensource.Config
		Error  string
	}{
		{
			Name:   "NoSource",
			Config: tokensource.Config{},
			Error:  "one of aws-sts, exec or static must be set",
		},
		{
			Name: "TwoSources",
			Config: tokensource.Config{
				Exec:   &tokensource.ExecConfig{Command: []string{"true"}},
				Static: &tokensource.StaticConfig{Token: "t"},
			},
			Error: "only one token source may be set",
		},
		{
			Name:   "ExecWithoutCommand",
			Config: tokensource.Config{Exec: &tokensource.ExecConfig{}},
			Error:  "exec requires a command",
		},
		{
			Name:   "StaticWithNothing",
			Config: tokensource.Config{Static: &tokensource.StaticConfig{}},
			Error:  "exactly one of token, token-file or token-env",
		},
		{
			Name: "StaticWithTwo",
			Config: tokensource.Config{
				Static: &tokensource.StaticConfig{Token: "t", TokenEnv: "E"},
			},
			Error: "exactly one of token, token-file or token-env",
		},
		{
			Name: "AWSSTSWithoutAudience",
			Config: tokensource.Config{
				AWSSTS: &tokensource.AWSSTSConfig{Region: "eu-west-1"},
			},
			Error: "audience is required",
		},
		{
			Name: "AWSSTSBadAlgorithm",
			Config: tokensource.Config{
				Audience:         []string{"aud"},
				SigningAlgorithm: "HS256",
				AWSSTS:           &tokensource.AWSSTSConfig{Region: "eu-west-1"},
			},
			Error: "signing-algorithm must be RS256 or ES384",
		},
		{
			Name: "AWSSTSDurationTooShort",
			Config: tokensource.Config{
				Audience: []string{"aud"},
				Duration: 30 * time.Second,
				AWSSTS:   &tokensource.AWSSTSConfig{Region: "eu-west-1"},
			},
			Error: "duration must be between",
		},
		{
			Name: "AWSSTSDurationTooLong",
			Config: tokensource.Config{
				Audience: []string{"aud"},
				Duration: 2 * time.Hour,
				AWSSTS:   &tokensource.AWSSTSConfig{Region: "eu-west-1"},
			},
			Error: "duration must be between",
		},
		{
			// A refresh margin covering the whole lifetime would silently mint one
			// token per request instead of caching.
			Name: "RefreshBeforeExceedsDuration",
			Config: tokensource.Config{
				Audience:           []string{"aud"},
				Duration:           time.Minute,
				CacheRefreshBefore: 2 * time.Minute,
				AWSSTS:             &tokensource.AWSSTSConfig{Region: "eu-west-1"},
			},
			Error: "must be less than duration",
		},
		{
			Name: "AWSSTSAssumeRoleWithoutARN",
			Config: tokensource.Config{
				Audience: []string{"aud"},
				AWSSTS: &tokensource.AWSSTSConfig{
					Region:      "eu-west-1",
					AssumeRoles: []tokensource.AssumeRoleConfig{{}},
				},
			},
			Error: "assume-role requires role-arn",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			source, err := tokensource.New(t.Context(), "ctx", test.Config)
			assert.Error(t, err)
			assert.Zero(t, source)
			assert.Contains(t, err.Error(), test.Error)
		})
	}
}

func TestStaticSource(t *testing.T) {
	token := makeToken(t, time.Now().Add(time.Hour), "")
	tokenPath := filepath.Join(t.TempDir(), "token.jwt")
	assert.NoError(t, os.WriteFile(tokenPath, []byte(token+"\n"), 0o600))

	tests := []struct {
		Name   string
		Config tokensource.StaticConfig
		Env    string
		Error  string
	}{
		{Name: "Inline", Config: tokensource.StaticConfig{Token: token}},
		{Name: "File", Config: tokensource.StaticConfig{TokenFile: tokenPath}},
		{Name: "Environment", Config: tokensource.StaticConfig{TokenEnv: "CACHEW_TEST_TOKEN"}, Env: token},
		{
			Name:   "MissingFile",
			Config: tokensource.StaticConfig{TokenFile: filepath.Join(t.TempDir(), "absent")},
			Error:  "read token file",
		},
		{
			Name:   "UnsetEnvironment",
			Config: tokensource.StaticConfig{TokenEnv: "CACHEW_TEST_TOKEN"},
			Error:  "unset or empty",
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Setenv("CACHEW_TEST_TOKEN", test.Env)
			source, err := tokensource.New(t.Context(), "ctx", tokensource.Config{Static: &test.Config})
			assert.NoError(t, err)

			got, err := source.Token(t.Context())
			if test.Error != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.Error)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, token, got)
		})
	}
}

func TestStaticIgnoresCacheTuning(t *testing.T) {
	token := makeToken(t, time.Now().Add(time.Hour), "")
	// duration and cache-refresh-before are inert for static sources, so a
	// combination that would be invalid for a minting source must still load.
	source, err := tokensource.New(t.Context(), "ctx", tokensource.Config{
		Duration:           time.Minute,
		CacheRefreshBefore: 2 * time.Minute,
		Static:             &tokensource.StaticConfig{Token: token},
	})
	assert.NoError(t, err)

	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, token, got)
}

func TestFingerprint(t *testing.T) {
	awsConfig := tokensource.Config{
		Audience: []string{"https://cachew.example.com"},
		AWSSTS:   &tokensource.AWSSTSConfig{Region: "eu-west-1"},
	}
	execConfig := tokensource.Config{
		Audience: []string{"https://cachew.example.com"},
		Exec:     &tokensource.ExecConfig{Command: []string{"true"}},
	}

	t.Setenv("AWS_PROFILE", "first")
	first := tokensource.Fingerprint(awsConfig)
	assert.NotEqual(t, "", first)
	assert.Equal(t, first, tokensource.Fingerprint(awsConfig), "must be deterministic")

	// Switching the ambient AWS identity must invalidate the cache entry, or a
	// still-fresh token minted for the previous principal would be replayed.
	t.Setenv("AWS_PROFILE", "second")
	assert.NotEqual(t, first, tokensource.Fingerprint(awsConfig))

	// Exec sources do not resolve AWS credentials, so AWS identity env is inert.
	execFirst := tokensource.Fingerprint(execConfig)
	t.Setenv("AWS_PROFILE", "third")
	assert.Equal(t, execFirst, tokensource.Fingerprint(execConfig))

	// Config changes always change the fingerprint.
	changed := awsConfig
	changed.Audience = []string{"https://other.example.com"}
	assert.NotEqual(t, tokensource.Fingerprint(awsConfig), tokensource.Fingerprint(changed))
}

func TestExecSource(t *testing.T) {
	token := makeToken(t, time.Now().Add(time.Hour), "")

	tests := []struct {
		Name    string
		Command []string
		Timeout time.Duration
		Error   string
	}{
		// Trailing whitespace from a shell pipeline must not end up in the header.
		{Name: "TrimsOutput", Command: []string{"printf", token + "\n"}},
		{Name: "NonZeroExit", Command: []string{"false"}, Error: "run token command"},
		{Name: "NoOutput", Command: []string{"true"}, Error: "produced no output"},
		{Name: "NotFound", Command: []string{"cachew-no-such-command"}, Error: "run token command"},
		{Name: "Timeout", Command: []string{"sleep", "5"}, Timeout: 50 * time.Millisecond, Error: "run token command"},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			source, err := tokensource.New(t.Context(), "ctx", tokensource.Config{
				Exec: &tokensource.ExecConfig{Command: test.Command, Timeout: test.Timeout},
			})
			assert.NoError(t, err)

			got, err := source.Token(t.Context())
			if test.Error != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), test.Error)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, token, got)
		})
	}
}

func TestExecSourceIncludesStderr(t *testing.T) {
	source, err := tokensource.New(t.Context(), "ctx", tokensource.Config{
		Exec: &tokensource.ExecConfig{Command: []string{"sh", "-c", "echo boom >&2; exit 1"}},
	})
	assert.NoError(t, err)

	_, err = source.Token(t.Context())
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "boom")
}

func TestExecSourcePassesEnv(t *testing.T) {
	token := makeToken(t, time.Now().Add(time.Hour), "")
	source, err := tokensource.New(t.Context(), "ctx", tokensource.Config{
		Exec: &tokensource.ExecConfig{
			Command: []string{"sh", "-c", "printf %s \"$CACHEW_TEST_VALUE\""},
			Env:     map[string]string{"CACHEW_TEST_VALUE": token},
		},
	})
	assert.NoError(t, err)

	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, token, got)
}

func TestStaticSourceRereadsFileOnEveryCall(t *testing.T) {
	useTempCacheDir(t)
	first := makeToken(t, time.Now().Add(time.Hour), "-first")
	second := makeToken(t, time.Now().Add(time.Hour), "-second")

	path := filepath.Join(t.TempDir(), "token.jwt")
	assert.NoError(t, os.WriteFile(path, []byte(first), 0o600))

	source, err := tokensource.New(t.Context(), "ctx", tokensource.Config{
		Cache:  true, // must not apply to a static source
		Static: &tokensource.StaticConfig{TokenFile: path},
	})
	assert.NoError(t, err)

	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, first, got)

	assert.NoError(t, os.WriteFile(path, []byte(second), 0o600))
	got, err = source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, second, got, "a rotated token file must be picked up immediately")
}

func TestStaticSourceRereadsEnvOnEveryCall(t *testing.T) {
	useTempCacheDir(t)
	first := makeToken(t, time.Now().Add(time.Hour), "-first")
	second := makeToken(t, time.Now().Add(time.Hour), "-second")

	t.Setenv("CACHEW_TEST_TOKEN", first)
	source, err := tokensource.New(t.Context(), "ctx", tokensource.Config{
		Cache:  true,
		Static: &tokensource.StaticConfig{TokenEnv: "CACHEW_TEST_TOKEN"},
	})
	assert.NoError(t, err)

	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, first, got)

	t.Setenv("CACHEW_TEST_TOKEN", second)
	got, err = source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, second, got)
}

func TestCacheDiskRejectsUnsafeFile(t *testing.T) {
	cacheDir := useTempCacheDir(t)
	token := makeToken(t, time.Now().Add(time.Hour), "")
	poisoned := makeToken(t, time.Now().Add(time.Hour), "-poisoned")

	tests := []struct {
		Name  string
		Setup func(t *testing.T, path string)
	}{
		{
			Name: "GroupWritable",
			Setup: func(t *testing.T, path string) {
				assert.NoError(t, os.WriteFile(path, []byte(poisoned), 0o660))
			},
		},
		{
			Name: "WorldReadable",
			Setup: func(t *testing.T, path string) {
				assert.NoError(t, os.WriteFile(path, []byte(poisoned), 0o644))
			},
		},
		{
			Name: "Symlink",
			Setup: func(t *testing.T, path string) {
				target := filepath.Join(t.TempDir(), "elsewhere.jwt")
				assert.NoError(t, os.WriteFile(target, []byte(poisoned), 0o600))
				assert.NoError(t, os.Symlink(target, path))
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			assert.NoError(t, os.MkdirAll(cacheDir, 0o700))
			path := filepath.Join(cacheDir, "prod.jwt")
			assert.NoError(t, os.RemoveAll(path))
			test.Setup(t, path)

			counter := &countingSource{token: func(int) string { return token }}
			source := tokensource.NewCacheForTest("prod", counter, true, time.Minute)

			got, err := source.Token(t.Context())
			assert.NoError(t, err)
			assert.Equal(t, token, got, "an unsafe cache entry must be ignored")
			assert.Equal(t, 1, counter.calls())
		})
	}
}

// countingSource records how many times a token was minted.
type countingSource struct {
	mu    sync.Mutex
	count int
	token func(int) string
}

func (c *countingSource) Token(_ context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	return c.token(c.count), nil
}

func (c *countingSource) calls() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

func TestCacheMemoisesInMemory(t *testing.T) {
	useTempCacheDir(t)
	token := makeToken(t, time.Now().Add(time.Hour), "")

	counter := &countingSource{token: func(int) string { return token }}
	source := tokensource.NewCacheForTest("ctx", counter, false, time.Minute)

	for range 5 {
		got, err := source.Token(t.Context())
		assert.NoError(t, err)
		assert.Equal(t, token, got)
	}
	assert.Equal(t, 1, counter.calls())
}

func TestCacheRefreshesBeforeExpiry(t *testing.T) {
	useTempCacheDir(t)
	fresh := makeToken(t, time.Now().Add(time.Hour), "-fresh")
	stale := makeToken(t, time.Now().Add(30*time.Second), "-stale")

	counter := &countingSource{token: func(n int) string {
		if n == 1 {
			return stale
		}
		return fresh
	}}
	// refreshBefore exceeds the stale token's remaining life, so it is never used.
	source := tokensource.NewCacheForTest("ctx", counter, false, time.Minute)

	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, stale, got)

	got, err = source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, fresh, got)
	assert.Equal(t, 2, counter.calls())
}

func TestCacheDoesNotCacheTokenWithoutExpiry(t *testing.T) {
	useTempCacheDir(t)
	opaque := "not-a-jwt"

	counter := &countingSource{token: func(int) string { return opaque }}
	source := tokensource.NewCacheForTest("ctx", counter, true, time.Minute)

	for range 3 {
		got, err := source.Token(t.Context())
		assert.NoError(t, err)
		assert.Equal(t, opaque, got)
	}
	assert.Equal(t, 3, counter.calls())
}

func TestCacheDisk(t *testing.T) {
	cacheDir := useTempCacheDir(t)
	token := makeToken(t, time.Now().Add(time.Hour), "")
	counter := &countingSource{token: func(int) string { return token }}

	source := tokensource.NewCacheForTest("prod", counter, true, time.Minute)
	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, token, got)

	path := filepath.Join(cacheDir, "prod.jwt")
	contents, err := os.ReadFile(path)
	assert.NoError(t, err)
	assert.Equal(t, token, string(contents))

	// A cached credential must not be readable by other users on the machine.
	info, err := os.Stat(path)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(cacheDir)
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())

	// A second process starts with an empty memo and must reuse the file.
	second := tokensource.NewCacheForTest("prod", counter, true, time.Minute)
	got, err = second.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, token, got)
	assert.Equal(t, 1, counter.calls())
}

func TestCacheDiskIgnoresUnusableFile(t *testing.T) {
	cacheDir := useTempCacheDir(t)
	token := makeToken(t, time.Now().Add(time.Hour), "")
	expired := makeToken(t, time.Now().Add(-time.Hour), "-expired")

	tests := []struct {
		Name     string
		Contents string
	}{
		{"Corrupt", "not-a-jwt"},
		{"Empty", ""},
		{"Truncated", strings.Split(token, ".")[0]},
		{"BadBase64", "aaa.!!!not-base64!!!.bbb"},
		{"NoExpiryClaim", makeToken(t, time.Time{}, "-noexp")},
		{"Expired", expired},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			assert.NoError(t, os.MkdirAll(cacheDir, 0o700))
			path := filepath.Join(cacheDir, "prod.jwt")
			assert.NoError(t, os.WriteFile(path, []byte(test.Contents), 0o600))

			counter := &countingSource{token: func(int) string { return token }}
			source := tokensource.NewCacheForTest("prod", counter, true, time.Minute)

			got, err := source.Token(t.Context())
			assert.NoError(t, err)
			assert.Equal(t, token, got)
			assert.Equal(t, 1, counter.calls(), "an unusable cache file must be a miss, not an error")
		})
	}
}

func TestCacheDiskWriteFailureIsTolerated(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "denied"))
	t.Setenv("HOME", filepath.Join(dir, "denied"))
	assert.NoError(t, os.WriteFile(filepath.Join(dir, "denied"), []byte("not a directory"), 0o600))

	token := makeToken(t, time.Now().Add(time.Hour), "")
	counter := &countingSource{token: func(int) string { return token }}
	source := tokensource.NewCacheForTest("prod", counter, true, time.Minute)

	got, err := source.Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, token, got)
}

func TestCacheDiskInvalidatedByConfigChange(t *testing.T) {
	cacheDir := useTempCacheDir(t)
	token := makeToken(t, time.Now().Add(time.Hour), "")

	// The command records each real mint, so a run count distinguishes a disk
	// cache hit from a re-mint across otherwise identical sources.
	runs := filepath.Join(t.TempDir(), "runs")
	newSource := func(audience string) tokensource.Source {
		source, err := tokensource.New(t.Context(), "prod", tokensource.Config{
			Audience: []string{audience},
			Cache:    true,
			Exec: &tokensource.ExecConfig{
				Command: []string{"sh", "-c", "echo run >> " + runs + "; printf %s " + token},
			},
		})
		assert.NoError(t, err)
		return source
	}
	countRuns := func() int {
		contents, err := os.ReadFile(runs)
		if err != nil {
			return 0
		}
		return strings.Count(string(contents), "run")
	}

	// Same config across two instances: one mint, then a disk hit.
	_, err := newSource("https://a.example.com").Token(t.Context())
	assert.NoError(t, err)
	_, err = newSource("https://a.example.com").Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, 1, countRuns())

	// A config change must invalidate the entry, not replay the old token.
	_, err = newSource("https://b.example.com").Token(t.Context())
	assert.NoError(t, err)
	assert.Equal(t, 2, countRuns())

	// The superseded entry is cleaned up so it cannot linger for its lifetime.
	entries, err := os.ReadDir(cacheDir)
	assert.NoError(t, err)
	assert.Equal(t, 1, len(entries))
}

func TestCacheIsSingleFlight(t *testing.T) {
	useTempCacheDir(t)
	token := makeToken(t, time.Now().Add(time.Hour), "")
	counter := &countingSource{token: func(int) string { return token }}
	source := tokensource.NewCacheForTest("prod", counter, true, time.Minute)

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			got, err := source.Token(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, token, got)
		})
	}
	wg.Wait()
	assert.Equal(t, 1, counter.calls())
}
