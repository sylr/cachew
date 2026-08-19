package tokensource

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/alecthomas/errors"
)

// DefaultCacheRefreshBefore is the schema default for Config.CacheRefreshBefore,
// applied by the HCL `default` tag when the attribute is absent. An explicit "0s"
// is honoured, meaning a token is reused right up to its expiry.
const DefaultCacheRefreshBefore = 2 * time.Minute

// cacheDirName is the subdirectory of the user cache directory holding tokens.
const cacheDirName = "cachew"

// cache memoises a minted token in memory and, optionally, on disk.
//
// Minting is serialised: the client fires many requests concurrently when
// downloading snapshots, and without single-flight every one of them would mint
// its own token and race to write the cache file.
type cache struct {
	name          string
	source        Source
	useDisk       bool
	refreshBefore time.Duration
	// fingerprint digests the token-source configuration; it keys the disk entry
	// so a config edit invalidates the cache rather than replaying a stale token.
	fingerprint string

	mu      sync.Mutex
	token   string
	expires time.Time
}

func newCache(name string, source Source, useDisk bool, refreshBefore time.Duration, fingerprint string) Source {
	if refreshBefore < 0 {
		refreshBefore = 0
	}
	return &cache{name: name, source: source, useDisk: useDisk, refreshBefore: refreshBefore, fingerprint: fingerprint}
}

func (c *cache) Token(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.token != "" && c.fresh(c.expires) {
		return c.token, nil
	}

	if c.useDisk {
		if token, expires, ok := c.readDisk(); ok && c.fresh(expires) {
			c.token, c.expires = token, expires
			return token, nil
		}
	}

	token, err := c.source.Token(ctx)
	if err != nil {
		return "", errors.WithStack(err)
	}

	// A token whose expiry cannot be read is still usable; it just cannot be
	// cached, so it is re-minted next time.
	expires, err := tokenExpiry(token)
	if err != nil {
		c.token, c.expires = "", time.Time{}
		return token, nil
	}

	c.token, c.expires = token, expires
	if c.useDisk {
		// A cache that cannot be written costs an extra mint on the next
		// invocation and nothing else, so it must not fail the request the token
		// was minted for — an unwritable cache directory would otherwise break
		// every cachew command.
		_ = c.writeDisk(token) //nolint:errcheck
	}
	return token, nil
}

// fresh reports whether a token expiring at expires can still be used.
func (c *cache) fresh(expires time.Time) bool {
	return time.Now().Add(c.refreshBefore).Before(expires)
}

// path is the on-disk location of this context's cached token.
//
// The context name comes from a config file and is interpolated into a path, so it
// is restricted to a safe filename rather than trusted: a name containing a
// separator or ".." would otherwise write outside the cache directory.
func (c *cache) path() (string, error) {
	if c.name == "" || c.name != filepath.Base(c.name) || c.name == "." || c.name == ".." {
		return "", errors.Errorf("context name %q cannot be used as a cache filename", c.name)
	}
	if strings.ContainsAny(c.name, `/\`) {
		return "", errors.Errorf("context name %q cannot be used as a cache filename", c.name)
	}
	dir, err := os.UserCacheDir()
	if err != nil {
		return "", errors.Errorf("locate user cache directory: %w", err)
	}
	return filepath.Join(dir, cacheDirName, "tokens", c.filename()), nil
}

// filename is the cache entry's base name, embedding the config fingerprint so a
// context edit resolves to a different entry.
func (c *cache) filename() string {
	if c.fingerprint == "" {
		return c.name + ".jwt"
	}
	return c.name + "-" + c.fingerprint + ".jwt"
}

// readDisk returns the cached token, if one is present and parseable. Any problem
// is a cache miss rather than an error: a corrupt or truncated file should cost a
// fresh mint, not break the client.
//
// The entry is only trusted if it is a regular file with owner-only permissions.
// That rejects a symlink pointing somewhere else and a cache left group- or
// world-writable, either of which would let another account choose the bearer
// token this client presents.
func (c *cache) readDisk() (token string, expires time.Time, ok bool) {
	path, err := c.path()
	if err != nil {
		return "", time.Time{}, false
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return "", time.Time{}, false
	}
	contents, err := os.ReadFile(path)
	if err != nil {
		return "", time.Time{}, false
	}
	token = string(contents)
	expires, err = tokenExpiry(token)
	if err != nil {
		return "", time.Time{}, false
	}
	return token, expires, true
}

// writeDisk stores the token with owner-only permissions, replacing any previous
// entry atomically so a concurrent reader never sees a half-written token.
func (c *cache) writeDisk(token string) error {
	path, err := c.path()
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return errors.Errorf("create token cache directory: %w", err)
	}

	temp, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return errors.Errorf("create token cache file: %w", err)
	}
	defer os.Remove(temp.Name()) //nolint:errcheck

	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close() //nolint:errcheck,gosec
		return errors.Errorf("set token cache permissions: %w", err)
	}
	if _, err := temp.WriteString(token); err != nil {
		_ = temp.Close() //nolint:errcheck,gosec
		return errors.Errorf("write token cache: %w", err)
	}
	if err := temp.Close(); err != nil {
		return errors.Errorf("close token cache: %w", err)
	}
	// path is built from a context name that path() has already constrained to a
	// bare filename, so it cannot escape the cache directory.
	if err := os.Rename(temp.Name(), path); err != nil { //nolint:gosec
		return errors.Errorf("replace token cache: %w", err)
	}

	c.removeStaleEntries(dir)
	return nil
}

// removeStaleEntries deletes this context's cache entries written under previous
// configurations, so a token minted for settings the operator has since changed
// cannot linger on disk for its remaining lifetime.
func (c *cache) removeStaleEntries(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	current := c.filename()
	for _, entry := range entries {
		name := entry.Name()
		if name == current {
			continue
		}
		// Match only this context's own entries — a bare "<name>.jwt" or
		// "<name>-<fingerprint>.jwt". A looser prefix match would delete entries
		// belonging to another context whose name happens to start with ours.
		if name == c.name+".jwt" || isFingerprintEntry(name, c.name) {
			_ = os.Remove(filepath.Join(dir, name)) //nolint:errcheck,gosec
		}
	}
}

// isFingerprintEntry reports whether name is "<context>-<fingerprint>.jwt" for the
// given context, where a fingerprint is exactly fingerprintLength hex characters.
// A context whose own name ends in "-<12 hex>" is not at risk of collateral
// deletion: fingerprint() never returns empty, so every real entry carries a
// fingerprint segment of its own and cannot look like a shorter context's entry.
func isFingerprintEntry(name, context string) bool {
	rest, ok := strings.CutPrefix(name, context+"-")
	if !ok {
		return false
	}
	rest, ok = strings.CutSuffix(rest, ".jwt")
	if !ok || len(rest) != fingerprintLength {
		return false
	}
	for _, r := range rest {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}
