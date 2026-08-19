package tokensource

import "time"

// NewCacheForTest exposes the caching wrapper so tests can drive it with a fake
// underlying source and count how often a token is actually minted. The empty
// fingerprint keeps the legacy "<name>.jwt" entry name.
func NewCacheForTest(name string, source Source, useDisk bool, refreshBefore time.Duration) Source {
	return newCache(name, source, useDisk, refreshBefore, "")
}

// Fingerprint exposes the config digest used to key disk-cache entries.
func Fingerprint(cfg Config) string { return fingerprint(cfg) }

// NewAWSSTSForTest builds the AWS STS source against a fake STS API, so tests
// exercise the request it constructs without reaching AWS.
func NewAWSSTSForTest(cfg Config, client stsAPI) (Source, error) {
	source, err := newAWSSTSWithClient(cfg, client)
	if err != nil {
		return nil, err
	}
	return source, nil
}
