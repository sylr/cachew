package oidc

import "time"

// SetTimeoutsForTest shortens the outbound request timeouts so tests exercising an
// unreachable issuer do not have to wait for the production bounds.
func SetTimeoutsForTest(discovery, jwks time.Duration) (restore func()) {
	previousDiscovery, previousJWKS := discoveryTimeout, jwksTimeout
	discoveryTimeout, jwksTimeout = discovery, jwks
	return func() { discoveryTimeout, jwksTimeout = previousDiscovery, previousJWKS }
}

// SetRefreshCooldownForTest overrides the minimum interval between forced JWKS
// refreshes, so tests can exercise both key rotation and the rate limit itself.
func SetRefreshCooldownForTest(d time.Duration) (restore func()) {
	previous := refreshCooldown
	refreshCooldown = d
	return func() { refreshCooldown = previous }
}
