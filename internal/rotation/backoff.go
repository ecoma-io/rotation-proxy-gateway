package rotation

import (
	"crypto/rand"
	"encoding/binary"
	"time"

	"rotation-proxy-gateway/internal/pool"
)

// jitterFactor returns a uniform float64 in [0, 1). The source is crypto/rand
// because the semgrep security gate rejects every math/rand variant even for
// non-cryptographic jitter, and backoff math runs so rarely that the
// syscall-backed read costs nothing that matters. Taking the top 53 bits
// keeps the value uniform despite float64 rounding.
func jitterFactor() float64 {
	var b [8]byte
	_, _ = rand.Read(b[:]) // documented never to fail; all-zero bytes still yield a usable factor
	return float64(binary.LittleEndian.Uint64(b[:])>>11) / (1 << 53)
}

// BackoffFor returns how long to wait before the next rotation attempt of a
// route whose last attempts did not change its egress IP: the route's
// rotate-interval doubled per consecutive unchanged result (interval, 2x, 4x,
// ...), capped at max. Retries never stop; they only slow down. Jitter of ±10%
// spreads out routes whose providers recover on the same cadence.
func BackoffFor(interval time.Duration, consecutive int, max time.Duration) time.Duration {
	if interval <= 0 {
		interval = time.Second
	}
	if consecutive < 1 {
		consecutive = 1
	}
	// Saturating doubling shared with the pool's dial cooldown: base only
	// ever doubles while it still fits under max, so no intermediate value
	// can overflow a duration.
	base := pool.SaturatingCooldown(interval, max, consecutive)
	jittered := time.Duration(float64(base) * (0.9 + 0.2*jitterFactor()))
	if jittered <= 0 {
		return base
	}
	if jittered > max {
		return max
	}
	return jittered
}
