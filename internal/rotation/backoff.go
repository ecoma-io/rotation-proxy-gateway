package rotation

import (
	"math/rand/v2"
	"time"
)

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
	base := interval
	for range consecutive - 1 {
		if base >= max || base > time.Duration(1<<62) {
			base = max
			break
		}
		base *= 2
	}
	if base > max {
		base = max
	}
	jittered := time.Duration(float64(base) * (0.9 + 0.2*rand.Float64()))
	if jittered <= 0 {
		return base
	}
	if jittered > max {
		return max
	}
	return jittered
}
