// Package pool holds the upstream proxy pool: rotation, route health tracking,
// and endpoint dial cooldowns.
package pool

import (
	"math"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/sanitize"
)

// RotationState is the manual-route rotation lifecycle phase shown by /status.
// Auto routes have none. draining/rotating/verifying mean the route is
// temporarily ineligible for new picks; stale means it is serving again after a
// rotation that did not change its egress IP.
type RotationState string

const (
	RotationIdle      RotationState = "idle"
	RotationDraining  RotationState = "draining"
	RotationRotating  RotationState = "rotating"
	RotationVerifying RotationState = "verifying"
	RotationStale     RotationState = "stale"
)

// Proxy is one upstream SOCKS route plus its health state.
type Proxy struct {
	URL    *url.URL
	Kind   config.EgressKind
	Origin config.RouteOrigin

	// Pick-path state is lock-free. PickFor scans every route on every
	// request, so these fields are atomics; the pool mutex only serializes
	// the choose-and-mark step that keeps LRU order exact. Drain-critical
	// pairing lives here too: markPicked raises inFlight before it publishes
	// the pick sequence, so once a pick is visible at all, its in-flight
	// holder is already counted.
	usedSeq       atomic.Uint64
	inFlight      atomic.Int64
	cooldownUntil atomic.Int64 // dial cooldown deadline, UnixNano; 0 = none
	authBlocked   atomic.Bool
	rotating      atomic.Bool

	mu                  sync.Mutex
	consecutiveFailures int
	lastDialError       string
	authFailures        uint64
	lastAuthError       string
	successes           uint64
	failures            uint64

	// Rotation bookkeeping (manual routes only): the lifecycle phase shown by
	// /status plus the stale-serving counters. Mutated only by the rotation
	// engine; serving paths read pick eligibility through the atomics above.
	rotationState     RotationState
	lastIP            string
	lastRotationAt    time.Time
	nextRetryIn       time.Duration
	consecutiveSameIP int
}

func newProxy(route config.RouteSpec) *Proxy {
	origin := effectiveOrigin(route.Origin)
	p := &Proxy{URL: route.URL, Kind: route.Kind, Origin: origin}
	if origin == config.RouteOriginManual {
		p.rotationState = RotationIdle
	}
	return p
}

// effectiveOrigin treats an unset origin as auto: hand-built RouteSpecs may
// carry the zero value and identity keys must agree with constructed entries.
func effectiveOrigin(origin config.RouteOrigin) config.RouteOrigin {
	if origin == "" {
		return config.RouteOriginAuto
	}
	return origin
}

// availableAt reports whether the route may take a new pick at UnixNano time
// nowNano. cooldownUntil 0 means no cooldown and is always available, which
// also covers test clocks pinned at time.Unix(0, 0).
func (p *Proxy) availableAt(nowNano int64) bool {
	cu := p.cooldownUntil.Load()
	return !p.authBlocked.Load() && !p.rotating.Load() && (cu == 0 || nowNano >= cu)
}

func (p *Proxy) cooldownNano() int64 { return p.cooldownUntil.Load() }

func (p *Proxy) authBlockedNow() bool { return p.authBlocked.Load() }

func (p *Proxy) lastUsedSequence() uint64 { return p.usedSeq.Load() }

// markPicked records the pick sequence and one in-flight holder. The
// in-flight increment lands before the sequence store: any observer that can
// already see the route as picked (a bumped usedSeq) therefore also sees the
// in-flight count, so a rotation drain can never miss its holder.
func (p *Proxy) markPicked(seq uint64) {
	p.inFlight.Add(1)
	p.usedSeq.Store(seq)
}

func (p *Proxy) rotatingNow() bool { return p.rotating.Load() }

// Status is the exported health view of one proxy. Proxy is the redacted
// host:port (credentials never leave the process).
type Status struct {
	Proxy               string            `json:"proxy"`
	Kind                config.EgressKind `json:"kind"`
	Origin              string            `json:"origin"`
	Available           bool              `json:"available"`
	InFlight            int               `json:"inFlight"`
	ConsecutiveFailures int               `json:"consecutiveFailures"`
	CooldownFor         string            `json:"cooldownFor"`
	Successes           uint64            `json:"successes"`
	Failures            uint64            `json:"failures"`
	LastDialError       string            `json:"lastDialError,omitempty"`
	AuthFailures        uint64            `json:"authFailures"`
	AuthBlocked         bool              `json:"authBlocked"`
	LastAuthError       string            `json:"lastAuthError,omitempty"`
	Rotation            *RotationStatus   `json:"rotation,omitempty"`
}

// RotationStatus is the public rotation view of one manual route. LastIP is
// the route's own public egress IP — an operational fact operators need to
// verify rotations, not a credential.
type RotationStatus struct {
	State             string `json:"state"`
	LastIP            string `json:"lastIP,omitempty"`
	LastRotationAt    string `json:"lastRotationAt,omitempty"`
	NextRetryIn       string `json:"nextRetryIn,omitempty"`
	ConsecutiveSameIP int    `json:"consecutiveSameIP"`
}

// Pool is a set of upstream SOCKS routes with least-recently-used round-robin
// rotation, endpoint dial cooldowns, and authentication blocks. All methods
// are safe for concurrent use.
type Pool struct {
	mu      sync.Mutex
	entries []*Proxy
	base    time.Duration
	max     time.Duration
	seq     *atomic.Uint64 // shared pick sequence across immutable generations

	// Now is the clock used for cooldowns; tests replace it.
	Now func() time.Time
}

// NewRoutes builds a pool from validated, kinded routes of both origins.
func NewRoutes(routes []config.RouteSpec, base, max time.Duration) *Pool {
	entries := make([]*Proxy, 0, len(routes))
	for _, route := range routes {
		entries = append(entries, newProxy(route))
	}
	return &Pool{
		entries: entries,
		base:    base,
		max:     max,
		seq:     &atomic.Uint64{},
		Now:     time.Now,
	}
}

// Reconfigure returns a new immutable route-list snapshot. Route state is
// retained only for canonical URL+kind+origin matches; moving a route between
// proxies.auto and proxies.manual rebuilds it because its role changed.
// Existing in-flight operations may safely keep using the original pool.
func (pl *Pool) Reconfigure(routes []config.RouteSpec, base, max time.Duration) *Pool {
	pl.mu.Lock()
	entries := append([]*Proxy(nil), pl.entries...)
	now := pl.Now
	seq := pl.seq
	pl.mu.Unlock()

	kept := make(map[string]*Proxy, len(entries))
	for _, entry := range entries {
		kept[routeKey(entry.URL, entry.Kind, entry.Origin)] = entry
	}
	next := make([]*Proxy, 0, len(routes))
	for _, route := range routes {
		if prior, ok := kept[routeKey(route.URL, route.Kind, route.Origin)]; ok {
			next = append(next, prior)
		} else {
			next = append(next, newProxy(route))
		}
	}
	return &Pool{entries: next, base: base, max: max, seq: seq, Now: now}
}

func routeKey(u *url.URL, kind config.EgressKind, origin config.RouteOrigin) string {
	return config.CanonicalRouteID(u) + "|" + string(kind) + "|" + string(effectiveOrigin(origin))
}

func (pl *Pool) nextSeq() uint64 {
	return pl.seq.Add(1)
}

// PickFor returns the next allowed proxy, excluding entries already tried for
// the current request. It picks the least recently used available entry (stable
// order on ties). When every allowed, non-excluded, non-auth-blocked entry is
// cooling down it returns the allowed route that recovers soonest. Routes held
// by an in-progress rotation are skipped on both paths. It returns nil when no
// allowed entry remains. The filter is applied equally to both paths so a
// dedicated v4/v6 listener never crosses into another egress kind.
//
// Every successful pick holds one in-flight count on the returned route; the
// caller releases it via Release when the request or tunnel finishes.
func (pl *Pool) PickFor(exclude map[*Proxy]bool, allow func(*Proxy) bool) *Proxy {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	nowNano := pl.Now().UnixNano()

	allowed := func(p *Proxy) bool { return allow == nil || allow(p) }
	var avail []*Proxy
	for _, e := range pl.entries {
		if allowed(e) && !exclude[e] && e.availableAt(nowNano) {
			avail = append(avail, e)
		}
	}
	if len(avail) == 0 {
		var best *Proxy
		var bestCooldown int64
		for _, e := range pl.entries {
			if !allowed(e) || exclude[e] || e.authBlockedNow() || e.rotatingNow() {
				continue
			}
			cu := e.cooldownNano()
			if best == nil || cu < bestCooldown {
				best, bestCooldown = e, cu
			}
		}
		if best != nil {
			best.markPicked(pl.nextSeq())
		}
		return best
	}

	chosen := avail[0]
	chosenSeq := chosen.lastUsedSequence()
	for _, e := range avail[1:] {
		if s := e.lastUsedSequence(); s < chosenSeq {
			chosen, chosenSeq = e, s
		}
	}
	chosen.markPicked(pl.nextSeq())
	return chosen
}

// Release drops one in-flight hold taken by PickFor. Each successful pick is
// released exactly once when its request or tunnel finishes; releasing a route
// that holds nothing is harmless.
func (p *Proxy) Release() {
	for {
		n := p.inFlight.Load()
		if n <= 0 {
			return
		}
		if p.inFlight.CompareAndSwap(n, n-1) {
			return
		}
	}
}

// InFlight reports how many picked requests or tunnels currently hold the
// route. The rotation engine drains to zero before rotating.
func (p *Proxy) InFlight() int { return int(p.inFlight.Load()) }

// ReportSuccess records a successful use and clears any endpoint dial cooldown.
// It does not clear an authentication block: unchanged credentials cannot be
// expected to recover without a reload that replaces the route.
func (pl *Pool) ReportSuccess(p *Proxy) {
	seq := pl.nextSeq()
	p.mu.Lock()
	p.consecutiveFailures = 0
	p.lastDialError = ""
	p.successes++
	p.mu.Unlock()
	p.cooldownUntil.Store(0)
	p.usedSeq.Store(seq)
}

// ReportFailure records an upstream endpoint TCP dial failure and puts the
// proxy into an exponentially growing cooldown: base doubled per consecutive
// dial failure, capped at max. It returns the applied cooldown.
func (pl *Pool) ReportFailure(p *Proxy, err error) time.Duration {
	pl.mu.Lock()
	base, max := pl.base, pl.max
	nowFunc := pl.Now
	pl.mu.Unlock()
	now := nowFunc()
	cd := func() time.Duration {
		p.mu.Lock()
		defer p.mu.Unlock()
		p.consecutiveFailures++
		p.failures++
		if err != nil {
			p.lastDialError = sanitize.ErrorString(err)
		}
		return saturatingCooldown(base, max, p.consecutiveFailures)
	}()
	p.cooldownUntil.Store(now.Add(cd).UnixNano())
	return cd
}

// saturatingCooldown returns base doubled (failures-1) times, capped at max.
// It never overflows and never returns a negative duration, even when base or
// max bypasses runtime configuration validation.
func saturatingCooldown(base, max time.Duration, failures int) time.Duration {
	if base <= 0 || max <= 0 {
		return 0
	}
	if base >= max {
		return max
	}
	cd := base
	shift := failures - 1
	if shift < 0 {
		shift = 0
	}
	if shift > 63 {
		return max
	}
	for range shift {
		if cd > max/2 {
			return max
		}
		if cd > time.Duration(math.MaxInt64)/2 {
			return max
		}
		cd *= 2
	}
	return cd
}

// ReportAuthBlocked records that a SOCKS route could not authenticate. It is
// separate from endpoint dial health and never changes cooldown.
func (pl *Pool) ReportAuthBlocked(p *Proxy, err error) {
	p.mu.Lock()
	p.authFailures++
	if err != nil {
		p.lastAuthError = sanitizeAuthError(err)
	}
	p.mu.Unlock()
	p.authBlocked.Store(true)
}

// sanitizeAuthError stores only the fixed safe labels produced by the SOCKS
// handshake for auth failures known to this package. Any other error text
// (including wrapped dial details or future auth reasons) is replaced with a
// fixed label so /status never exposes raw arbitrary errors.
func sanitizeAuthError(err error) string {
	msg := sanitize.ErrorString(err)
	switch {
	case containsToken(msg, "endpoint requires credentials but none are configured"):
		return "endpoint requires credentials but none are configured"
	case containsToken(msg, "endpoint accepted no offered authentication method"):
		return "endpoint accepted no offered authentication method"
	case containsToken(msg, "endpoint rejected credentials"):
		return "endpoint rejected credentials"
	default:
		return "SOCKS authentication failed"
	}
}

func containsToken(haystack, needle string) bool {
	return len(haystack) >= len(needle) && strings.Contains(haystack, needle)
}

// Snapshot returns the health view of every entry.
func (pl *Pool) Snapshot() []Status {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	nowNano := pl.Now().UnixNano()
	out := make([]Status, 0, len(pl.entries))
	for _, e := range pl.entries {
		e.mu.Lock()
		cu := e.cooldownNano()
		cooling := cu != 0 && nowNano < cu
		cooldown := "0s"
		if cooling {
			cooldown = time.Duration(cu - nowNano).Truncate(time.Millisecond).String()
		}
		out = append(out, Status{
			Proxy:               e.URL.Host,
			Kind:                e.Kind,
			Origin:              string(e.Origin),
			Available:           !e.authBlocked.Load() && !e.rotating.Load() && !cooling,
			InFlight:            int(e.inFlight.Load()),
			ConsecutiveFailures: e.consecutiveFailures,
			CooldownFor:         cooldown,
			Successes:           e.successes,
			Failures:            e.failures,
			LastDialError:       e.lastDialError,
			AuthFailures:        e.authFailures,
			AuthBlocked:         e.authBlocked.Load(),
			LastAuthError:       e.lastAuthError,
			Rotation:            e.rotationStatus(),
		})
		e.mu.Unlock()
	}
	return out
}

// rotationStatus builds the rotation view of a manual route. It must be called
// with p.mu held.
func (p *Proxy) rotationStatus() *RotationStatus {
	if p.Origin != config.RouteOriginManual {
		return nil
	}
	rs := &RotationStatus{
		State:             string(p.rotationState),
		ConsecutiveSameIP: p.consecutiveSameIP,
	}
	rs.LastIP = p.lastIP
	if !p.lastRotationAt.IsZero() {
		rs.LastRotationAt = p.lastRotationAt.UTC().Format(time.RFC3339)
	}
	if p.nextRetryIn > 0 {
		rs.NextRetryIn = p.nextRetryIn.Truncate(time.Millisecond).String()
	}
	return rs
}
