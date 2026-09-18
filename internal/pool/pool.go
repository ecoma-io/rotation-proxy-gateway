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

// Proxy is one upstream SOCKS route plus its health state.
type Proxy struct {
	URL  *url.URL
	Kind config.EgressKind

	mu                  sync.Mutex
	consecutiveFailures int
	cooldownUntil       time.Time
	lastDialError       string
	authFailures        uint64
	authBlocked         bool
	lastAuthError       string
	usedSeq             uint64
	successes           uint64
	failures            uint64
}

func (p *Proxy) available(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !p.authBlocked && !now.Before(p.cooldownUntil)
}

func (p *Proxy) cooldownUntilTime() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cooldownUntil
}

func (p *Proxy) authBlockedNow() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.authBlocked
}

func (p *Proxy) lastUsedSequence() uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.usedSeq
}

func (p *Proxy) markUsed(seq uint64) {
	p.mu.Lock()
	p.usedSeq = seq
	p.mu.Unlock()
}

// Status is the exported health view of one proxy. Proxy is the redacted
// host:port (credentials never leave the process).
type Status struct {
	Proxy               string            `json:"proxy"`
	Kind                config.EgressKind `json:"kind"`
	Available           bool              `json:"available"`
	ConsecutiveFailures int               `json:"consecutiveFailures"`
	CooldownFor         string            `json:"cooldownFor"`
	Successes           uint64            `json:"successes"`
	Failures            uint64            `json:"failures"`
	LastDialError       string            `json:"lastDialError,omitempty"`
	AuthFailures        uint64            `json:"authFailures"`
	AuthBlocked         bool              `json:"authBlocked"`
	LastAuthError       string            `json:"lastAuthError,omitempty"`
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

// NewRoutes builds a pool from validated, kinded static routes.
func NewRoutes(routes []config.RouteSpec, base, max time.Duration) *Pool {
	entries := make([]*Proxy, 0, len(routes))
	for _, route := range routes {
		entries = append(entries, &Proxy{URL: route.URL, Kind: route.Kind})
	}
	return &Pool{
		entries: entries,
		base:    base,
		max:     max,
		seq:     &atomic.Uint64{},
		Now:     time.Now,
	}
}

// Reconfigure returns a new immutable route-list snapshot. Route health is
// retained only for canonical URL+kind matches; existing in-flight operations
// may safely keep using the original pool.
func (pl *Pool) Reconfigure(routes []config.RouteSpec, base, max time.Duration) *Pool {
	pl.mu.Lock()
	entries := append([]*Proxy(nil), pl.entries...)
	now := pl.Now
	seq := pl.seq
	pl.mu.Unlock()

	kept := make(map[string]*Proxy, len(entries))
	for _, entry := range entries {
		kept[routeKey(entry.URL, entry.Kind)] = entry
	}
	next := make([]*Proxy, 0, len(routes))
	for _, route := range routes {
		key := routeKey(route.URL, route.Kind)
		if prior, ok := kept[key]; ok {
			next = append(next, prior)
		} else {
			next = append(next, &Proxy{URL: route.URL, Kind: route.Kind})
		}
	}
	return &Pool{entries: next, base: base, max: max, seq: seq, Now: now}
}

func routeKey(u *url.URL, kind config.EgressKind) string {
	return config.CanonicalRouteID(u) + "|" + string(kind)
}

func (pl *Pool) nextSeq() uint64 {
	return pl.seq.Add(1)
}

// PickFor returns the next allowed proxy, excluding entries already tried for
// the current request. It picks the least recently used available entry (stable
// order on ties). When every allowed, non-excluded, non-auth-blocked entry is
// cooling down it returns the allowed route that recovers soonest. It returns
// nil when no allowed entry remains. The filter is applied equally to both
// paths so a dedicated v4/v6 listener never crosses into another egress kind.
func (pl *Pool) PickFor(exclude map[*Proxy]bool, allow func(*Proxy) bool) *Proxy {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	now := pl.Now()

	allowed := func(p *Proxy) bool { return allow == nil || allow(p) }
	var avail []*Proxy
	for _, e := range pl.entries {
		if allowed(e) && !exclude[e] && e.available(now) {
			avail = append(avail, e)
		}
	}
	if len(avail) == 0 {
		var best *Proxy
		for _, e := range pl.entries {
			if !allowed(e) || exclude[e] || e.authBlockedNow() {
				continue
			}
			if best == nil || e.cooldownUntilTime().Before(best.cooldownUntilTime()) {
				best = e
			}
		}
		if best != nil {
			best.markUsed(pl.nextSeq())
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
	chosen.markUsed(pl.nextSeq())
	return chosen
}

// ReportSuccess records a successful use and clears any endpoint dial cooldown.
// It does not clear an authentication block: unchanged credentials cannot be
// expected to recover without a reload that replaces the route.
func (pl *Pool) ReportSuccess(p *Proxy) {
	seq := pl.nextSeq()
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consecutiveFailures = 0
	p.cooldownUntil = time.Time{}
	p.lastDialError = ""
	p.successes++
	p.usedSeq = seq
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
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consecutiveFailures++
	p.failures++
	cd := saturatingCooldown(base, max, p.consecutiveFailures)
	p.cooldownUntil = now.Add(cd)
	if err != nil {
		p.lastDialError = sanitize.ErrorString(err)
	}
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
	defer p.mu.Unlock()
	p.authFailures++
	p.authBlocked = true
	if err != nil {
		p.lastAuthError = sanitizeAuthError(err)
	}
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
	now := pl.Now()
	out := make([]Status, 0, len(pl.entries))
	for _, e := range pl.entries {
		e.mu.Lock()
		cooling := now.Before(e.cooldownUntil)
		cooldown := "0s"
		if cooling {
			cooldown = e.cooldownUntil.Sub(now).Truncate(time.Millisecond).String()
		}
		out = append(out, Status{
			Proxy:               e.URL.Host,
			Kind:                e.Kind,
			Available:           !e.authBlocked && !cooling,
			ConsecutiveFailures: e.consecutiveFailures,
			CooldownFor:         cooldown,
			Successes:           e.successes,
			Failures:            e.failures,
			LastDialError:       e.lastDialError,
			AuthFailures:        e.authFailures,
			AuthBlocked:         e.authBlocked,
			LastAuthError:       e.lastAuthError,
		})
		e.mu.Unlock()
	}
	return out
}
