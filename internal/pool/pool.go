// Package pool holds the upstream proxy pool: rotation, route health tracking,
// and endpoint dial cooldowns.
package pool

import (
	"net/url"
	"sync"
	"time"
)

// Proxy is one upstream SOCKS route plus its health state.
type Proxy struct {
	URL *url.URL

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
	Proxy               string `json:"proxy"`
	Available           bool   `json:"available"`
	ConsecutiveFailures int    `json:"consecutiveFailures"`
	CooldownFor         string `json:"cooldownFor"`
	Successes           uint64 `json:"successes"`
	Failures            uint64 `json:"failures"`
	LastDialError       string `json:"lastDialError,omitempty"`
	AuthFailures        uint64 `json:"authFailures"`
	AuthBlocked         bool   `json:"authBlocked"`
	LastAuthError       string `json:"lastAuthError,omitempty"`
}

// Pool is a set of upstream SOCKS routes with least-recently-used round-robin
// rotation, endpoint dial cooldowns, and authentication blocks. All methods
// are safe for concurrent use.
type Pool struct {
	mu      sync.Mutex
	entries []*Proxy
	base    time.Duration
	max     time.Duration
	seq     uint64 // pick sequence driving least-recently-used rotation

	// Now is the clock used for cooldowns; tests replace it.
	Now func() time.Time
}

// New builds a pool from parsed proxy URLs.
func New(urls []*url.URL, base, max time.Duration) *Pool {
	entries := make([]*Proxy, 0, len(urls))
	for _, u := range urls {
		entries = append(entries, &Proxy{URL: u})
	}
	return &Pool{
		entries: entries,
		base:    base,
		max:     max,
		Now:     time.Now,
	}
}

func (pl *Pool) nextSeq() uint64 {
	pl.seq++
	return pl.seq
}

// Pick returns the next proxy to try, excluding entries already tried for the
// current request. It picks the least recently used available entry (stable
// order on ties). When every non-excluded, non-auth-blocked entry is cooling
// down it returns the one that recovers soonest. It returns nil when exclude
// covers all entries or all remaining entries are auth-blocked.
func (pl *Pool) Pick(exclude map[*Proxy]bool) *Proxy {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	now := pl.Now()

	var avail []*Proxy
	for _, e := range pl.entries {
		if !exclude[e] && e.available(now) {
			avail = append(avail, e)
		}
	}
	if len(avail) == 0 {
		var best *Proxy
		for _, e := range pl.entries {
			if exclude[e] || e.authBlockedNow() {
				continue
			}
			if best == nil || e.cooldownUntilTime().Before(best.cooldownUntilTime()) {
				best = e
			}
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
// expected to recover without a pool reload that changes the route URL.
func (pl *Pool) ReportSuccess(p *Proxy) {
	seq := pl.nextSeq() // before p.mu: keep lock order pool -> proxy
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
	now := pl.Now() // before p.mu: keep lock order pool -> proxy
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consecutiveFailures++
	p.failures++
	shift := p.consecutiveFailures - 1
	if shift > 16 {
		shift = 16
	}
	cd := pl.base << uint(shift)
	if cd > pl.max {
		cd = pl.max
	}
	p.cooldownUntil = now.Add(cd)
	if err != nil {
		p.lastDialError = err.Error()
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
		p.lastAuthError = err.Error()
	}
}

// Reload replaces the pool contents, preserving health state for URLs that
// are present both before and after the change.
func (pl *Pool) Reload(urls []*url.URL) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	kept := make(map[string]*Proxy, len(pl.entries))
	for _, e := range pl.entries {
		kept[e.URL.String()] = e
	}
	next := make([]*Proxy, 0, len(urls))
	for _, u := range urls {
		if old, ok := kept[u.String()]; ok {
			next = append(next, old)
			delete(kept, u.String())
		} else {
			next = append(next, &Proxy{URL: u})
		}
	}
	pl.entries = next
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
