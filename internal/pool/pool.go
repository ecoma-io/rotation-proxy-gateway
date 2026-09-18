// Package pool holds the upstream proxy pool: rotation, per-proxy health
// tracking, and failure cooldowns.
package pool

import (
	"net/url"
	"sync"
	"time"
)

// Proxy is one upstream proxy plus its health state.
type Proxy struct {
	URL *url.URL

	mu                  sync.Mutex
	consecutiveFailures int
	cooldownUntil       time.Time
	lastError           string
	usedSeq             uint64
	successes           uint64
	failures            uint64
}

func (p *Proxy) available(now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return !now.Before(p.cooldownUntil)
}

func (p *Proxy) cooldownUntilTime() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cooldownUntil
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
	LastError           string `json:"lastError,omitempty"`
}

// Pool is a set of upstream proxies with least-recently-used round-robin
// rotation and cooldown handling. All methods are safe for concurrent use.
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

// Pick returns the next proxy to try, excluding entries already tried for
// the current request. It picks the least recently used available entry
// (stable order on ties). When every non-excluded entry is cooling down it
// returns the one that recovers soonest (degraded beats down). It returns nil
// only when exclude covers the whole pool.
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
			if exclude[e] {
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

// ReportSuccess records a successful use and clears any cooldown.
func (pl *Pool) ReportSuccess(p *Proxy) {
	seq := pl.nextSeq() // before p.mu: keep lock order pool -> proxy
	p.mu.Lock()
	defer p.mu.Unlock()
	p.consecutiveFailures = 0
	p.cooldownUntil = time.Time{}
	p.lastError = ""
	p.successes++
	p.usedSeq = seq
}

// ReportFailure records a failure and puts the proxy into an exponentially
// growing cooldown: base doubled per consecutive failure, capped at max.
// It returns the applied cooldown.
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
		p.lastError = err.Error()
	}
	return cd
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
		avail := !now.Before(e.cooldownUntil)
		cooldown := "0s"
		if !avail {
			cooldown = e.cooldownUntil.Sub(now).Truncate(time.Millisecond).String()
		}
		out = append(out, Status{
			Proxy:               e.URL.Host,
			Available:           avail,
			ConsecutiveFailures: e.consecutiveFailures,
			CooldownFor:         cooldown,
			Successes:           e.successes,
			Failures:            e.failures,
			LastError:           e.lastError,
		})
		e.mu.Unlock()
	}
	return out
}
