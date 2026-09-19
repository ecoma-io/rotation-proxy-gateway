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
	// the choose-and-mark step that keeps selection order exact. Drain-critical
	// pairing lives here too: serving raises inFlight before it advances the
	// pass, so once a pick is visible at all, its in-flight holder is already
	// counted.
	//
	// pass is the weighted recency clock: every serving event advances it by
	// the cached stride below, so heavier routes drift back more slowly and
	// are re-picked proportionally more often. Equal weights reproduce plain
	// least-recently-used round-robin exactly. The stride is precomputed from
	// the weight (strideUnits/weight) whenever the weight changes, keeping the
	// pick path free of both a division and a second atomic load.
	pass          atomic.Uint64
	strideStep    atomic.Uint64
	weight        atomic.Uint64
	inFlight      atomic.Int64
	cooldownUntil atomic.Int64 // dial cooldown deadline, relNanos; 0 = none
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

// strideUnits scales the weighted recency clock. One serving event advances a
// route's pass by strideUnits/weight: at the MaxRouteWeight ceiling the stride
// still keeps ~4 decimal digits of resolution, and the uint64 pass only
// overflows past ~2^40 serving events — unreachable in practice.
const strideUnits = uint64(1) << 24

// normalizeWeight guards hand-built specs that bypass YAML validation: a
// weight below the default behaves as the default.
func normalizeWeight(w int) uint64 {
	if w < config.DefaultRouteWeight {
		return config.DefaultRouteWeight
	}
	return uint64(w)
}

// processStart anchors the cooldown clock. Cooldown deadlines are stored as
// nanoseconds relative to it, not as UnixNano: t.Sub(processStart) uses the
// monotonic reading whenever both times carry one, so cooldowns measure real
// elapsed time and wall-clock steps (NTP corrections, manual date changes)
// can neither expire nor extend a cooldown. Clocks without a monotonic
// reading — the test fakes — fall back to wall arithmetic against the same
// anchor, which is consistent as long as every site goes through relNanos.
var processStart = time.Now()

func relNanos(t time.Time) int64 { return int64(t.Sub(processStart)) }

func newProxy(route config.RouteSpec, anchor uint64) *Proxy {
	origin := effectiveOrigin(route.Origin)
	p := &Proxy{URL: route.URL, Kind: route.Kind, Origin: origin}
	p.setWeight(route.Weight)
	p.pass.Store(anchor)
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

// availableAt reports whether the route may take a new pick at nowNano, a
// relNanos (monotonic-anchored) timestamp. cooldownUntil 0 means no cooldown
// and is always available; a test clock pinned before processStart yields a
// negative nowNano, which compares consistently against stored deadlines.
func (p *Proxy) availableAt(nowNano int64) bool {
	cu := p.cooldownUntil.Load()
	return !p.authBlocked.Load() && !p.rotating.Load() && (cu == 0 || nowNano >= cu)
}

func (p *Proxy) cooldownNano() int64 { return p.cooldownUntil.Load() }

func (p *Proxy) authBlockedNow() bool { return p.authBlocked.Load() }

func (p *Proxy) recencyPass() uint64 { return p.pass.Load() }

// stride is how far one serving event pushes the route back on the weighted
// recency clock: heavier routes drift more slowly and absorb proportionally
// more picks. The division happens once per weight change, not per pick.
func (p *Proxy) stride() uint64 { return p.strideStep.Load() }

// setWeight applies a reloaded configuration weight in place. Weight is not
// route identity: retuning it must never reset cooldown, authentication, or
// rotation state, so Reconfigure updates kept entries instead of rebuilding
// them.
func (p *Proxy) setWeight(w int) {
	weight := normalizeWeight(w)
	p.weight.Store(weight)
	p.strideStep.Store(strideUnits / weight)
}

func (p *Proxy) rotatingNow() bool { return p.rotating.Load() }

// Status is the exported health view of one proxy. Proxy is the redacted
// host:port (credentials never leave the process).
type Status struct {
	Proxy               string            `json:"proxy"`
	Kind                config.EgressKind `json:"kind"`
	Origin              string            `json:"origin"`
	Weight              uint64            `json:"weight"`
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

// Pool is a set of upstream SOCKS routes with weighted least-recently-used
// rotation, endpoint dial cooldowns, and authentication blocks. All methods
// are safe for concurrent use.
type Pool struct {
	mu      sync.Mutex
	entries []*Proxy
	base    time.Duration
	max     time.Duration

	// Family-balance state, both guarded by mu. kindStride holds each
	// family's stride (strideUnits per configured share; 0 = no share), and
	// kindPass is the family recency clock advanced by every serving event
	// through serve. When any stride is positive, mixed picks first choose
	// the family with the smaller kindPass, then the weighted route order
	// picks inside it. Reconfigure carries kindPass across generations so a
	// reload does not reset the split's phase. scratch is the per-pick family
	// bucket used by pickBalanced, reused across picks to keep the balanced
	// path allocation-free.
	kindPass   [2]uint64
	kindStride [2]uint64
	scratch    [2][]*Proxy

	// Now is the clock used for cooldowns; tests replace it.
	Now func() time.Time
}

// NewRoutes builds a pool from validated, kinded routes of both origins. The
// balance shares shape the mixed listener's family split; a zero KindBalance
// keeps every family's share following the routes' own weights.
func NewRoutes(routes []config.RouteSpec, base, max time.Duration, balance config.KindBalance) *Pool {
	entries := make([]*Proxy, 0, len(routes))
	for _, route := range routes {
		entries = append(entries, newProxy(route, 0))
	}
	pl := &Pool{entries: entries, base: base, max: max, Now: time.Now}
	pl.setBalance(balance)
	return pl
}

// setBalance installs per-generation family strides. Callers hold no lock
// only during construction; Reconfigure calls it on the new pool before
// publishing it.
func (pl *Pool) setBalance(balance config.KindBalance) {
	pl.kindStride[kindIndex(config.EgressV4)] = balanceStride(balance.V4)
	pl.kindStride[kindIndex(config.EgressV6)] = balanceStride(balance.V6)
}

// balanceStride converts a configured share into a family-clock stride; no
// share means the family never wins the clock comparison and only serves as
// standby.
func balanceStride(share int) uint64 {
	if share < 1 {
		return 0
	}
	return strideUnits / uint64(share)
}

func kindIndex(kind config.EgressKind) int {
	if kind == config.EgressV6 {
		return 1
	}
	return 0
}

// Reconfigure returns a new immutable route-list snapshot. Route state is
// retained only for canonical URL+kind+origin matches; moving a route between
// proxies.auto and proxies.manual rebuilds it because its role changed.
// Retained entries pick up a changed configured weight in place — weight is
// not identity, so retuning it keeps their health state. Family-balance
// clocks carry over so a reload does not reset the split's phase, and a
// changed ratio applies through the new strides. Existing in-flight
// operations may safely keep using the original pool.
func (pl *Pool) Reconfigure(routes []config.RouteSpec, base, max time.Duration, balance config.KindBalance) *Pool {
	pl.mu.Lock()
	entries := append([]*Proxy(nil), pl.entries...)
	kindPass := pl.kindPass
	now := pl.Now
	pl.mu.Unlock()

	// New routes join at the pool's recency front: anchoring at the smallest
	// existing pass reproduces the fresh-route-is-picked-next behavior without
	// a catch-up burst against accumulated passes.
	minPass := uint64(0)
	for i, entry := range entries {
		p := entry.pass.Load()
		if i == 0 || p < minPass {
			minPass = p
		}
	}

	kept := make(map[string]*Proxy, len(entries))
	for _, entry := range entries {
		kept[routeKey(entry.URL, entry.Kind, entry.Origin)] = entry
	}
	next := make([]*Proxy, 0, len(routes))
	for _, route := range routes {
		if prior, ok := kept[routeKey(route.URL, route.Kind, route.Origin)]; ok {
			prior.setWeight(route.Weight)
			next = append(next, prior)
		} else {
			next = append(next, newProxy(route, minPass))
		}
	}
	fresh := &Pool{entries: next, base: base, max: max, Now: now, kindPass: kindPass}
	fresh.setBalance(balance)
	return fresh
}

func routeKey(u *url.URL, kind config.EgressKind, origin config.RouteOrigin) string {
	return config.CanonicalRouteID(u) + "|" + string(kind) + "|" + string(effectiveOrigin(origin))
}

// serve records one serving step for p: an in-flight hold plus one weighted
// step back on the recency clock. The in-flight increment lands before the
// pass advance: any observer that can already see the route as picked (an
// advanced pass) therefore also sees the in-flight count, so a rotation drain
// can never miss its holder. advanceFamily is false for dedicated-listener
// picks, whose traffic must leave the family clocks untouched. With family
// balance engaged on the mixed path, the event also advances p's family clock
// by its stride, including on the all-cooling fallback path so standby service
// keeps the split's bookkeeping honest.
func (pl *Pool) serve(p *Proxy, advanceFamily bool) {
	p.inFlight.Add(1)
	p.pass.Add(p.stride())
	if advanceFamily {
		if k := kindIndex(p.Kind); pl.kindStride[k] > 0 {
			pl.kindPass[k] += pl.kindStride[k]
		}
	}
}

// balanced reports whether any family has a configured share, which is what
// engages the two-level mixed pick.
func (pl *Pool) balanced() bool {
	return pl.kindStride[0] > 0 || pl.kindStride[1] > 0
}

// preferredKind names the family the balance ratio asks for next: among
// positive-share kinds, the one whose family clock is furthest behind. Equal
// clocks prefer v4, keeping the choice deterministic. A zero share never wins
// against a positive one; it only serves through pickBalanced's standby
// defer. Callers hold pl.mu.
func (pl *Pool) preferredKind() int {
	hasV4, hasV6 := pl.kindStride[0] > 0, pl.kindStride[1] > 0
	switch {
	case hasV4 && (!hasV6 || pl.kindPass[0] <= pl.kindPass[1]):
		return 0
	case hasV6:
		return 1
	default:
		return 0 // unreachable through balanced()
	}
}

// pickBalanced chooses within the available routes under the family split:
// the preferred family serves if it has a live route here, otherwise the
// other one does — availability beats the ratio — and within a family the
// weighted recency order decides. Callers hold pl.mu, which also owns the
// scratch buckets; serve below advances the winning family's clock. Returns
// nil when avail is empty, which callers exclude beforehand.
func (pl *Pool) pickBalanced(avail []*Proxy) *Proxy {
	pl.scratch[0] = pl.scratch[0][:0]
	pl.scratch[1] = pl.scratch[1][:0]
	for _, p := range avail {
		k := kindIndex(p.Kind)
		pl.scratch[k] = append(pl.scratch[k], p)
	}
	first := pl.preferredKind()
	for _, k := range [2]int{first, 1 - first} {
		if len(pl.scratch[k]) > 0 {
			return minRecencyPass(pl.scratch[k])
		}
	}
	return nil
}

// minRecencyPass returns the candidate with the smallest weighted recency
// pass, first-seen order breaking ties.
func minRecencyPass(candidates []*Proxy) *Proxy {
	chosen := candidates[0]
	chosenPass := chosen.recencyPass()
	for _, e := range candidates[1:] {
		if s := e.recencyPass(); s < chosenPass {
			chosen, chosenPass = e, s
		}
	}
	return chosen
}

// jumpToBack pushes a route behind the whole pool by its own weighted step —
// the weighted generalization of storing a fresh global sequence. Rare by
// design (rotation stale returns): per-pick demotion uses serve so the pass
// differentials that encode the weights survive. The scan stays off the pick
// hot path by living only here.
func (pl *Pool) jumpToBack(p *Proxy) {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	base := p.pass.Load()
	for _, e := range pl.entries {
		if v := e.pass.Load(); v > base {
			base = v
		}
	}
	p.pass.Store(base + p.stride())
}

// PickFor returns the next allowed proxy, excluding entries already tried for
// the current request. Among available entries it picks the smallest weighted
// recency pass (stable order on ties): every serving event advances a route's
// pass by strideUnits/weight, so picks distribute proportionally to the
// configured weights and equal weights give true round-robin. With a
// configured family balance, the pick is two-level on the mixed path: the
// family clock whose stride tracks the configured share chooses the family
// first, then the weighted order picks inside it; a family without a live
// route here defers to the other, so availability beats the ratio. When every
// allowed, non-excluded, non-auth-blocked entry is cooling down it returns the
// allowed route that recovers soonest — weight- and family-independent,
// because soonest recovery is the only criterion that matters there. Routes
// held by an in-progress rotation are skipped on both paths. It returns nil
// when no allowed entry remains. The filter is applied equally to both paths
// so a dedicated v4/v6 listener never crosses into another egress kind.
//
// Every successful pick holds one in-flight count on the returned route; the
// caller releases it via Release when the request or tunnel finishes.
func (pl *Pool) PickFor(exclude map[*Proxy]bool, allow func(*Proxy) bool) *Proxy {
	return pl.pick(exclude, allow, true)
}

// PickForDedicated is the dedicated-listener variant of PickFor. Selection,
// including the all-cooling fallback, is identical, but the pick consults no
// family ratio and advances no family clock, so a dedicated listener's traffic
// never shifts the mixed split's phase. The kind filter (allow) still bounds
// which routes it can serve, which is what keeps a dedicated listener inside
// its own egress family.
func (pl *Pool) PickForDedicated(exclude map[*Proxy]bool, allow func(*Proxy) bool) *Proxy {
	return pl.pick(exclude, allow, false)
}

// pick is the shared selection core. mixed=false is the dedicated path: pure
// weighted recency within the allowed set, no family ratio, no family-clock
// advance. Both paths hold pl.mu, which also owns the balanced path's scratch
// buckets and the family clocks.
func (pl *Pool) pick(exclude map[*Proxy]bool, allow func(*Proxy) bool, mixed bool) *Proxy {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	nowNano := relNanos(pl.Now())

	// One fused pass serves both outcomes: available routes collect for the
	// pick, and the soonest-recovering cooling route collects for the
	// all-cooling fallback — the second full scan this used to need. The
	// candidate sets are disjoint by construction (a fallback candidate has
	// just failed availableAt), and the fallback ignores cooldown but never
	// auth blocks or in-progress rotations.
	allowed := func(p *Proxy) bool { return allow == nil || allow(p) }
	var avail []*Proxy
	var fallback *Proxy
	var fallbackCooldown int64
	for _, e := range pl.entries {
		if !allowed(e) || exclude[e] {
			continue
		}
		if e.availableAt(nowNano) {
			avail = append(avail, e)
			continue
		}
		if !e.authBlockedNow() && !e.rotatingNow() {
			cu := e.cooldownNano()
			if fallback == nil || cu < fallbackCooldown {
				fallback, fallbackCooldown = e, cu
			}
		}
	}
	if len(avail) == 0 {
		if fallback != nil {
			pl.serve(fallback, mixed)
		}
		return fallback
	}

	chosen := minRecencyPass(avail)
	if mixed && pl.balanced() {
		chosen = pl.pickBalanced(avail)
	}
	pl.serve(chosen, mixed)
	return chosen
}

// CoolingFor reports the route's remaining cooldown on this pool's clock, or 0
// when the route is not cooling. The proxy server logs it at debug when the
// all-cooling fallback hands out a route that has not recovered yet.
func (pl *Pool) CoolingFor(p *Proxy) time.Duration {
	cu := p.cooldownNano()
	if cu == 0 {
		return 0
	}
	nowNano := relNanos(pl.Now())
	if nowNano >= cu {
		return 0
	}
	return time.Duration(cu - nowNano)
}

// Size reports the total number of routes in the pool, health notwithstanding.
func (pl *Pool) Size() int {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	return len(pl.entries)
}

// CountAllowed reports how many routes pass the allow filter — the asking
// listener's kind view — regardless of health. Error diagnostics use it to
// show how much of the pool the listener could ever serve.
func (pl *Pool) CountAllowed(allow func(*Proxy) bool) int {
	pl.mu.Lock()
	defer pl.mu.Unlock()
	n := 0
	for _, e := range pl.entries {
		if allow == nil || allow(e) {
			n++
		}
	}
	return n
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
// expected to recover without a reload that replaces the route. The completed
// request advances the route one extra weighted step, so a route that just
// served lets its peers absorb the next picks — the weighted form of the old
// fresh-sequence bump. The cooldown clear happens under p.mu together with
// the counter reset: cooldownUntil is last-writer-wins, and the two writes
// must land as one unit so a concurrent failure cannot leave a live cooldown
// over a zeroed failure streak (or the reverse).
func (pl *Pool) ReportSuccess(p *Proxy) {
	p.mu.Lock()
	p.consecutiveFailures = 0
	p.lastDialError = ""
	p.successes++
	p.cooldownUntil.Store(0)
	p.mu.Unlock()
	p.pass.Add(p.stride())
}

// ReportFailure records an upstream endpoint TCP dial failure and puts the
// proxy into an exponentially growing cooldown: base doubled per consecutive
// dial failure, capped at max. It returns the applied cooldown. The cooldown
// store lands under p.mu with the streak increment for the same
// last-writer-wins reason as ReportSuccess.
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
	if err != nil {
		p.lastDialError = sanitize.ErrorString(err)
	}
	cd := SaturatingCooldown(base, max, p.consecutiveFailures)
	p.cooldownUntil.Store(relNanos(now.Add(cd)))
	return cd
}

// SaturatingCooldown returns base doubled (failures-1) times, capped at max.
// It never overflows and never returns a negative duration, even when base or
// max bypasses runtime configuration validation. The rotation engine's retry
// backoff shares this spine so the two growth curves cannot drift apart.
func SaturatingCooldown(base, max time.Duration, failures int) time.Duration {
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
	nowNano := relNanos(pl.Now())
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
			Weight:              e.weight.Load(),
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
