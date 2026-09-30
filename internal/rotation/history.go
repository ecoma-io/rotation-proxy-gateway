package rotation

import (
	"crypto/rand"
	"encoding/base32"
	"strconv"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

// How a recorded egress address came to be known. The two values are the
// table's own closed vocabulary, kept here so this package states the fact
// without depending on where it is stored.
const (
	// SourceBaseline: the boot precheck probe, before any rotation ran.
	SourceBaseline = "baseline"
	// SourceRotation: a verified rotation commit.
	SourceRotation = "rotation"
)

// Fixed failure-kind labels. These are deliberately not error strings: a
// rotate-API failure's message can quote the provider's URL, and a durable
// history row must not be able to carry one. The human-readable detail stays
// in the process log, where internal/sanitize governs it.
const (
	// FailureNone: the attempt reached a verified terminal state.
	FailureNone = "none"
	// FailureAPIUnreachable: the provider's rotate call could not be made.
	FailureAPIUnreachable = "api_unreachable"
	// FailureAPIRejected: the provider answered the rotate call with a
	// non-2xx status.
	FailureAPIRejected = "api_rejected"
	// FailureBaselineUnknown: the baseline probe failed, so the rotation ran
	// without an IP comparison and could only verify a non-colliding address.
	FailureBaselineUnknown = "baseline_unknown"
	// FailureAborted: the attempt unwound because the engine stopped or a
	// reload removed the route. Not a provider failure.
	FailureAborted = "aborted"
)

// newAttemptID mints one rotation attempt's stable identity from crypto/rand,
// the only entropy source this repository uses (the semgrep security gate
// rejects every math/rand variant, v2 included).
//
// It is minted once per procedure and reused by whichever terminal path ends
// that procedure, which is what makes recording the attempt twice — something
// two overlapping abort paths can otherwise do — a no-op at the store's primary
// key instead of a duplicate history row. 16 random bytes in unpadded base32 is
// 26 characters, log-safe and URL-safe by construction.
func newAttemptID() string {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// crypto/rand does not fail on any supported platform, but a degraded id
		// must still be unique within the process or a retry would not dedupe.
		return "rot-degraded-" + strconv.FormatUint(degradedAttemptIDs.Add(1), 10)
	}
	return "rot-" + base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw[:])
}

// degradedAttemptIDs backs the fallback above, so a process with an unavailable
// CSPRNG still produces distinct ids and keeps its retries idempotent.
var degradedAttemptIDs atomic.Uint64

// routeFields is the credential-free identity of a route as analytics sees it.
//
// It is built from URL.Host, never from config.CanonicalRouteID: that function
// embeds the route's SOCKS userinfo ("socks5://user:pass@host:port"), which is
// right for an in-memory identity key and wrong for anything durable — a
// history row outlives the configuration revision that made the credential
// secret, and an operator reading history should never be handed a password.
// Host + kind + origin is exactly what the logs and /status already report.
func routeFields(p *pool.Proxy) (host, kind, origin string) {
	if p == nil || p.URL == nil {
		return "", "", ""
	}
	return p.URL.Host, string(p.Kind), string(p.Origin)
}

// configRevisionOf reports the durable configuration revision the attempt's
// generation was materialized from, or 0 when this instance runs on its local
// seed file. Read from the generation the procedure already holds, so recording
// costs no store lookup.
func configRevisionOf(gen *pool.Generation) int64 {
	if gen == nil {
		return 0
	}
	return gen.ConfigRevision
}

// recordRotated records a completed, verified rotation: the egress-IP
// observation and the attempt that produced it.
//
// Both are enqueued here and neither blocks — this runs on a procedure
// goroutine, and a rotation must never wait on a database. The event id is the
// attempt's, so a retried write of the same attempt is a no-op at the store.
func (e *Engine) recordRotated(p *pool.Proxy, gen *pool.Generation, attemptID, ip string, at time.Time, revisit bool, epoch uint64, started time.Time, baseline string, baselineKnown bool, apiAttempts, probeAttempts int) {
	if e.history == nil {
		return
	}
	host, kind, origin := routeFields(p)
	e.history.RecordIPObservation(IPObservation{
		RouteHost:     host,
		RouteKind:     kind,
		RouteOrigin:   origin,
		IP:            ip,
		Source:        SourceRotation,
		At:            at,
		Revisit:       revisit,
		RotationEpoch: epoch,
	})
	e.history.RecordRotationAttempt(Attempt{
		EventID:           attemptID,
		Mode:              ModeManual,
		RouteHost:         host,
		RouteKind:         kind,
		RouteOrigin:       origin,
		RotationEpoch:     epoch,
		StartedAt:         started,
		EndedAt:           at,
		Outcome:           OutcomeRotated,
		FailureKind:       FailureNone,
		BaselineIP:        knownIP(baseline, baselineKnown),
		ObservedIP:        ip,
		APIAttempts:       apiAttempts,
		ProbeAttempts:     probeAttempts,
		ConfigRevision:    configRevisionOf(gen),
		ConsecutiveSameIP: 0, // a successful rotation clears the run
		Revisit:           revisit,
	})
}

// recordUnchanged records an attempt that ran to a terminal state without
// changing the route's egress IP — the outcome the engine backs off and retries.
//
// The observed address is the route's own last verified one, read at the moment
// the decision was made. A reader could not reconstruct it later: the route may
// have rotated since, and "what IP was it stuck on" is exactly the question this
// row exists to answer.
func (e *Engine) recordUnchanged(p *pool.Proxy, gen *pool.Generation, attemptID string, epoch uint64, started time.Time, baseline string, baselineKnown bool, consecutive int, apiFailed bool, apiAttempts, probeAttempts int) {
	if e.history == nil {
		return
	}
	host, kind, origin := routeFields(p)
	e.history.RecordRotationAttempt(Attempt{
		EventID:           attemptID,
		Mode:              ModeManual,
		RouteHost:         host,
		RouteKind:         kind,
		RouteOrigin:       origin,
		RotationEpoch:     epoch,
		StartedAt:         started,
		EndedAt:           e.Now(),
		Outcome:           terminalOutcome(apiFailed),
		FailureKind:       terminalFailureKind(baselineKnown, apiFailed),
		BaselineIP:        knownIP(baseline, baselineKnown),
		ObservedIP:        p.LastIP(),
		APIAttempts:       apiAttempts,
		ProbeAttempts:     probeAttempts,
		ConfigRevision:    configRevisionOf(gen),
		ConsecutiveSameIP: consecutive,
	})
}

// recordAbort records an attempt that unwound without reaching a terminal
// rotation state: the engine is shutting down, or a reload removed or replaced
// the route.
//
// It is deliberately its own outcome rather than a rotation failure. An operator
// asking "did this route's IP fail to rotate" must not have to read a restart or
// a config edit into the answer, and a failure count that absorbed every restart
// would stop meaning anything.
func (e *Engine) recordAbort(p *pool.Proxy, gen *pool.Generation, attemptID string, epoch uint64, started time.Time) {
	if e.history == nil {
		return
	}
	host, kind, origin := routeFields(p)
	e.history.RecordRotationAttempt(Attempt{
		EventID:       attemptID,
		Mode:          ModeManual,
		RouteHost:     host,
		RouteKind:     kind,
		RouteOrigin:   origin,
		RotationEpoch: epoch,
		StartedAt:     started,
		EndedAt:       e.Now(),
		Outcome:       OutcomeAborted,
		FailureKind:   FailureAborted,
		// The address the attempt had learned up to the unwind, so a reader can
		// still see which egress IP the route was on when it stopped.
		ObservedIP: p.LastIP(),
		// The baseline is deliberately absent: an unwind says nothing about
		// whether the pre-rotation probe succeeded.
		ConfigRevision: configRevisionOf(gen),
	})
}

// recordBaselineObservation records an egress IP learned by the boot precheck,
// before any rotation ran. It joins the same history a rotation commit writes
// to, so "which IPs has this route ever served from" covers its starting
// address too — and a later rotation that returns to it is visibly a revisit.
func (e *Engine) recordBaselineObservation(p *pool.Proxy, ip string, at time.Time) {
	if e.history == nil || ip == "" {
		return
	}
	host, kind, origin := routeFields(p)
	e.history.RecordIPObservation(IPObservation{
		RouteHost:     host,
		RouteKind:     kind,
		RouteOrigin:   origin,
		IP:            ip,
		Source:        SourceBaseline,
		At:            at,
		Revisit:       false,
		RotationEpoch: p.RotationEpoch(),
	})
}

// knownIP returns the baseline only when the probe actually verified it. An
// unverified baseline is not an address the attempt learned — it is the absence
// of one — and storing it as though it were known would make a later comparison
// against it meaningless.
func knownIP(baseline string, verified bool) string {
	if !verified {
		return ""
	}
	return baseline
}

// terminalOutcome classifies an attempt that reached a terminal state without
// rotating. A failed provider call is its own outcome because it is a different
// operational problem from a provider that answered and kept the same address,
// and an operator debugging a stuck route needs to tell them apart.
func terminalOutcome(apiFailed bool) RotationOutcome {
	if apiFailed {
		return OutcomeAPIFailed
	}
	return OutcomeUnchangedIP
}

// terminalFailureKind labels why a non-rotating attempt ended the way it did,
// in that order of specificity: a rejected call is a more precise fact than a
// mere "the call failed", and a missing baseline is a fact about the attempt
// rather than about the provider at all.
func terminalFailureKind(baselineKnown, apiFailed bool) string {
	switch {
	case apiFailed:
		return FailureAPIRejected
	case !baselineKnown:
		return FailureBaselineUnknown
	default:
		return FailureNone
	}
}

// rotationMode is the mode label every recorded attempt carries. The rotation
// engine drives manual routes only; the column exists so a future mode does not
// have to reinterpret existing rows.
const ModeManual = string(config.RouteOriginManual)
