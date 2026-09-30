package analyticsstore

import (
	"rotation-proxy-gateway/internal/rotation"
)

// RotationHistory adapts a Recorder to the rotation engine's History interface.
//
// It is the one place the two packages meet. The dependency runs this way on
// purpose: internal/rotation states what it observed through a two-method
// interface and never learns that a database, a batch, or a retry exists, so
// the engine — which runs on timers and provider round-trips — cannot be
// dragged into any of it. This side is the only code that knows both.
//
// A nil *Recorder satisfies History through NewRotationHistory's nil check and
// produces a sink that discards everything, so the engine can be wired with no
// DSN configured and behave exactly as it did before analytics existed.
type RotationHistory struct {
	recorder *Recorder
}

// NewRotationHistory adapts a recorder for the rotation engine. A nil recorder
// yields a sink that discards every observation, which is the disabled state.
func NewRotationHistory(r *Recorder) *RotationHistory {
	return &RotationHistory{recorder: r}
}

// RecordRotationAttempt maps an engine attempt onto the store's row and enqueues
// it. Non-blocking: the engine calls this from a procedure goroutine and a
// rotation must never wait on a database.
//
// The IP canonicalization is deliberately left to the writer rather than done
// here. Doing it once, at the last moment before the value is bound, means there
// is no path by which an uncanonical address reaches a row — and it keeps this
// adapter free of the identity rules, which belong to the writer.
func (h *RotationHistory) RecordRotationAttempt(a rotation.Attempt) {
	if h == nil || h.recorder == nil {
		return
	}
	// The mode travels with the attempt rather than being supplied here, so the
	// engine — which knows what drove it — owns the label and a recorder cannot
	// file a future rotation mode under this one.
	mode := a.Mode
	if mode == "" {
		mode = rotation.ModeManual
	}
	h.recorder.RecordRotationAttempt(RotationAttempt{
		EventID:           EventID(a.EventID),
		Instance:          h.recorder.Instance(),
		Route:             RouteKeyFor(a.RouteHost, a.RouteKind, a.RouteOrigin),
		Mode:              mode,
		RotationEpoch:     a.RotationEpoch,
		StartedAt:         a.StartedAt,
		EndedAt:           a.EndedAt,
		Outcome:           RotationOutcome(a.Outcome),
		FailureKind:       a.FailureKind,
		BaselineIP:        a.BaselineIP,
		ObservedIP:        a.ObservedIP,
		APIAttempts:       a.APIAttempts,
		ProbeAttempts:     a.ProbeAttempts,
		ConfigRevision:    a.ConfigRevision,
		ConsecutiveSameIP: a.ConsecutiveSameIP,
	})
}

// RecordIPObservation maps an engine observation onto the store's row and
// enqueues it. Non-blocking, like every method here.
func (h *RotationHistory) RecordIPObservation(o rotation.IPObservation) {
	if h == nil || h.recorder == nil {
		return
	}
	h.recorder.RecordIPObservation(IPObservation{
		Route:         RouteKeyFor(o.RouteHost, o.RouteKind, o.RouteOrigin),
		IP:            o.IP,
		ObservedAt:    o.At,
		Source:        IPHistorySource(o.Source),
		Revisit:       o.Revisit,
		RotationEpoch: o.RotationEpoch,
		Instance:      h.recorder.Instance(),
	})
}
