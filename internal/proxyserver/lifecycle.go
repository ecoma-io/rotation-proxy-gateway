package proxyserver

import (
	"io"
	"net/http"
	"sync/atomic"
	"time"
)

// The serving lifecycle, and the one endpoint that reports it.
//
// A process that is going away has two different things to say, and they must
// not be the same thing:
//
//   - liveness — "this process is alive". That is GET /healthz, and it stays
//     true for as long as the admin listener exists, drain window included. The
//     container health check reads it, and a liveness probe that failed during a
//     drain would tell Docker to kill a process that is stopping correctly —
//     mid-drain, with live tunnels on it.
//   - readiness — "send me traffic". That is GET /readyz, and it goes false
//     BEFORE any listener socket closes. This is the ordering a draining
//     instance depends on: a load balancer that still believes the instance is
//     ready must be told otherwise while the socket it is routing to is still
//     answering, and only then may that socket go away.
//
// Readiness is a statement about this process alone. It is deliberately not
// derived from the config snapshot, from a route's cooldown, from the warm
// pool, or from an upstream provider: a provider outage is not a reason to stop
// routing to an instance that can still serve every target it has, and a route
// cooling must not empty a load balancer's whole pool. The machine below reads
// nothing but its own state, and the type gives it nothing else to read.

// State is one point in the lifecycle. The values are ordered: a process only
// ever moves forward through them, and a transition that would move it backward
// is refused rather than obeyed.
type State int32

const (
	// StateStarting is the zero value: the process has not yet reached the
	// point where it can serve. Nothing in the boot sequence advertises
	// readiness before the proxy listeners exist, so this state is not
	// observable over HTTP in a healthy process — it exists so that "ready" is
	// never the zero value of a field, where a missed transition would silently
	// mean healthy.
	StateStarting State = iota
	StateReady
	StateDraining
	StateStopped
)

// String is the token /readyz reports for the state, and the only vocabulary
// an operator sees for it. It carries no detail by construction: there is no
// route, provider, or config fact in it to leak.
func (s State) String() string {
	switch s {
	case StateStarting:
		return "starting"
	case StateReady:
		return "ready"
	case StateDraining:
		return "draining"
	case StateStopped:
		return "stopped"
	}
	return "unknown"
}

// lifecycle is the readiness state machine.
//
// It is a bare monotonic integer rather than a bool, and that is the whole
// difference from a service with a single terminal point. This process has
// several: the rotation engine cancel, the warm-pool stop, each proxy listener
// drain, and the admin drain. One atomic integer is what lets a reader tell
// "not ready yet" from "draining" from "stopped" — both of the latter answer
// `/readyz` 503 — and what stops a late or duplicated transition from
// re-advertising a process that already told its load balancer to stop.
//
// It is safe for concurrent use by construction — no lock, no callback, nothing
// that can block — because the readers are probe goroutines that must never
// queue behind the data path, and the writer is the shutdown path that must
// never wait for them.
type Lifecycle struct {
	state atomic.Int32
}

func NewLifecycle() *Lifecycle { return &Lifecycle{} }

// load reports the current state.
func (l *Lifecycle) load() State { return State(l.state.Load()) }

// ready reports whether the process is currently advertising readiness. It is
// exactly the /readyz success condition.
func (l *Lifecycle) Ready() bool { return l.load() == StateReady }

// advance moves the state forward, and only forward. It reports whether the
// move happened: a call that would take the process backward — ready after
// draining, say — is refused, so no late or duplicated call can re-advertise an
// instance that has already told its load balancer to stop. The
// compare-and-swap is what makes that guarantee hold against a concurrent
// writer rather than merely in the common case.
func (l *Lifecycle) advance(from, to State) bool {
	return l.state.CompareAndSwap(int32(from), int32(to))
}

// markReady advertises readiness once the listeners are up. A repeated call is
// a no-op that keeps the forward-only guarantee above intact.
func (l *Lifecycle) MarkReady() bool {
	return l.advance(StateStarting, StateReady) || l.advance(StateReady, StateReady)
}

// beginDraining stops advertising readiness from the instant it is called,
// whether or not the process ever advertised it: a process stopped during
// startup has just as much reason to answer "not ready" as one stopped while
// serving. A repeated call is the same state, not a backward move.
func (l *Lifecycle) BeginDraining() bool {
	return l.advance(StateStarting, StateDraining) || l.advance(StateReady, StateDraining) ||
		l.advance(StateDraining, StateDraining)
}

// markStopped is the terminal transition, taken once nothing can accept a
// connection any more. Like the others it is idempotent: the several paths out
// of the serve loop may each reach it.
func (l *Lifecycle) MarkStopped() bool {
	return l.advance(StateDraining, StateStopped) || l.advance(StateReady, StateStopped) ||
		l.advance(StateStarting, StateStopped) || l.advance(StateStopped, StateStopped)
}

// ReadyPath is the readiness endpoint. It is matched exactly: "/readyz/" is
// not this endpoint.
//
// It is exported so the binary healthcheck probes the same path the handler is
// registered on, rather than a second literal that can drift from it.
const ReadyPath = "/readyz"

// ReadyBody is the success body, matching GET /healthz's shape so an operator
// reads one convention instead of two. It is the literal the binary
// healthcheck's body check compares against, for the same reason.
const ReadyBody = "ok\n"

// serveReadyz answers the readiness probe: 200 "ok\n" while the process is
// advertising, 503 with the state token otherwise. A probe reads only the
// status code; the body exists so a human running curl learns why.
//
// A non-GET is 405 with an Allow header rather than a JSON envelope: /readyz is
// an admin-plane path alongside /status, not part of any wire contract this
// process speaks to a client.
//
// The response is explicitly uncacheable. A cached 200 replayed after the
// process began draining would route traffic into a socket that is about to
// close — the exact failure this endpoint exists to prevent.
func (l *Lifecycle) serveReadyz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		w.WriteHeader(http.StatusMethodNotAllowed)
		_, _ = io.WriteString(w, "method not allowed\n")
		return
	}
	st := l.load()
	if st == StateReady {
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, ReadyBody)
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = io.WriteString(w, st.String()+"\n")
}

// ReadinessPropagation is the head start the process gives whatever routes to
// it, between "this instance is no longer ready" and "this instance stops
// accepting connections". Without it the two happen at the same instant, and
// every health check that had already been scheduled, every in-flight probe,
// and every load-balancer view that is one interval out of date lands on a
// closed port — a connection refused where a 503 or a served request was
// available.
//
// Five seconds is derived from the probe cadence the deployment is told to
// ship: a 2s interval plus a 1s timeout means the worst-case notification is 3s,
// plus slack for scheduling. It is drawn from the shutdown grace rather than
// added to it (see Propagation), so the total time from signal to exit is
// unchanged and a container's stop_grace_period needs no adjustment.
//
// It is exported so a test can name the window it is sampling rather than
// restate the number and drift from it.
const ReadinessPropagation = 5 * time.Second

// propagation is the readiness head start this process will take, capped at half
// the drain budget so the drain keeps the majority of it.
//
// The cap is what makes the window safe to spend on every deployment: a process
// configured with a short grace (a test, or an operator who wants a fast stop)
// takes a short head start instead of one that leaves nothing for in-flight
// work. A budget that cannot carry a head start at all — zero, or a negative no
// configuration produces — takes none, which is the previous behavior exactly.
func Propagation(grace time.Duration) time.Duration {
	half := grace / 2
	if half <= 0 {
		return 0
	}
	if ReadinessPropagation > half {
		return half
	}
	return ReadinessPropagation
}
