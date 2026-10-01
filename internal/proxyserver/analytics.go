package proxyserver

import (
	"time"

	"rotation-proxy-gateway/internal/analyticsstore"
	"rotation-proxy-gateway/internal/pool"
)

// Recorder is where this package hands its terminal request outcomes to durable
// analytics.
//
// It is an interface with two methods so that internal/analyticsstore can
// implement it without internal/proxyserver importing it. The dependency runs
// the same way it runs for the rotation engine — this package states what a
// request did and the store decides where it goes — and for the same reason: this
// package is on the hot path of every proxied request, and it must not acquire a
// dependency on a database, a batch writer, or a driver in order to describe one.
//
// A nil Recorder is the disabled state and the default. Every report goes through
// observeRequest or observeFailure, and both handle nil, so "no DSN configured"
// costs one nil check per terminal request and nothing else — no branch on the
// request path, no goroutine, no connection.
type Recorder interface {
	// RecordRequest reports one request's rolled-up contribution. It MUST NOT
	// block: it runs after the client's request is already answered.
	RecordRequest(s analyticsstore.RequestSample)
	// RecordFailure reports one request's terminal failure. It MUST NOT block,
	// for the same reason.
	RecordFailure(s analyticsstore.FailureSample)
}

// bucketNow truncates an instant to the analytics aggregation window.
//
// It is here, at the one point a timestamp is needed, rather than stored on the
// Server: the recorder owns the window and already truncates whatever BucketStart
// it is handed, so this is belt-and-braces that keeps the value a caller computes
// identical to the one the writer will use. A caller that passes an untruncated
// time is still correct, because Recorder.RecordRequest canonicalizes it again.
func bucketNow(at time.Time) time.Time { return at.Truncate(analyticsstore.DefaultBucketWidth) }

// familyLabel is proxyFamily's durable spelling.
//
// The stored value is the request's own family constraint, not the listener's
// kind view: a client that asks for v6 egress and gets a v6 route over the mixed
// listener is the same observation as one that gets it over the v6 listener, and
// an operator grouping failures by "which constraint did the client send" needs
// them in one bucket. The mixed listener view is already reported per listener
// by /status, and the listener column carries it.
func familyLabel(f proxyFamily) string {
	switch f {
	case familyV4:
		return "v4"
	case familyV6:
		return "v6"
	default:
		return "mixed"
	}
}

// routeKeyOf is the credential-free identity a route is stored under. It reads
// URL.Host, never URL.String and never config.CanonicalRouteID, both of which
// embed the route's SOCKS userinfo.
func routeKeyOf(p *pool.Proxy) analyticsstore.RouteKey {
	if p == nil || p.URL == nil {
		return analyticsstore.RouteKey{}
	}
	return analyticsstore.RouteKeyFor(p.URL.Host, string(p.Kind), string(p.Origin))
}

// UseRecorder attaches durable analytics to this listener.
//
// It is a method rather than a NewRuntime parameter for the same reason the
// rotation engine has UseHistory: analytics is optional and off by default, so
// the common construction path must not have to name it. A nil recorder
// restores the disabled state.
//
// It is safe to call before Serve starts, from a single goroutine, and is not
// safe to call once sessions are in flight — same constraint, same reason: the
// field is written without synchronization, and one is not worth a data race.
func (s *Server) UseRecorder(r Recorder) { s.recorder = r }

// observeRequest reports one request that reached a terminal outcome, with its
// chosen route.
//
// It is called after the client has been answered, never before: a sample about
// a request whose bytes have not been served yet describes something that has not
// happened. Both arguments are hot-path values already in hand at every call
// site — the winning route and the byte counts the relay produced — so neither
// costs a query, a lock, or an allocation to pass.
//
// A nil route means the request never reached one (no_route or retry_exhausted).
// That failure is recorded by observeFailure, which has a kind to file it under;
// this call is skipped rather than given an empty-key row, because a row that
// reads like a route but is not one is worse than no row.
func (s *Server) observeRequest(route *pool.Proxy, listener, family, targetHost string, ok bool, toClient, toUpstream int64, at time.Time) {
	if s == nil || s.recorder == nil {
		return
	}
	sample := analyticsstore.RequestSample{
		Route:           routeKeyOf(route),
		Listener:        listener,
		Family:          family,
		BucketStart:     bucketNow(at),
		Requests:        1,
		ToClientBytes:   toClient,
		ToUpstreamBytes: toUpstream,
	}
	if ok {
		sample.Successes = 1
	} else {
		sample.Failures = 1
	}
	s.recorder.RecordRequest(sample)
}

// observeFailure reports one request's terminal failure, bucketed by error kind
// and target host.
//
// errorKind must be one of this package's own logErrorKind values — the same
// closed vocabulary the logs already use — so a durable row and a log line about
// one request always agree. targetHost must already be host-only, which every
// call site gets from targetLogValue rather than re-deriving; that helper is the
// credential defense for inbound authority syntax, and reimplementing it here
// would be a second, weaker version of the same rule.
//
// A request that failed both rolls a failure_events row and a request_aggregates
// row, deliberately. The tables answer different questions: one is "which routes
// carried traffic, and how much", the other is "what went wrong, where". Joining
// them would make every counter query re-derive the failure taxonomy.
func (s *Server) observeFailure(route *pool.Proxy, listener, family, errorKind, targetHost string, at time.Time) {
	if s == nil || s.recorder == nil {
		return
	}
	s.recorder.RecordFailure(analyticsstore.FailureSample{
		Route:       routeKeyOf(route),
		ErrorKind:   errorKind,
		TargetHost:  targetHost,
		Listener:    listener,
		Family:      family,
		BucketStart: bucketNow(at),
		Failures:    1,
	})
}
