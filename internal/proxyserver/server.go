// Package proxyserver implements the inbound HTTP forward proxy. Client
// connections send HTTP/1.1 CONNECT or absolute-form HTTP requests; every
// request reaches its target through a SOCKS5H route from the shared
// health-aware pool.
package proxyserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/sanitize"
	"rotation-proxy-gateway/internal/socksdial"
	"rotation-proxy-gateway/internal/warmpool"

	"github.com/rs/zerolog"
)

// inboundHandshakeTimeout bounds the client-side greeting, request, and reply
// exchange, mirroring the old HTTP ReadHeaderTimeout. It is cleared once the
// success reply is written so established tunnels have no timeouts.
const inboundHandshakeTimeout = 30 * time.Second

// inboundBufSize keeps enough room for ordinary HTTP request headers while the
// framing path still has a hard upper bound for adversarial inputs. It is shared
// by the HTTP parser and CONNECT's read-ahead preservation wrapper.
const inboundBufSize = 4 << 10

// credentialDigestSize is the fixed length every credential field is reduced
// to before any comparison: constant-time comparison cannot depend on field
// lengths, and a digest of one fixed length has none.
const credentialDigestSize = sha256.Size

// credentialDigestKey is the process-wide random key credential digests are
// keyed with. It deliberately lives outside the account struct: together the
// account digests and the key are only as secret as the process, while a
// leaked digest without the key says nothing brute-forceable about the
// credential bytes behind it. Generated once, at the first account arming —
// process startup — where a failed crypto/rand read means the OS CSPRNG is
// broken and nothing this process could serve is safe, so refusing to run is
// the correct outcome.
var credentialDigestKey = sync.OnceValue(func() [credentialDigestSize]byte {
	var key [credentialDigestSize]byte
	if _, err := rand.Read(key[:]); err != nil {
		panic(fmt.Sprintf("proxyserver: read credential digest key: %v", err))
	}
	return key
})

// credentialDigest reduces one credential field to the fixed-length value the
// inbound comparison runs on: HMAC-SHA256 under the process-wide random key.
// Digesting both sides keeps field lengths out of the comparison —
// subtle.ConstantTimeCompare returns immediately on a length mismatch, so the
// raw variable-length fields would expose the configured lengths.
func credentialDigest(field []byte) [credentialDigestSize]byte {
	key := credentialDigestKey()
	mac := hmac.New(sha256.New, key[:])
	mac.Write(field) //nolint:errcheck // hash.Hash.Write documents no error
	var digest [credentialDigestSize]byte
	mac.Sum(digest[:0])
	return digest
}

// inboundAccount is the HTTP Basic credential pair a server demands from every
// client, held as digests of the configured fields: digesting the configured
// pair once keeps the per-request cost at digesting the presented fields, and
// the fixed digest length keeps the configured field lengths out of the
// comparison. A nil pointer leaves the forward proxy unauthenticated.
type inboundAccount struct {
	usernameSum [credentialDigestSize]byte
	passwordSum [credentialDigestSize]byte
}

// newInboundAccount reduces one configured credential pair to its digest form.
func newInboundAccount(username, password []byte) *inboundAccount {
	return &inboundAccount{
		usernameSum: credentialDigest(username),
		passwordSum: credentialDigest(password),
	}
}

// credentialsMatch compares presented HTTP Basic credentials against the
// configured account without leaking which field mismatched or either side's
// field lengths. Every field is reduced to a fixed-length digest first, and
// both comparisons always execute so a wrong username never skips password
// comparison (and vice versa).
func credentialsMatch(account *inboundAccount, username, password []byte) bool {
	usernameSum := credentialDigest(username)
	passwordSum := credentialDigest(password)
	userOK := subtle.ConstantTimeCompare(usernameSum[:], account.usernameSum[:])
	passOK := subtle.ConstantTimeCompare(passwordSum[:], account.passwordSum[:])
	return userOK&passOK == 1
}

// WarmBorrower is the serving path's window into the warm pool. Borrow is a
// non-blocking pop: nil means dial cold, exactly as before the pool existed.
// DiscardRoute drops the route's parked siblings after a borrowed connection
// failed at the transport level — they likely died with it.
type WarmBorrower interface {
	Borrow(*pool.Proxy) *socksdial.HalfConn
	DiscardRoute(*pool.Proxy)
}

// Server is the inbound HTTP forward-proxy listener handler.
type Server struct {
	store    *pool.Store
	log      zerolog.Logger
	version  string
	listener string
	allow    func(*pool.Proxy) bool
	dial     func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error)
	// warm lends parked half connections. Nil (and the zero value of every
	// test Server) keeps the cold dial path. It is set once, before Serve
	// starts, and read-only afterwards.
	warm WarmBorrower
	// account, when non-nil, requires HTTP Basic proxy authentication on every
	// request. Set once, before Serve starts, and read-only afterwards; nil
	// keeps the forward proxy unauthenticated.
	account *inboundAccount

	cmu   sync.Mutex
	conns map[net.Conn]struct{}
	// shuttingDown refuses new sessions once shutdown began closing
	// listeners. Guarded by cmu together with the connection map so admission
	// and the drain wait cannot interleave.
	shuttingDown bool
	// live counts tracked sessions so Shutdown can wait for the drain without
	// polling the connection map.
	live sync.WaitGroup
	// baseCtx is the context every upstream dial runs under. Shutdown
	// cancels it when the grace budget expires, unblocking dials still in
	// their TCP connect phase; a handshake-phase dial blocked reading the
	// upstream greeting is not reachable from this context — only the
	// dial's own socket deadline ends it, which is why Shutdown bounds the
	// full wait (and force-closes client conns) against the shared grace
	// budget instead of relying on the dial to unwind.
	baseCtx    context.Context
	cancelBase context.CancelFunc

	startTime time.Time
	requests  atomic.Uint64
	failovers atomic.Uint64
}

// ListenerStatus is the safe operational view for one inbound proxy listener.
type ListenerStatus struct {
	Requests  uint64 `json:"requests"`
	Failovers uint64 `json:"failovers"`
}

func (s *Server) ListenerStatus() ListenerStatus {
	return ListenerStatus{
		Requests:  s.requests.Load(),
		Failovers: s.failovers.Load(),
	}
}

// NewRuntime builds a listener-specific proxy Server whose new sessions use
// atomic runtime generations. Every session loads its generation once so route
// picks, health reports, and session settings stay within one snapshot even
// when a reload publishes a new generation in parallel.
func NewRuntime(store *pool.Store, log zerolog.Logger, version, listener string, allowed ...config.EgressKind) *Server {
	allow := func(p *pool.Proxy) bool {
		for _, kind := range allowed {
			if p.Kind == kind {
				return true
			}
		}
		return len(allowed) == 0
	}
	baseCtx, cancelBase := context.WithCancel(context.Background())
	return &Server{
		store:      store,
		log:        log.With().Str("listener", listener).Logger(),
		version:    version,
		listener:   listener,
		allow:      allow,
		dial:       dialVia,
		conns:      map[net.Conn]struct{}{},
		baseCtx:    baseCtx,
		cancelBase: cancelBase,
		startTime:  time.Now(),
	}
}

// Serve accepts client connections until ln is closed. It returns nil after a
// deliberate listener close (shutdown) and the accept error otherwise.
func (s *Server) Serve(ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			s.log.Warn().Str("error", sanitize.ErrorString(err)).Msg("listener accept failed; stopping")
			return err
		}
		if !s.beginSession(conn) {
			conn.Close() //nolint:errcheck // refused session during shutdown
			continue
		}
		go func() {
			defer s.live.Done()
			s.serveConn(conn)
		}()
	}
}

// beginSession admits one accepted connection: registration for force-close
// and the drain count land in one critical section, so a session can never be
// admitted uncounted between Shutdown's drain wait and its connection sweep.
// It refuses connections that arrive after shutdown began; the caller closes
// them and keeps accepting until the listener itself closes.
func (s *Server) beginSession(c net.Conn) bool {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	if s.shuttingDown {
		return false
	}
	s.conns[c] = struct{}{}
	s.live.Add(1)
	return true
}

// forceCloseWait bounds the extra time Shutdown spends waiting for sessions
// to unwind after their connections were force-closed: sessions finish on
// closed sockets promptly, so this only bites a wedged handler. The whole
// process shutdown stays inside grace + a bounded tail (see shutdownAll in
// cmd/rotation-proxy-gateway), which the surrounding orchestrator's kill
// timer must exceed.
const forceCloseWait = time.Second

// Shutdown waits for active sessions to finish. When ctx expires before the
// drain completes, pending upstream dials are canceled, tracked client
// connections are force-closed, the remaining sessions finish on their closed
// connections within forceCloseWait, and ctx.Err() is returned. Closing the
// listener itself is the caller's job: it stops new accepts at a precisely
// chosen point in the shutdown sequence.
func (s *Server) Shutdown(ctx context.Context) error {
	s.cmu.Lock()
	s.shuttingDown = true
	s.cmu.Unlock()
	defer s.cancelBase()

	done := make(chan struct{})
	go func() {
		s.live.Wait()
		close(done)
	}()
	select {
	case <-done:
		s.log.Debug().Msg("listener drained; all sessions finished")
		return nil
	case <-ctx.Done():
		// Cancel upstream dials first so sessions blocked in their TCP
		// connect unwind by themselves, then force-close the client sockets
		// to break established tunnels and handshake waits.
		s.cancelBase()
		if n := s.CloseConns(); n > 0 {
			s.log.Warn().Int("connections", n).Msg("grace budget expired; force-closing client connections")
		} else {
			s.log.Debug().Msg("grace budget expired with no tracked client connections")
		}
		select {
		case <-done:
			s.log.Debug().Msg("sessions finished after force-close")
		case <-time.After(forceCloseWait):
			s.log.Warn().Msg("sessions still running after the force-close tail")
		}
		return ctx.Err()
	}
}

// generation loads the current immutable runtime snapshot.
func (s *Server) generation() *pool.Generation {
	return s.store.Load()
}

// MixedListener is the listener name of the mixed v4/v6 egress view.
const MixedListener = "mixed"

// UseWarmPool arms the warm-connection borrow path. It must be called before
// Serve; afterwards the field is read-only.
func (s *Server) UseWarmPool(w WarmBorrower) {
	s.warm = w
}

// UseInboundAccount arms mandatory HTTP Basic proxy authentication for every
// request on this listener. It must be called before Serve; afterwards the
// field is read-only. The configured pair is reduced to digests immediately,
// so the caller's slices are not retained.
func (s *Server) UseInboundAccount(username, password []byte) {
	s.account = newInboundAccount(username, password)
}

// dialWarmFirst establishes the upstream tunnel for one attempt: a parked
// half connection when the warm pool has one for this route, the cold dial
// otherwise. A borrowed connection that the endpoint itself refuses
// (non-zero CONNECT reply) surfaces as-is so the caller's classification
// gives it the pair-scoped treatment — identical to the cold path. A
// borrowed connection that fails at the transport level says nothing about
// the route today: its siblings are discarded, no route health is reported
// for the attempt, and the cold dial decides the outcome.
func (s *Server) dialWarmFirst(ctx context.Context, p *pool.Proxy, target socksdial.Target, timeout time.Duration) (net.Conn, error) {
	if s.warm != nil {
		if hc := s.warm.Borrow(p); hc != nil {
			conn, err := hc.CompleteConnect(target, timeout)
			if err == nil {
				s.log.Debug().Str("upstream", upstreamLogValue(p)).Msg("warm connection completed")
				return conn, nil
			}
			if isConnectTargetError(err) {
				return nil, err
			}
			s.log.Debug().Str("upstream", upstreamLogValue(p)).Msg("warm connection died; dialing cold")
			s.warm.DiscardRoute(p)
		}
	}
	return s.dial(ctx, p.URL, target, timeout)
}

type sessionSettings struct {
	maxRetries  int
	dialTimeout time.Duration
}

// generationSettings derives session-scoped values from one loaded generation
// so a reload cannot change retry or timeout policy part-way through a session.
func generationSettings(gen *pool.Generation) sessionSettings {
	cfg := gen.Config
	return sessionSettings{
		maxRetries:  cfg.MaxRetries,
		dialTimeout: cfg.DialTimeout,
	}
}

// settings reports the current generation's session values. Tests use it to
// assert publication; serving paths load the generation once and derive the
// settings from that same snapshot.
func (s *Server) settings() sessionSettings {
	return generationSettings(s.generation())
}

func (s *Server) untrackConn(c net.Conn) {
	s.cmu.Lock()
	delete(s.conns, c)
	s.cmu.Unlock()
}

// CloseConns closes every tracked client connection, including established
// tunnels and sessions still inside their handshake, and returns how many
// were closed. Shutdown calls it when the shared grace budget expires. It
// deliberately does not cancel the base context — callers that need that
// pairing use Shutdown, and tests may call this directly without tearing
// down the server's dial context.
func (s *Server) CloseConns() int {
	s.cmu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.cmu.Unlock()
	for _, c := range conns {
		c.Close() //nolint:errcheck // best-effort force-close
	}
	return len(conns)
}

// AdminMux serves the health and status endpoints for one proxy listener, for
// tests and for any single-listener embedding. A process serves one AdminMux
// for all of its views; the process owns the lifecycle that mux reports.
func (s *Server) AdminMux() *http.ServeMux {
	return AdminMux(s.version, s.startTime, s.store, map[string]*Server{s.listener: s}, nil, nil, nil, NewLifecycle())
}

// AdminMux serves aggregate health/status for all proxy listener views sharing
// a runtime generation store. Existing status fields remain global totals;
// listeners adds safe per-listener counters — requests counts valid CONNECT
// commands (protocol rejects never advance it) and failovers counts in-band
// route fallbacks, distinct from rotations. The pool snapshot comes from the
// current generation so /status changes atomically with serving behavior.
// rotations and ipRevisits, when non-nil, report the rotation engine's
// process-lifetime aggregates: completed rotations, and the subset of them
// that committed an address the same route had already verified. warm, when
// non-nil, reports the warm-pool view (bounds, gauges, lifecycle counters); it
// is omitted entirely when no warm pool backs the process. lc is the process
// lifecycle /readyz reports; a nil lc is answered as ready, which is correct
// for a single-listener embedding that owns no drain sequence.
func AdminMux(version string, started time.Time, store *pool.Store, listeners map[string]*Server, rotations func() uint64, ipRevisits func() uint64, warm func() warmpool.Status, lc *Lifecycle) *http.ServeMux {
	mux := http.NewServeMux()
	// Liveness, unconditionally. It never reports the drain: see lifecycle.go
	// for why a liveness probe that fails while a process is stopping
	// correctly is worse than no probe at all.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
	// Readiness, the mirror image: 503 from the instant the drain starts, while
	// every listener is still accepting.
	ready := lc
	if ready == nil {
		ready = &Lifecycle{}
		ready.MarkReady()
	}
	mux.HandleFunc(ReadyPath, ready.serveReadyz)
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		perListener := make(map[string]ListenerStatus, len(listeners))
		var requests, failovers uint64
		for name, listener := range listeners {
			status := listener.ListenerStatus()
			perListener[name] = status
			requests += status.Requests
			failovers += status.Failovers
		}
		gen := store.Load()
		status := map[string]any{
			"version":   version,
			"uptime":    time.Since(started).Truncate(time.Second).String(),
			"requests":  requests,
			"failovers": failovers,
			"listeners": perListener,
			"pool":      gen.Pool.Snapshot(),
		}
		if rotations != nil {
			status["rotations"] = rotations()
		}
		if ipRevisits != nil {
			status["ipRevisits"] = ipRevisits()
		}
		if warm != nil {
			status["warmPool"] = warm()
		}
		_ = json.NewEncoder(w).Encode(status)
	})
	return mux
}
