// Package proxyserver implements the inbound SOCKS5 proxy. Client connections
// speak RFC 1928 CONNECT, with no authentication unless a bootstrap account is
// configured (RFC 1929); every accepted tunnel is relayed through SOCKS5
// routes from the shared health-aware pool.
package proxyserver

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
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

// SOCKS5 wire constants (RFC 1928).
const (
	socksVersion             = 0x05
	socksAuthNone            = 0x00
	socksAuthUserPass        = 0x02
	socksAuthUnaccepted      = 0xff
	socksCmdConnect          = 0x01
	socksCmdBind             = 0x02
	socksCmdUDPAssociate     = 0x03
	socksAtypIPv4            = 0x01
	socksAtypDomain          = 0x03
	socksAtypIPv6            = 0x04
	socksReplySuccess        = 0x00
	socksReplyGeneral        = 0x01
	socksReplyCmdUnsupported = 0x07
)

// RFC 1929 username/password subnegotiation constants: one version byte
// (0x01) framing ULEN/UNAME/PLEN/PASSWD and a one-byte status in the reply.
const (
	authUPVersion = 0x01
	authUPSuccess = 0x00
	authUPFailure = 0xff
)

// errInboundAuth marks a completed RFC 1929 exchange whose credentials did
// not match the configured account: the failure reply was already written,
// so the caller only logs and closes. It never carries credential bytes.
var errInboundAuth = errors.New("inbound authentication rejected")

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

// inboundAccount is the RFC 1929 credential pair a server demands from every
// client, held as digests of the configured fields: digesting the configured
// pair once keeps the per-session cost at digesting the presented fields, and
// the fixed digest length keeps the configured field lengths out of the
// comparison. A nil pointer keeps the historical NO AUTHENTICATION handshake.
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

// WarmBorrower is the serving path's window into the warm pool. Borrow is a
// non-blocking pop: nil means dial cold, exactly as before the pool existed.
// DiscardRoute drops the route's parked siblings after a borrowed connection
// failed at the transport level — they likely died with it.
type WarmBorrower interface {
	Borrow(*pool.Proxy) *socksdial.HalfConn
	DiscardRoute(*pool.Proxy)
}

// Server is the inbound SOCKS5 listener handler.
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
	// account, when non-nil, switches the inbound handshake to mandatory
	// RFC 1929 username/password authentication. Set once, before Serve
	// starts, and read-only afterwards; nil keeps no-authentication.
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
	// their TCP connect phase; handshake-phase dials unblock through
	// CloseConns closing the client side or their own dial deadline.
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

// UseInboundAccount arms mandatory RFC 1929 username/password authentication
// for every session on this listener. It must be called before Serve;
// afterwards the field is read-only. The configured pair is reduced to
// digests immediately, so the caller's slices are not retained.
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

// serveConn runs one client session: SOCKS5 greeting, one CONNECT request, and
// the established-tunnel relay. Protocol-level rejects log under
// error_kind=bad_request and never advance the request counter or touch the
// pool; only a valid CONNECT does both.
func (s *Server) serveConn(conn net.Conn) {
	defer s.untrackConn(conn)
	defer conn.Close() //nolint:errcheck // relay shutdown handles write failure

	// The deadline covers greeting, request, and reply framing — the whole
	// retry chain included; the success path re-arms it for the reply and
	// clears it before relaying.
	deadline := time.Now().Add(inboundHandshakeTimeout)
	conn.SetDeadline(deadline) //nolint:errcheck // best-effort hardening

	// One pooled reader frames the whole inbound exchange: the greeting and
	// CONNECT frame then cost one or two socket reads instead of one per
	// field, and bytes the client pipelined behind the frame stay available
	// for the relay instead of being dropped.
	br := inboundBufPool.Get().(*bufio.Reader)
	br.Reset(conn)
	defer func() {
		br.Reset(nil)
		inboundBufPool.Put(br)
	}()

	req, err := readSocksRequest(br, conn, s.account)
	if err != nil {
		// A rejected credential is a terminal failure an operator who armed
		// authentication needs to see; every other framing reject stays flow
		// detail at debug. Neither line carries credential bytes.
		if errors.Is(err, errInboundAuth) {
			s.log.Warn().Str("error_kind", "auth_rejected").Msg("socks authentication rejected")
			return
		}
		s.log.Debug().Str("error_kind", "bad_request").Str("error", socksRejectLogValue(err)).Msg("socks request rejected")
		return
	}
	if req.cmd != socksCmdConnect {
		writeSocksReply(conn, socksReplyCmdUnsupported) //nolint:errcheck // the connection closes either way
		s.log.Debug().Str("error_kind", "bad_request").Msg("socks command not supported")
		return
	}

	requestID := s.requests.Add(1)
	log := s.log.With().Int64("request_id", int64(requestID)).Logger()
	// A client that pipelined payload behind the CONNECT frame must have
	// those bytes relayed, not dropped: they ride a prefix wrapper ahead of
	// the socket reads.
	client := conn
	if n := br.Buffered(); n > 0 {
		prefix := make([]byte, n)
		if _, err := io.ReadFull(br, prefix); err != nil {
			// The framing socket just failed; there is nothing to serve.
			return
		}
		client = &prefixConn{Conn: conn, prefix: prefix}
	}
	s.serveTunnel(client, req.target, deadline, log)
}

// serveTunnel dials the target through the pool with the retry/exclude loop,
// sends the success reply once, and relays until either side ends the stream.
// It loads one generation for the whole session so route picks and health
// reports stay consistent across reloads. handshakeDeadline is the inbound
// framing window serveConn armed; the retry chain must fit inside it.
func (s *Server) serveTunnel(clientConn net.Conn, target socksdial.Target, handshakeDeadline time.Time, log zerolog.Logger) {
	gen := s.generation()
	settings := generationSettings(gen)
	start := time.Now()
	// host:port is the pool-state and log identity; target.Type is the wire
	// address type the outbound CONNECT carries. Both descend from the
	// inbound frame, retries included.
	targetAddr := target.Addr()
	logTarget := socksTargetLogValue(targetAddr)
	log.Debug().Str("target", logTarget).Msg("tunnel start")

	exclude := map[*pool.Proxy]bool{}
	var upstream net.Conn
	var chosen *pool.Proxy
	var attempts int
	// exhausted distinguishes why the chain ended with no tunnel. true means
	// the retry budget ran out while the pool could still supply routes; the
	// loop breaks on the *next* pick when the cap is already reached, so a
	// final attempt that succeeded or failed in-band is never misread as an
	// untried leftover. false means the last pick itself came back nil — no
	// eligible untried route remained.
	exhausted := false
	for attempt := 0; ; attempt++ {
		// A retry dials again under the inbound handshake window. Once that
		// window is gone — a slow retry chain, most plausibly a vanished
		// client — further attempts would spend route health on a client
		// that can no longer be answered.
		if attempt > 0 && !time.Now().Before(handshakeDeadline) {
			writeSocksReply(clientConn, socksReplyGeneral) //nolint:errcheck // the client is gone either way
			log.Warn().Str("target", logTarget).Int("attempts", attempts).
				Str("error_kind", errorKindSetup).Str("duration", logDuration(time.Since(start))).
				Msg("inbound handshake deadline expired before the next attempt")
			return
		}
		// The budget ends the chain before picking: a pick would have
		// succeeded -- eligible routes remain -- so this is retry exhaustion,
		// not route exhaustion.
		if attempt >= settings.maxRetries {
			exhausted = true
			break
		}
		p := gen.Pool.PickFor(exclude, s.allow, targetAddr)
		if p == nil {
			break
		}
		attempts = attempt + 1
		// The winning pick holds the route for the tunnel's whole lifetime;
		// earlier excluded attempts release when the handler ends.
		defer p.Release()
		if log.Debug().Enabled() {
			ev := log.Debug().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
				Int("attempt", attempts).Int("excluded", len(exclude))
			// A pick from the all-cooling fallback arrives with cooldown left;
			// the size of that bet is the whole point of the line.
			if cd := gen.Pool.CoolingFor(p, targetAddr); cd > 0 {
				ev = ev.Str("cooldown_remaining", logDuration(cd))
			}
			ev.Msg("route selected")
		}
		up, err := s.dialWarmFirst(s.baseCtx, p, target, settings.dialTimeout)
		if err != nil {
			switch {
			case isProxyDialError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", errorKindProxyConnect).
					Str("error", logErrorValue(err)).Str("cooldown", cooldown.String()).
					Msg("upstream dial failed")
			case isConnectTargetError(err):
				// The endpoint answered CONNECT itself: the route works and
				// only the (route, target) pair is refused, so the cooldown
				// lands on the pair and the route stays eligible for every
				// other target. Same retry treatment as socks_connect.
				cooldown := gen.Pool.ReportTargetFailure(p, targetAddr, err)
				exclude[p] = true
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", errorKindConnectTarget).
					Str("error", logErrorValue(err)).Str("cooldown", cooldown.String()).
					Msg("upstream refused connect target")
			case isSocksHandshakeError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", errorKindSocksConnect).
					Str("error", logErrorValue(err)).Str("cooldown", cooldown.String()).
					Msg("upstream handshake failed")
			case isProxyAuthError(err):
				gen.Pool.ReportAuthBlocked(p, err)
				exclude[p] = true
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", errorKindAuthRoute).
					Str("error", logErrorValue(err)).
					Msg("upstream auth failed")
			default:
				writeSocksReply(clientConn, socksReplyGeneral) //nolint:errcheck // the connection closes either way
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", logErrorKind(err)).Str("error", logErrorValue(err)).
					Str("duration", logDuration(time.Since(start))).
					Msg("upstream setup failed")
				return
			}
			// A fallback is a real handoff to another attempt; the final
			// attempt's failure is terminal, not a fallback.
			if attempt+1 < settings.maxRetries {
				s.failovers.Add(1)
			}
			continue
		}
		gen.Pool.ReportSuccess(p, targetAddr)
		upstream, chosen = up, p
		break
	}
	if upstream == nil {
		kind := errorKindNoRoute
		if exhausted {
			kind = errorKindRetryExhausted
		}
		writeSocksReply(clientConn, socksReplyGeneral) //nolint:errcheck // the connection closes either way
		log.Warn().Str("target", logTarget).Int("attempts", attempts).
			Int("pool_size", gen.Pool.Size()).Int("kind_routes", gen.Pool.CountAllowed(s.allow)).
			Int("excluded", len(exclude)).
			Str("error_kind", kind).Str("duration", logDuration(time.Since(start))).
			Msg("tunnel failed")
		return
	}
	// Framing gets a fresh inbound window: the original deadline may be
	// nearly spent after a retry chain, and the established tunnel must not
	// inherit a deadline from its handshake.
	clientConn.SetDeadline(time.Now().Add(inboundHandshakeTimeout)) //nolint:errcheck // best-effort hardening
	writeSocksReply(clientConn, socksReplySuccess)                  //nolint:errcheck // relay shutdown handles write failure
	// Established tunnels carry no timeouts.
	clientConn.SetDeadline(time.Time{}) //nolint:errcheck // best-effort hardening
	log.Info().Str("target", logTarget).Str("upstream", upstreamLogValue(chosen)).
		Int("attempts", attempts).Str("duration", logDuration(time.Since(start))).
		Msg("tunnel")

	// Relay until both directions end. Established tunnels carry no health or
	// retry semantics; the close record is the only trace of which side ended
	// the stream first and why.
	closes := make(chan relayResult, 2)
	// relayDone closes only after the response relay armed its teardown
	// options and closed the client side, so the handler's own deferred
	// client close can never race ahead of an armed reset.
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		n, err := copyToClient(clientConn, upstream)
		// Send before teardown: whichever result lands first is the cause;
		// the one our own closes unblock is the artifact.
		closes <- relayResult{direction: relayToClient, bytes: n, err: err}
		if isUpstreamBreak(err) {
			// A broken upstream must not masquerade as a clean end of stream:
			// reset the client side so a truncated stream stays truncated.
			// tcpConnOf looks through the pipelining prefix wrapper, so the
			// reset reaches the socket for pipelining clients too.
			if tc := tcpConnOf(clientConn); tc != nil {
				// Best-effort: a failed SO_LINGER still leaves the close to
				// end the stream, just with a FIN instead of a RST.
				_ = tc.SetLinger(0)
				log.Debug().Msg("upstream broke the tunnel; client side set to reset on close")
			}
		}
		_ = clientConn.Close() // unblocks the client-to-upstream direction
	}()
	n, err := copyWithPooledBuffer(upstream, clientConn)
	if err == nil {
		// A clean end of the client-to-upstream direction is a client
		// half-close: one direction ended while the response direction may
		// still carry bytes. Propagate the FIN to the upstream and keep
		// relaying until the response ends on its own — the gateway never
		// terminates a tunnel the client still has open. A full client close
		// is indistinguishable here and gets the same relay: a write to a
		// vanished client fails by itself, ending the response direction.
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite() //nolint:errcheck // best-effort FIN propagation
		}
		// The response relay's result is guaranteed queued once relayDone
		// closes (it defers after its send), so waiting there — not on the
		// shared channel, which would hand back this direction's own result
		// — is what keeps the session alive until the response truly ends.
		select {
		case <-relayDone:
		case <-s.baseCtx.Done():
			// Shutdown's force-close already closed the client side; unblock
			// the response relay the way an abort teardown does, so the
			// session cannot linger on a parked upstream.
			_ = upstream.Close()
			<-relayDone
		}
		second := <-closes
		_ = upstream.Close() //nolint:errcheck // best-effort: the response direction ended
		recordTunnelClose(log, logTarget, chosen, start,
			relayResult{direction: relayToUpstream, bytes: n}, second)
		return
	}
	closes <- relayResult{direction: relayToUpstream, bytes: n, err: err}
	upstream.Close()   //nolint:errcheck // best-effort teardown
	clientConn.Close() //nolint:errcheck // unblocks the other direction
	first := <-closes
	second := <-closes // the forced close of the remaining side is an artifact
	<-relayDone        // the reset, when armed, lands before this returns
	recordTunnelClose(log, logTarget, chosen, start, first, second)
}

// socksRequest is one parsed inbound CONNECT-able request: the target, whose
// address type is the inbound frame's own ATYP (the wire truth the outbound
// CONNECT must reproduce), and the requested command.
type socksRequest struct {
	target socksdial.Target
	cmd    byte
}

// readSocksRequest performs the RFC 1928 greeting and reads one request. With
// a nil account the only accepted method is NO AUTHENTICATION REQUIRED; with
// an account configured the only accepted method is username/password
// (RFC 1929) — a configured credential is mandatory, not offered as an
// alternative to 0x00. Reads come from br so a buffered framing captures the
// whole exchange in as few socket reads as possible; protocol replies are
// written to w. Parse failures return an error and the connection must simply
// close: the RFC defines no reply for a request the server could not parse,
// and an unknown address type makes the frame length unknowable. Parseable
// but unsupported commands (BIND, UDP ASSOCIATE) return with the command so
// the caller can answer 0x07.
func readSocksRequest(br *bufio.Reader, w io.Writer, account *inboundAccount) (socksRequest, error) {
	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil {
		return socksRequest{}, fmt.Errorf("read greeting: %w", err)
	}
	if head[0] != socksVersion {
		return socksRequest{}, fmt.Errorf("unexpected SOCKS version 0x%02x", head[0])
	}
	if head[1] == 0 {
		return socksRequest{}, errors.New("empty method list")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return socksRequest{}, fmt.Errorf("read methods: %w", err)
	}
	var want byte = socksAuthNone
	if account != nil {
		want = socksAuthUserPass
	}
	offered := false
	for _, m := range methods {
		if m == want {
			offered = true
			break
		}
	}
	if !offered {
		w.Write([]byte{socksVersion, socksAuthUnaccepted}) //nolint:errcheck // the connection closes either way
		return socksRequest{}, errors.New("no acceptable authentication method")
	}
	if _, err := w.Write([]byte{socksVersion, want}); err != nil {
		return socksRequest{}, fmt.Errorf("write method selection: %w", err)
	}
	if account != nil {
		if err := readUserPassAuth(br, w, account); err != nil {
			return socksRequest{}, err
		}
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return socksRequest{}, fmt.Errorf("read request: %w", err)
	}
	if req[0] != socksVersion {
		return socksRequest{}, fmt.Errorf("unexpected request version 0x%02x", req[0])
	}
	if req[2] != 0x00 {
		return socksRequest{}, fmt.Errorf("non-zero reserved byte 0x%02x", req[2])
	}
	switch atyp := req[3]; atyp {
	case socksAtypIPv4:
		addr := make([]byte, 6)
		if _, err := io.ReadFull(br, addr); err != nil {
			return socksRequest{}, fmt.Errorf("read IPv4 target: %w", err)
		}
		target, err := socksTarget(socksdial.AddrIPv4, addr[:4], addr[4:])
		if err != nil {
			return socksRequest{}, err
		}
		return socksRequest{target: target, cmd: req[1]}, nil
	case socksAtypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(br, lenByte); err != nil {
			return socksRequest{}, fmt.Errorf("read domain length: %w", err)
		}
		if lenByte[0] == 0 {
			return socksRequest{}, errors.New("empty domain name")
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(br, name); err != nil {
			return socksRequest{}, fmt.Errorf("read domain target: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(br, portBytes); err != nil {
			return socksRequest{}, fmt.Errorf("read domain port: %w", err)
		}
		target, err := socksTarget(socksdial.AddrDomain, name, portBytes)
		if err != nil {
			return socksRequest{}, err
		}
		return socksRequest{target: target, cmd: req[1]}, nil
	case socksAtypIPv6:
		addr := make([]byte, 18)
		if _, err := io.ReadFull(br, addr); err != nil {
			return socksRequest{}, fmt.Errorf("read IPv6 target: %w", err)
		}
		target, err := socksTarget(socksdial.AddrIPv6, addr[:16], addr[16:])
		if err != nil {
			return socksRequest{}, err
		}
		return socksRequest{target: target, cmd: req[1]}, nil
	default:
		return socksRequest{}, fmt.Errorf("unsupported address type 0x%02x", atyp)
	}
}

// readUserPassAuth performs the RFC 1929 username/password subnegotiation:
// VER ULEN UNAME PLEN PASSWD in, VER STATUS back. A mismatch writes the
// failure reply and returns errInboundAuth — the caller closes, never logs
// credential bytes. Malformed frames (bad version, truncation) return an
// error with no reply, the same close-silently doctrine as the rest of the
// inbound framing.
func readUserPassAuth(br *bufio.Reader, w io.Writer, account *inboundAccount) error {
	ver := make([]byte, 2) // VER, ULEN
	if _, err := io.ReadFull(br, ver); err != nil {
		return fmt.Errorf("read auth version: %w", err)
	}
	if ver[0] != authUPVersion {
		return fmt.Errorf("unexpected auth version 0x%02x", ver[0])
	}
	uname := make([]byte, ver[1])
	if _, err := io.ReadFull(br, uname); err != nil {
		return fmt.Errorf("read auth username: %w", err)
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(br, plen); err != nil {
		return fmt.Errorf("read auth password length: %w", err)
	}
	passwd := make([]byte, plen[0])
	if _, err := io.ReadFull(br, passwd); err != nil {
		return fmt.Errorf("read auth password: %w", err)
	}
	// Constant-time across the pair: the handshake is the one place a timing
	// side channel would discriminate between a known-username/wrong-password
	// guess and a wrong username.
	if !credentialsMatch(account, uname, passwd) {
		w.Write([]byte{authUPVersion, authUPFailure}) //nolint:errcheck // the connection closes either way
		return errInboundAuth
	}
	if _, err := w.Write([]byte{authUPVersion, authUPSuccess}); err != nil {
		return fmt.Errorf("write auth reply: %w", err)
	}
	return nil
}

// credentialsMatch compares presented RFC 1929 credentials against the
// configured account without leaking which field mismatched or either side's
// field lengths. Every field is reduced to a fixed-length digest first —
// subtle.ConstantTimeCompare returns immediately on a length mismatch, so
// comparing the variable-length fields directly would expose the configured
// lengths — and both comparisons always execute; their results are combined
// with & and returned, so the caller branches once on the pair and a wrong
// username can never skip the password comparison (and vice versa).
func credentialsMatch(account *inboundAccount, username, password []byte) bool {
	usernameSum := credentialDigest(username)
	passwordSum := credentialDigest(password)
	userOK := subtle.ConstantTimeCompare(usernameSum[:], account.usernameSum[:])
	passOK := subtle.ConstantTimeCompare(passwordSum[:], account.passwordSum[:])
	return userOK&passOK == 1
}

// socksTarget builds the request target from one inbound frame's address
// bytes: the port is validated, the host is rendered as the host:port
// identity pool state and logs key on, and the address type is the frame's
// own ATYP — carried through to the outbound CONNECT, never re-inferred from
// the host string. A zero port is a parse failure: there is no meaningful
// CONNECT target without one.
func socksTarget(atyp socksdial.AddrType, host, portBytes []byte) (socksdial.Target, error) {
	port := binary.BigEndian.Uint16(portBytes)
	if port == 0 {
		return socksdial.Target{}, errors.New("zero target port")
	}
	var hostStr string
	switch atyp {
	case socksdial.AddrDomain:
		hostStr = string(host)
	case socksdial.AddrIPv4, socksdial.AddrIPv6:
		// The canonical text of the frame's own address bytes; encoding at the
		// outbound route round-trips these bytes exactly.
		hostStr = net.IP(host).String()
	}
	return socksdial.Target{Host: hostStr, Port: port, Type: atyp}, nil
}

// writeSocksReply writes a full SOCKS reply with a zero IPv4 BND.ADDR/PORT.
// The gateway cannot know the upstream bound address; RFC 1928 clients must
// ignore it in a CONNECT success reply.
func writeSocksReply(w io.Writer, code byte) error {
	_, err := w.Write([]byte{socksVersion, code, 0x00, socksAtypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

// copyBufPool lends 64KiB relay buffers. Relaying is the hot path for
// established tunnels, and io.Copy's implicit 32KiB buffer would be allocated
// per relay; the pool keeps one larger buffer per in-flight copy instead.
var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64<<10)
		return &buf
	},
}

func copyWithPooledBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufp := copyBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(dst, src, *bufp)
	copyBufPool.Put(bufp)
	return n, err
}

// upstreamBreakError marks a relay failure raised on the upstream side of the
// response direction: a read from the upstream conn failed, so the response
// stream itself broke mid-flight. Failures raised on the client side of the
// same relay — writes to a vanished client — stay bare and must never be
// treated as an upstream break.
type upstreamBreakError struct{ err error }

func (e *upstreamBreakError) Error() string { return e.err.Error() }
func (e *upstreamBreakError) Unwrap() error { return e.err }

// isUpstreamBreak reports whether err is a genuine upstream-side failure of
// the response relay: not a clean end of stream, not the artifact of the
// gateway's own teardown close, and not a client-side write failure.
func isUpstreamBreak(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return false
	}
	var brk *upstreamBreakError
	return errors.As(err, &brk)
}

// copyToClient relays the response direction, upstream to client, and keeps
// the failing end distinguishable: an upstream read failure comes back wrapped
// in upstreamBreakError, while a client write failure stays bare. The
// reset-on-upstream-break decision and the close record's broken-tunnel
// classification both key on that difference.
func copyToClient(client, upstream net.Conn) (int64, error) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	buf := *bufp
	var total int64
	for {
		n, rerr := upstream.Read(buf)
		if n > 0 {
			m, werr := client.Write(buf[:n])
			total += int64(m)
			if werr != nil {
				return total, fmt.Errorf("write to client: %w", werr)
			}
			if m < n {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, &upstreamBreakError{err: rerr}
		}
	}
}

// tcpConnOf looks through the pipelining prefix wrapper for the client
// socket's *net.TCPConn, so teardown socket options reach the real socket
// even when the framing reader handed the relay a wrapped conn. Non-TCP
// client conns (tests) return nil.
func tcpConnOf(c net.Conn) *net.TCPConn {
	if pc, ok := c.(*prefixConn); ok {
		c = pc.Conn
	}
	tc, _ := c.(*net.TCPConn)
	return tc
}

// inboundBufPool lends the buffered readers that frame inbound SOCKS5
// exchanges. Greeting and CONNECT frame together stay under 300 bytes, so
// one 4KiB fill usually captures the whole exchange in a single socket read
// where field-by-field ReadFulls cost four to six.
const inboundBufSize = 4 << 10

var inboundBufPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, inboundBufSize) },
}

// prefixConn serves the bytes a client pipelined behind its CONNECT frame —
// already pulled into the framing reader — before falling through to the
// socket. It is the inbound mirror of socksdial's upstream-side prefix
// handling: a pipelining client's bytes must be relayed, not dropped.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}

// relayResult is the outcome of one direction of an established tunnel relay.
type relayResult struct {
	direction string
	bytes     int64
	err       error
}

const (
	relayToClient   = "upstream_to_client"
	relayToUpstream = "client_to_upstream"
)

// recordTunnelClose logs which side ended an established tunnel first and how
// much each direction carried. An upstream-side error is a broken tunnel — the
// client's stream died mid-flight — and logs at warn; every other close is
// routine flow detail at debug. Tunnel closes never mutate route health.
// recordTunnelClose classifies the tunnel's end. The direction that ended
// first is the cause; the other direction's result is normally the artifact
// of the teardown close. A genuine upstream break must surface as broken
// (warn) whichever way it orders: first, behind a client-side failure, or
// behind a clean client half-close — while teardown artifacts (the gateway's
// own closes) and client-side write failures stay routine closes.
func recordTunnelClose(log zerolog.Logger, target string, p *pool.Proxy, start time.Time, first, second relayResult) {
	toClient, toUpstream := second, first
	if first.direction == relayToClient {
		toClient, toUpstream = first, second
	}
	msg, reason, cause := "tunnel closed", "client_closed", first.err
	switch {
	case first.direction == relayToClient && isUpstreamBreak(first.err):
		msg, reason = "tunnel broken", "upstream_broken"
	case second.direction == relayToClient && isUpstreamBreak(second.err):
		msg, reason, cause = "tunnel broken", "upstream_broken", second.err
	case first.direction == relayToClient && first.err == nil:
		reason = "upstream_closed"
	case first.err != nil:
		reason = "client_aborted"
	}
	ev := log.Debug()
	if msg == "tunnel broken" {
		ev = log.Warn()
	}
	ev.Str("target", target).Str("upstream", upstreamLogValue(p)).
		Str("duration", logDuration(time.Since(start))).
		Int64("client_to_upstream_bytes", toUpstream.bytes).
		Int64("upstream_to_client_bytes", toClient.bytes).
		Str("close_reason", reason)
	if cause != nil {
		ev = ev.Str("error", logErrorValue(cause))
	}
	ev.Msg(msg)
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

// AdminMux serves the health and status endpoints for the admin listener.
func (s *Server) AdminMux() *http.ServeMux {
	return AdminMux(s.version, s.startTime, s.store, map[string]*Server{s.listener: s}, nil, nil, nil)
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
// is omitted entirely when no warm pool backs the process.
func AdminMux(version string, started time.Time, store *pool.Store, listeners map[string]*Server, rotations func() uint64, ipRevisits func() uint64, warm func() warmpool.Status) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(w, "ok\n")
	})
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
