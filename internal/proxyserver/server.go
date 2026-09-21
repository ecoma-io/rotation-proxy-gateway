// Package proxyserver implements the inbound SOCKS5 proxy. Client connections
// speak RFC 1928 CONNECT with no authentication; every accepted tunnel is
// relayed through SOCKS5 routes from the shared health-aware pool.
package proxyserver

import (
	"bufio"
	"context"
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

// Server is the inbound SOCKS5 listener handler.
type Server struct {
	store    *pool.Store
	log      zerolog.Logger
	version  string
	listener string
	allow    func(*pool.Proxy) bool
	dial     func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error)

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

// MixedListener is the listener name of the mixed v4/v6 egress view. The name
// decides the pick path: dedicated views pick through PickForDedicated so
// their traffic never advances the family-balance clocks the mixed view splits
// by.
const MixedListener = "mixed"

func (s *Server) pick(gen *pool.Generation, exclude map[*pool.Proxy]bool, target string) *pool.Proxy {
	if s.listener == MixedListener {
		return gen.Pool.PickFor(exclude, s.allow, target)
	}
	return gen.Pool.PickForDedicated(exclude, s.allow, target)
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

	req, err := readSocksRequest(br, conn)
	if err != nil {
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
	for attempt := 0; attempt < settings.maxRetries; attempt++ {
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
		p := s.pick(gen, exclude, targetAddr)
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
		up, err := s.dial(s.baseCtx, p.URL, target, settings.dialTimeout)
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
		writeSocksReply(clientConn, socksReplyGeneral) //nolint:errcheck // the connection closes either way
		log.Warn().Str("target", logTarget).Int("attempts", attempts).
			Int("pool_size", gen.Pool.Size()).Int("kind_routes", gen.Pool.CountAllowed(s.allow)).
			Int("excluded", len(exclude)).
			Str("error_kind", errorKindNoRoute).Str("duration", logDuration(time.Since(start))).
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

	// Relay until either side ends the stream. Established tunnels carry no
	// health or retry semantics; the close record is the only trace of which
	// side ended the stream first and why.
	closes := make(chan relayResult, 2)
	go func() {
		n, err := copyWithPooledBuffer(clientConn, upstream)
		// Send before teardown: whichever result lands first is the cause;
		// the one our own closes unblock is the artifact.
		closes <- relayResult{direction: relayToClient, bytes: n, err: err}
		if err != nil {
			// A broken upstream must not masquerade as a clean end of stream:
			// reset the client side so a truncated stream stays truncated.
			if tc, ok := clientConn.(*net.TCPConn); ok {
				// Best-effort: a failed SO_LINGER still leaves the close to
				// end the stream, just with a FIN instead of a RST.
				_ = tc.SetLinger(0)
				log.Debug().Msg("upstream broke the tunnel; client side set to reset on close")
			}
		}
		_ = clientConn.Close() // unblocks the client-to-upstream direction
	}()
	n, err := copyWithPooledBuffer(upstream, clientConn)
	closes <- relayResult{direction: relayToUpstream, bytes: n, err: err}
	upstream.Close()   //nolint:errcheck // best-effort teardown
	clientConn.Close() //nolint:errcheck // unblocks the other direction
	first := <-closes
	second := <-closes // the forced close of the remaining side is an artifact
	recordTunnelClose(log, logTarget, chosen, start, first, second)
}

// socksRequest is one parsed inbound CONNECT-able request: the target, whose
// address type is the inbound frame's own ATYP (the wire truth the outbound
// CONNECT must reproduce), and the requested command.
type socksRequest struct {
	target socksdial.Target
	cmd    byte
}

// readSocksRequest performs the RFC 1928 greeting (version 5, NO
// AUTHENTICATION REQUIRED only) and reads one request. Reads come from br so
// a buffered framing captures the whole exchange in as few socket reads as
// possible; protocol replies are written to w. Parse failures return an error
// and the connection must simply close: the RFC defines no reply for a request
// the server could not parse, and an unknown address type makes the frame
// length unknowable. Parseable but unsupported commands (BIND, UDP ASSOCIATE)
// return with the command so the caller can answer 0x07.
func readSocksRequest(br *bufio.Reader, w io.Writer) (socksRequest, error) {
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
	offered := false
	for _, m := range methods {
		if m == socksAuthNone {
			offered = true
			break
		}
	}
	if !offered {
		w.Write([]byte{socksVersion, socksAuthUnaccepted}) //nolint:errcheck // the connection closes either way
		return socksRequest{}, errors.New("no acceptable authentication method")
	}
	if _, err := w.Write([]byte{socksVersion, socksAuthNone}); err != nil {
		return socksRequest{}, fmt.Errorf("write method selection: %w", err)
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
// of the teardown close. One artifact ordering lies: when the client side
// failed first but the upstream direction also failed on its own — an error
// that is not our close — an upstream reset killed the tunnel from the far
// side, and it must be logged as broken (warn), not as a clean client end
// (debug).
func recordTunnelClose(log zerolog.Logger, target string, p *pool.Proxy, start time.Time, first, second relayResult) {
	toClient, toUpstream := second, first
	if first.direction == relayToClient {
		toClient, toUpstream = first, second
	}
	msg, reason, cause := "tunnel closed", "client_closed", first.err
	switch {
	case first.direction == relayToClient && first.err != nil:
		msg, reason = "tunnel broken", "upstream_broken"
	case first.direction == relayToClient:
		reason = "upstream_closed"
	case first.err != nil && second.err != nil && !errors.Is(second.err, net.ErrClosed):
		msg, reason, cause = "tunnel broken", "upstream_broken", second.err
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
	return AdminMux(s.version, s.startTime, s.store, map[string]*Server{s.listener: s}, nil)
}

// AdminMux serves aggregate health/status for all proxy listener views sharing
// a runtime generation store. Existing status fields remain global totals;
// listeners adds safe per-listener counters — requests counts valid CONNECT
// commands (protocol rejects never advance it) and failovers counts in-band
// route fallbacks, distinct from rotations. The pool snapshot comes from the
// current generation so /status changes atomically with serving behavior.
func AdminMux(version string, started time.Time, store *pool.Store, listeners map[string]*Server, rotations func() uint64) *http.ServeMux {
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
		// The active family split is part of the serving contract, so /status
		// reports exactly what the current generation enforces — omitted when
		// no balance block is configured.
		if bal := gen.Config.Balance; bal.V4 > 0 || bal.V6 > 0 {
			status["balance"] = map[string]int{"v4": bal.V4, "v6": bal.V6}
		}
		if rotations != nil {
			status["rotations"] = rotations()
		}
		_ = json.NewEncoder(w).Encode(status)
	})
	return mux
}
