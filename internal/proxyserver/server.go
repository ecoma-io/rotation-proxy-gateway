// Package proxyserver implements the inbound SOCKS5 proxy. Client connections
// speak RFC 1928 CONNECT with no authentication; every accepted tunnel is
// relayed through SOCKS5 routes from the shared health-aware pool.
package proxyserver

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"

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
	dial     func(context.Context, *url.URL, string, time.Duration) (net.Conn, error)

	cmu   sync.Mutex
	conns map[net.Conn]struct{}
	// live counts tracked sessions so Shutdown can wait for the drain without
	// polling the connection map.
	live sync.WaitGroup

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
	return &Server{
		store:     store,
		log:       log.With().Str("listener", listener).Logger(),
		version:   version,
		listener:  listener,
		allow:     allow,
		dial:      dialVia,
		conns:     map[net.Conn]struct{}{},
		startTime: time.Now(),
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
			return err
		}
		s.live.Add(1)
		go func() {
			defer s.live.Done()
			s.serveConn(conn)
		}()
	}
}

// Shutdown waits for active sessions to finish. When ctx expires before the
// drain completes, tracked client connections are force-closed, the remaining
// sessions finish on their closed connections, and ctx.Err() is returned.
// Closing the listener itself is the caller's job: it stops new accepts at a
// precisely chosen point in the shutdown sequence.
func (s *Server) Shutdown(ctx context.Context) error {
	done := make(chan struct{})
	go func() {
		s.live.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		s.CloseConns()
		<-done
		return ctx.Err()
	}
}

// generation loads the current immutable runtime snapshot.
func (s *Server) generation() *pool.Generation {
	return s.store.Load()
}

func (s *Server) pick(gen *pool.Generation, exclude map[*pool.Proxy]bool) *pool.Proxy {
	return gen.Pool.PickFor(exclude, s.allow)
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
	s.trackConn(conn)
	defer s.untrackConn(conn)
	defer conn.Close() //nolint:errcheck // relay shutdown handles write failure

	// The deadline covers greeting, request, and reply framing; the success
	// path clears it before relaying.
	conn.SetDeadline(time.Now().Add(inboundHandshakeTimeout)) //nolint:errcheck // best-effort hardening

	req, err := readSocksRequest(conn)
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
	s.serveTunnel(conn, req.target, log)
}

// serveTunnel dials the target through the pool with the retry/exclude loop,
// sends the success reply once, and relays until either side ends the stream.
// It loads one generation for the whole session so route picks and health
// reports stay consistent across reloads.
func (s *Server) serveTunnel(clientConn net.Conn, target string, log zerolog.Logger) {
	gen := s.generation()
	settings := generationSettings(gen)
	start := time.Now()
	logTarget := socksTargetLogValue(target)
	log.Debug().Str("target", logTarget).Msg("tunnel start")

	exclude := map[*pool.Proxy]bool{}
	var upstream net.Conn
	var chosen *pool.Proxy
	var attempts int
	for attempt := 0; attempt < settings.maxRetries; attempt++ {
		attempts = attempt + 1
		p := s.pick(gen, exclude)
		if p == nil {
			break
		}
		// The winning pick holds the route for the tunnel's whole lifetime;
		// earlier excluded attempts release when the handler ends.
		defer p.Release()
		up, err := s.dial(context.Background(), p.URL, target, settings.dialTimeout)
		if err != nil {
			switch {
			case isProxyDialError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", errorKindProxyConnect).
					Str("error", logErrorValue(err)).Str("cooldown", cooldown.String()).
					Msg("upstream dial failed")
				continue
			case isSocksHandshakeError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", errorKindSocksConnect).
					Str("error", logErrorValue(err)).Str("cooldown", cooldown.String()).
					Msg("upstream handshake failed")
				continue
			case isProxyAuthError(err):
				gen.Pool.ReportAuthBlocked(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", errorKindAuthRoute).
					Str("error", logErrorValue(err)).
					Msg("upstream auth failed")
				continue
			default:
				writeSocksReply(clientConn, socksReplyGeneral) //nolint:errcheck // the connection closes either way
				log.Warn().Str("target", logTarget).Str("upstream", upstreamLogValue(p)).
					Int("attempt", attempts).Str("error_kind", logErrorKind(err)).Str("error", logErrorValue(err)).
					Str("duration", logDuration(time.Since(start))).
					Msg("upstream setup failed")
				return
			}
		}
		gen.Pool.ReportSuccess(p)
		upstream, chosen = up, p
		break
	}
	if upstream == nil {
		writeSocksReply(clientConn, socksReplyGeneral) //nolint:errcheck // the connection closes either way
		log.Warn().Str("target", logTarget).Int("attempts", len(exclude)).
			Str("error_kind", errorKindNoRoute).Str("duration", logDuration(time.Since(start))).
			Msg("tunnel failed")
		return
	}
	writeSocksReply(clientConn, socksReplySuccess) //nolint:errcheck // relay shutdown handles write failure
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
				tc.SetLinger(0)
			}
		}
		clientConn.Close() // unblocks the client-to-upstream direction
	}()
	n, err := copyWithPooledBuffer(upstream, clientConn)
	closes <- relayResult{direction: relayToUpstream, bytes: n, err: err}
	upstream.Close()   //nolint:errcheck // best-effort teardown
	clientConn.Close() //nolint:errcheck // unblocks the other direction
	first := <-closes
	second := <-closes // the forced close of the remaining side is an artifact
	recordTunnelClose(log, logTarget, chosen, start, first, second)
}

// socksRequest is one parsed inbound CONNECT-able request: the host:port
// target and the requested command.
type socksRequest struct {
	target string
	cmd    byte
}

// readSocksRequest performs the RFC 1928 greeting (version 5, NO
// AUTHENTICATION REQUIRED only) and reads one request. Parse failures return
// an error and the connection must simply close: the RFC defines no reply for
// a request the server could not parse, and an unknown address type makes the
// frame length unknowable. Parseable but unsupported commands (BIND, UDP
// ASSOCIATE) return with the command so the caller can answer 0x07.
func readSocksRequest(conn net.Conn) (socksRequest, error) {
	// Greeting: VER NMETHODS METHODS...
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return socksRequest{}, fmt.Errorf("read greeting: %w", err)
	}
	if head[0] != socksVersion {
		return socksRequest{}, fmt.Errorf("unexpected SOCKS version 0x%02x", head[0])
	}
	if head[1] == 0 {
		return socksRequest{}, errors.New("empty method list")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
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
		conn.Write([]byte{socksVersion, socksAuthUnaccepted}) //nolint:errcheck // the connection closes either way
		return socksRequest{}, errors.New("no acceptable authentication method")
	}
	if _, err := conn.Write([]byte{socksVersion, socksAuthNone}); err != nil {
		return socksRequest{}, fmt.Errorf("write method selection: %w", err)
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
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
		if _, err := io.ReadFull(conn, addr); err != nil {
			return socksRequest{}, fmt.Errorf("read IPv4 target: %w", err)
		}
		target, err := joinSocksTarget(net.IP(addr[:4]).String(), addr[4:])
		if err != nil {
			return socksRequest{}, err
		}
		return socksRequest{target: target, cmd: req[1]}, nil
	case socksAtypDomain:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return socksRequest{}, fmt.Errorf("read domain length: %w", err)
		}
		if lenByte[0] == 0 {
			return socksRequest{}, errors.New("empty domain name")
		}
		name := make([]byte, lenByte[0])
		if _, err := io.ReadFull(conn, name); err != nil {
			return socksRequest{}, fmt.Errorf("read domain target: %w", err)
		}
		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, portBytes); err != nil {
			return socksRequest{}, fmt.Errorf("read domain port: %w", err)
		}
		target, err := joinSocksTarget(string(name), portBytes)
		if err != nil {
			return socksRequest{}, err
		}
		return socksRequest{target: target, cmd: req[1]}, nil
	case socksAtypIPv6:
		addr := make([]byte, 18)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return socksRequest{}, fmt.Errorf("read IPv6 target: %w", err)
		}
		target, err := joinSocksTarget(net.IP(addr[:16]).String(), addr[16:])
		if err != nil {
			return socksRequest{}, err
		}
		return socksRequest{target: target, cmd: req[1]}, nil
	default:
		return socksRequest{}, fmt.Errorf("unsupported address type 0x%02x", atyp)
	}
}

// joinSocksTarget validates the port and renders host:port. A zero port is a
// parse failure: there is no meaningful CONNECT target without one.
func joinSocksTarget(host string, portBytes []byte) (string, error) {
	port := binary.BigEndian.Uint16(portBytes)
	if port == 0 {
		return "", errors.New("zero target port")
	}
	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
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
func recordTunnelClose(log zerolog.Logger, target string, p *pool.Proxy, start time.Time, first, second relayResult) {
	toClient, toUpstream := second, first
	if first.direction == relayToClient {
		toClient, toUpstream = first, second
	}
	msg, reason := "tunnel closed", "client_closed"
	switch {
	case first.direction == relayToClient && first.err != nil:
		msg, reason = "tunnel broken", "upstream_broken"
	case first.direction == relayToClient:
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
	if first.err != nil {
		ev = ev.Str("error", logErrorValue(first.err))
	}
	ev.Msg(msg)
}

func (s *Server) trackConn(c net.Conn) {
	s.cmu.Lock()
	s.conns[c] = struct{}{}
	s.cmu.Unlock()
}

func (s *Server) untrackConn(c net.Conn) {
	s.cmu.Lock()
	delete(s.conns, c)
	s.cmu.Unlock()
}

// CloseConns closes every tracked client connection, including established
// tunnels and sessions still inside their handshake. Shutdown calls it when
// the shared grace budget expires.
func (s *Server) CloseConns() {
	s.cmu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.cmu.Unlock()
	for _, c := range conns {
		c.Close() //nolint:errcheck // best-effort force-close
	}
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
		io.WriteString(w, "ok\n")
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
		json.NewEncoder(w).Encode(status)
	})
	return mux
}
