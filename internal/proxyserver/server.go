// Package proxyserver implements the inbound HTTP forward proxy. All outbound
// traffic is tunneled through SOCKS5 routes from the proxy pool.
package proxyserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

var hopByHopHeaders = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"trailers":            true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

// stripHopByHop removes hop-by-hop headers, including any named by the
// Connection header itself.
func stripHopByHop(h http.Header) {
	for _, tokens := range h.Values("Connection") {
		for _, tok := range strings.Split(tokens, ",") {
			h.Del(strings.TrimSpace(tok))
		}
	}
	for name := range h {
		if hopByHopHeaders[strings.ToLower(name)] {
			h.Del(name)
		}
	}
}

// Server is the inbound HTTP forward-proxy handler.
type Server struct {
	store    *pool.Store
	log      *slog.Logger
	version  string
	listener string
	allow    func(*pool.Proxy) bool
	dial     func(context.Context, *url.URL, string, time.Duration) (net.Conn, error)
	// tlsCache lets repeated absolute-form https targets resume TLS sessions
	// inside their per-request tunnels instead of paying a full handshake
	// every time. The cache itself is safe for concurrent use.
	tlsCache tls.ClientSessionCache

	cmu   sync.Mutex
	conns map[net.Conn]struct{}

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

// NewRuntime builds a listener-specific proxy Server whose new requests use
// atomic runtime generations. Every request loads its generation once so route
// picks, health reports, and request settings stay within one snapshot even
// when a reload publishes a new generation in parallel.
func NewRuntime(store *pool.Store, log *slog.Logger, version, listener string, allowed ...config.EgressKind) *Server {
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
		log:       log.With("listener", listener),
		version:   version,
		listener:  listener,
		allow:     allow,
		dial:      dialVia,
		tlsCache:  tls.NewLRUClientSessionCache(0),
		conns:     map[net.Conn]struct{}{},
		startTime: time.Now(),
	}
}

// generation loads the current immutable runtime snapshot.
func (s *Server) generation() *pool.Generation {
	return s.store.Load()
}

func (s *Server) pick(gen *pool.Generation, exclude map[*pool.Proxy]bool) *pool.Proxy {
	return gen.Pool.PickFor(exclude, s.allow)
}

type requestSettings struct {
	maxRetries        int
	maxBodyBuffer     int64
	dialTimeout       time.Duration
	targetTLSInsecure bool
}

// generationSettings derives request-scoped values from one loaded generation
// so a reload cannot change retry, body, timeout, or TLS policy part-way
// through an operation.
func generationSettings(gen *pool.Generation) requestSettings {
	cfg := gen.Config
	return requestSettings{
		maxRetries:        cfg.MaxRetries,
		maxBodyBuffer:     cfg.MaxBodyBuffer,
		dialTimeout:       cfg.DialTimeout,
		targetTLSInsecure: cfg.TargetTLSInsecure,
	}
}

// settings reports the current generation's request values. Tests use it to
// assert publication; serving paths load the generation once and derive the
// settings from that same snapshot.
func (s *Server) settings() requestSettings {
	return generationSettings(s.generation())
}

func (s *Server) roundTripWithSettings(ctx context.Context, p *pool.Proxy, out *http.Request, settings requestSettings) (*http.Response, error) {
	return s.roundTripViaSOCKSWithOptions(ctx, p, out, settings.dialTimeout, settings.targetTLSInsecure)
}

func (s *Server) roundTripViaSOCKSWithOptions(ctx context.Context, p *pool.Proxy, out *http.Request, dialTimeout time.Duration, targetTLSInsecure bool) (*http.Response, error) {
	target, err := targetAddress(out.URL)
	if err != nil {
		return nil, err
	}
	conn, err := s.dial(ctx, p.URL, target, dialTimeout)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*http.Response, error) {
		conn.Close()
		return nil, err
	}
	if out.URL.Scheme == "https" {
		host := out.URL.Hostname()
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: targetTLSInsecure,
			ClientSessionCache: s.tlsCache,
		})
		hsCtx, cancel := context.WithTimeout(ctx, dialTimeout)
		err := tlsConn.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			return fail(fmt.Errorf("target TLS handshake: %w", err))
		}
		conn = tlsConn
	}
	// Buffer the request write: http.Request.Write emits the start line,
	// headers, and body in many small writes, which would otherwise each
	// become a syscall and a small TCP segment on the tunnel.
	bw := bufio.NewWriterSize(conn, 4<<10)
	if err := out.Write(bw); err != nil {
		return fail(fmt.Errorf("write target request: %w", err))
	}
	if err := bw.Flush(); err != nil {
		return fail(fmt.Errorf("write target request: %w", err))
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), out)
	if err != nil {
		return fail(fmt.Errorf("read target response: %w", err))
	}
	resp.Body = &connReadCloser{ReadCloser: resp.Body, conn: conn}
	return resp, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	requestID := s.requests.Add(1)
	log := s.log.With("request_id", requestID)
	if r.Method == http.MethodConnect {
		s.handleTunnel(w, r, log)
		return
	}
	s.handleHTTP(w, r, log)
}

// handleHTTP forwards a plain absolute-form request through a SOCKS5 route.
// It loads one generation for the whole operation so route picks, health
// reports, and request settings stay consistent across reloads.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request, log *slog.Logger) {
	gen := s.generation()
	settings := generationSettings(gen)
	start := time.Now()
	target := httpTargetLogValue(r.URL)
	if !r.URL.IsAbs() || r.Host == "" {
		http.Error(w, "proxy request requires an absolute URI", http.StatusBadRequest)
		log.Warn("request rejected", "target", target, "error_kind", "bad_request")
		return
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "proxy request requires an http or https URI", http.StatusBadRequest)
		log.Warn("request rejected", "target", target, "error_kind", "bad_request")
		return
	}
	log.Debug("request start", "method", r.Method, "target", target)

	// Known-large bodies can stream immediately. Unknown-length bodies are
	// buffered up to the cap so small bodies remain replayable after an
	// endpoint dial, SOCKS handshake, or authentication fallback. A buffered
	// prefix of a larger unknown-length body is replayable only until SOCKS
	// setup succeeds.
	var body []byte
	streamMode := r.ContentLength > settings.maxBodyBuffer
	directStream := streamMode
	if !streamMode {
		b, err := io.ReadAll(io.LimitReader(r.Body, settings.maxBodyBuffer+1))
		if err != nil {
			r.Body.Close()
			http.Error(w, "failed to read request body", http.StatusBadRequest)
			log.Warn("request rejected", "target", target, "error_kind", "body_read", "error", logErrorValue(err))
			return
		}
		body = b
		if int64(len(body)) > settings.maxBodyBuffer {
			streamMode = true
		} else {
			r.Body.Close()
		}
	}
	log.Debug("request body mode", "target", target, "body_mode", bodyLogMode(streamMode))
	stripHopByHop(r.Header)

	exclude := map[*pool.Proxy]bool{}
	attempts := 0
	for attempt := 0; attempt < settings.maxRetries; attempt++ {
		attemptNumber := attempt + 1
		if r.Context().Err() != nil {
			if streamMode {
				r.Body.Close()
			}
			log.Debug("request canceled", "target", target, "attempts", attempt)
			return
		}
		p := s.pick(gen, exclude)
		if p == nil {
			break
		}
		// Hold the route until this handler returns: the pick counts as
		// in-flight work for rotation draining, and earlier excluded attempts
		// release when the handler ends rather than leaking.
		defer p.Release()
		attempts = attemptNumber
		out := buildOutbound(r, body)
		if streamMode {
			if directStream {
				out.Body = r.Body
			} else {
				out.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
			}
			out.ContentLength = r.ContentLength
			out.TransferEncoding = append([]string(nil), r.TransferEncoding...)
			// r.Body populates r.Trailer at EOF. Retain the same map rather
			// than the clone made by Request.Clone so Request.Write sees the
			// final trailer values after streaming the body.
			out.Trailer = r.Trailer
		}
		resp, err := s.roundTripWithSettings(r.Context(), p, out, settings)
		if streamMode && !isProxyDialError(err) && !isProxyAuthError(err) && !isSocksHandshakeError(err) {
			r.Body.Close()
		}
		if err != nil {
			if r.Context().Err() != nil {
				if streamMode {
					r.Body.Close()
				}
				log.Debug("request canceled", "target", target, "attempts", attemptNumber)
				return
			}
			switch {
			case isProxyDialError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn("upstream dial failed", "target", target, "upstream", upstreamLogValue(p),
					"attempt", attemptNumber, "error_kind", errorKindProxyConnect,
					"error", logErrorValue(err), "cooldown", cooldown.String())
				continue
			case isSocksHandshakeError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn("upstream handshake failed", "target", target, "upstream", upstreamLogValue(p),
					"attempt", attemptNumber, "error_kind", errorKindSocksConnect,
					"error", logErrorValue(err), "cooldown", cooldown.String())
				continue
			case isProxyAuthError(err):
				gen.Pool.ReportAuthBlocked(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn("upstream auth failed", "target", target, "upstream", upstreamLogValue(p),
					"attempt", attemptNumber, "error_kind", errorKindAuthRoute,
					"error", logErrorValue(err))
				continue
			default:
				if r.Context().Err() != nil {
					log.Debug("request canceled", "target", target, "attempts", attemptNumber)
					return
				}
				http.Error(w, "upstream SOCKS setup failed", http.StatusBadGateway)
				log.Warn("upstream setup failed", "target", target, "upstream", upstreamLogValue(p),
					"attempt", attemptNumber, "error_kind", logErrorKind(err), "error", logErrorValue(err),
					"duration", logDuration(time.Since(start)))
				return
			}
		}

		if streamMode {
			r.Body.Close()
		}
		if r.Context().Err() != nil {
			resp.Body.Close()
			log.Debug("request canceled", "target", target, "attempts", attemptNumber)
			return
		}
		gen.Pool.ReportSuccess(p)
		s.writeResponse(log, w, resp)
		log.Info("request", "method", r.Method, "target", target, "upstream", upstreamLogValue(p),
			"status", resp.StatusCode, "attempts", attemptNumber, "duration", logDuration(time.Since(start)))
		return
	}

	if streamMode {
		r.Body.Close()
	}
	http.Error(w, "no usable upstream SOCKS routes", http.StatusBadGateway)
	log.Warn("request failed", "target", target, "attempts", attempts,
		"error_kind", errorKindNoRoute, "duration", logDuration(time.Since(start)))
}

// buildOutbound clones the client request for a route attempt. Buffered bodies
// are replayed from memory; empty bodies without trailers use nil rather than an
// empty reader so net/http keeps no-body request framing.
func buildOutbound(r *http.Request, body []byte) *http.Request {
	out := r.Clone(r.Context())
	out.RequestURI = "" // http.Request.Write derives origin-form from URL.
	out.Close = true    // each SOCKS tunnel is scoped to this request.
	if len(r.Trailer) > 0 {
		// A trailer requires chunked framing. The body probe has reached EOF, so
		// these values are complete and safe to clone for each retry.
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = -1
		out.TransferEncoding = []string{"chunked"}
		return out
	}
	out.Trailer = nil
	out.TransferEncoding = nil
	if len(body) > 0 {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
		return out
	}
	out.Body = nil
	out.ContentLength = 0
	return out
}

func targetAddress(u *url.URL) (string, error) {
	host := u.Hostname()
	if host == "" {
		return "", fmt.Errorf("target URL has no host")
	}
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		default:
			return "", fmt.Errorf("unsupported target scheme %q", u.Scheme)
		}
	}
	return net.JoinHostPort(host, port), nil
}

type connReadCloser struct {
	io.ReadCloser
	conn net.Conn
}

func (c *connReadCloser) Close() error {
	err := c.ReadCloser.Close()
	if closeErr := c.conn.Close(); err == nil {
		err = closeErr
	}
	return err
}

// flushWriter flushes after every write so streamed bodies — server-sent
// events in particular — reach the client as they arrive instead of waiting
// for the net/http output buffer to fill.
type flushWriter struct {
	w http.ResponseWriter
}

func (fw flushWriter) Write(p []byte) (int, error) {
	n, err := fw.w.Write(p)
	if flusher, ok := fw.w.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func (s *Server) writeResponse(log *slog.Logger, w http.ResponseWriter, resp *http.Response) {
	stripHopByHop(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	if _, err := io.Copy(flushWriter{w: w}, resp.Body); err != nil {
		// The client sees a truncated body: nothing to retry and no health to
		// mutate, but the log attributes the mid-body drop to this request.
		log.Warn("response relay failed", "error_kind", logErrorKind(err), "error", logErrorValue(err))
	}
	resp.Body.Close()
}

// handleTunnel relays an inbound CONNECT tunnel through the SOCKS5 pool.
// Retries occur only before the SOCKS target connection succeeds. It loads
// one generation for the whole operation so route picks and health reports
// stay consistent across reloads.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request, log *slog.Logger) {
	gen := s.generation()
	settings := generationSettings(gen)
	start := time.Now()
	target := r.URL.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(r.URL.Host, "443")
	}
	logTarget := tunnelTargetLogValue(target)
	log.Debug("tunnel start", "target", logTarget)
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "tunneling unsupported", http.StatusInternalServerError)
		log.Error("tunnel unsupported", "target", logTarget, "error_kind", "server")
		return
	}
	clientConn, brw, err := hj.Hijack()
	if err != nil {
		log.Error("hijack failed", "target", logTarget, "error", logErrorValue(err))
		return
	}
	s.trackConn(clientConn)
	defer s.untrackConn(clientConn)

	var prefix []byte
	if n := brw.Reader.Buffered(); n > 0 {
		prefix = make([]byte, n)
		if _, err := io.ReadFull(brw.Reader, prefix); err != nil {
			clientConn.Close()
			return
		}
	}

	exclude := map[*pool.Proxy]bool{}
	var upstream net.Conn
	var chosen *pool.Proxy
	var attempts int
	for attempt := 0; attempt < settings.maxRetries; attempt++ {
		attempts = attempt + 1
		if r.Context().Err() != nil {
			log.Debug("tunnel canceled", "target", logTarget, "attempts", attempt)
			clientConn.Close()
			return
		}
		p := s.pick(gen, exclude)
		if p == nil {
			break
		}
		// The winning pick holds the route for the tunnel's whole lifetime;
		// earlier excluded attempts release when the handler ends.
		defer p.Release()
		up, err := s.dial(r.Context(), p.URL, target, settings.dialTimeout)
		if err != nil {
			if r.Context().Err() != nil {
				log.Debug("tunnel canceled", "target", logTarget, "attempts", attempts)
				clientConn.Close()
				return
			}
			switch {
			case isProxyDialError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn("upstream dial failed", "target", logTarget, "upstream", upstreamLogValue(p),
					"attempt", attempts, "error_kind", errorKindProxyConnect,
					"error", logErrorValue(err), "cooldown", cooldown.String())
				continue
			case isSocksHandshakeError(err):
				cooldown := gen.Pool.ReportFailure(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn("upstream handshake failed", "target", logTarget, "upstream", upstreamLogValue(p),
					"attempt", attempts, "error_kind", errorKindSocksConnect,
					"error", logErrorValue(err), "cooldown", cooldown.String())
				continue
			case isProxyAuthError(err):
				gen.Pool.ReportAuthBlocked(p, err)
				exclude[p] = true
				s.failovers.Add(1)
				log.Warn("upstream auth failed", "target", logTarget, "upstream", upstreamLogValue(p),
					"attempt", attempts, "error_kind", errorKindAuthRoute,
					"error", logErrorValue(err))
				continue
			default:
				clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				clientConn.Close()
				log.Warn("upstream setup failed", "target", logTarget, "upstream", upstreamLogValue(p),
					"attempt", attempts, "error_kind", logErrorKind(err), "error", logErrorValue(err),
					"duration", logDuration(time.Since(start)))
				return
			}
		}
		gen.Pool.ReportSuccess(p)
		upstream, chosen = up, p
		break
	}
	if upstream == nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		clientConn.Close()
		log.Warn("tunnel failed", "target", logTarget, "attempts", len(exclude),
			"error_kind", errorKindNoRoute, "duration", logDuration(time.Since(start)))
		return
	}
	if len(prefix) > 0 {
		upstream.Write(prefix) //nolint:errcheck // relay shutdown handles write failure
	}
	brw.Writer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n") //nolint:errcheck
	brw.Writer.Flush()                                                    //nolint:errcheck
	log.Info("tunnel", "target", logTarget, "upstream", upstreamLogValue(chosen),
		"attempts", attempts, "duration", logDuration(time.Since(start)))

	// Relay until either side ends the stream. Established tunnels carry no
	// health or retry semantics; the close record is the only trace of which
	// side ended the stream first and why.
	closes := make(chan relayResult, 2)
	go func() {
		n, err := io.Copy(clientConn, upstream)
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
	n, err := io.Copy(upstream, clientConn)
	closes <- relayResult{direction: relayToUpstream, bytes: n, err: err}
	upstream.Close()
	clientConn.Close() // unblocks the other direction
	first := <-closes
	second := <-closes // the forced close of the remaining side is an artifact
	recordTunnelClose(log, logTarget, chosen, start, first, second)
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
func recordTunnelClose(log *slog.Logger, target string, p *pool.Proxy, start time.Time, first, second relayResult) {
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
	args := []any{
		"target", target,
		"upstream", upstreamLogValue(p),
		"duration", logDuration(time.Since(start)),
		"client_to_upstream_bytes", toUpstream.bytes,
		"upstream_to_client_bytes", toClient.bytes,
		"close_reason", reason,
	}
	if first.err != nil {
		args = append(args, "error", logErrorValue(first.err))
	}
	if msg == "tunnel broken" {
		log.Warn(msg, args...)
		return
	}
	log.Debug(msg, args...)
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

// CloseTunnels closes hijacked client connections; http.Server.Shutdown does
// not track hijacked connections, so shutdown calls this after its grace period.
func (s *Server) CloseTunnels() {
	s.cmu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.cmu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// AdminMux serves the health and status endpoints for the admin listener.
func (s *Server) AdminMux() *http.ServeMux {
	return AdminMux(s.version, s.startTime, s.store, map[string]*Server{s.listener: s}, nil)
}

// AdminMux serves aggregate health/status for all proxy listener views sharing
// a runtime generation store. Existing status fields remain global totals;
// listeners adds safe per-listener counters. rotations reports completed
// manual-route IP rotations from the rotation engine (nil omits the field);
// failovers counts in-band route fallbacks and stays a listener metric. The
// pool snapshot comes from the current generation so /status changes
// atomically with serving behavior.
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
		status := map[string]any{
			"version":   version,
			"uptime":    time.Since(started).Truncate(time.Second).String(),
			"requests":  requests,
			"failovers": failovers,
			"listeners": perListener,
			"pool":      store.Load().Pool.Snapshot(),
		}
		if rotations != nil {
			status["rotations"] = rotations()
		}
		json.NewEncoder(w).Encode(status)
	})
	return mux
}
