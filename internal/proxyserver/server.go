// Package proxyserver implements the HTTP forward proxy: plain absolute-form
// requests and CONNECT tunneling, each rotated across the proxy pool with
// retries on failure.
package proxyserver

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"proxy-auto-rotate-forwarder/internal/config"
	"proxy-auto-rotate-forwarder/internal/pool"
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
	if tokens := h.Get("Connection"); tokens != "" {
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

// retryStatus reports whether a target response should trigger rotation to
// the next proxy: request timeout, rate limit, or server error.
func retryStatus(code int) bool {
	return code == http.StatusRequestTimeout ||
		code == http.StatusTooManyRequests ||
		code >= 500
}

// Server is the forward proxy http.Handler.
type Server struct {
	pool    *pool.Pool
	cfg     *config.Config
	log     *slog.Logger
	version string

	tmu        sync.Mutex
	transports map[string]*http.Transport

	cmu   sync.Mutex
	conns map[net.Conn]struct{}

	startTime time.Time
	requests  atomic.Uint64
	rotations atomic.Uint64
}

// New builds a proxy Server.
func New(pl *pool.Pool, cfg *config.Config, log *slog.Logger, version string) *Server {
	return &Server{
		pool:       pl,
		cfg:        cfg,
		log:        log,
		version:    version,
		transports: map[string]*http.Transport{},
		conns:      map[net.Conn]struct{}{},
		startTime:  time.Now(),
	}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests.Add(1)
	if r.Method == http.MethodConnect {
		s.handleTunnel(w, r)
		return
	}
	s.handleHTTP(w, r)
}

// handleHTTP forwards a plain absolute-form request through the pool.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !r.URL.IsAbs() || r.Host == "" {
		http.Error(w, "proxy request requires an absolute URI", http.StatusBadRequest)
		return
	}

	// Buffer the body (up to the cap) so requests can replay on rotation.
	var body []byte
	streamMode := false
	b, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBuffer+1))
	if err != nil {
		r.Body.Close()
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if int64(len(b)) > s.cfg.MaxBodyBuffer {
		streamMode = true // body streamed once; replay impossible
	} else {
		body = b
		r.Body.Close()
	}
	stripHopByHop(r.Header)

	attempts := s.cfg.MaxRetries
	if streamMode {
		attempts = 1
	}
	exclude := map[*pool.Proxy]bool{}
	var lastResp *http.Response
	var lastErr error
	var lastBody []byte

	for attempt := 0; attempt < attempts; attempt++ {
		p := s.pool.Pick(exclude)
		if p == nil {
			break
		}
		out := buildOutbound(r, body)
		if streamMode {
			out.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
			out.ContentLength = r.ContentLength
		}
		resp, err := s.transportFor(p).RoundTrip(out)
		if streamMode {
			r.Body.Close()
		}
		if err != nil {
			lastErr = err
			s.pool.ReportFailure(p, err)
			exclude[p] = true
			s.rotations.Add(1)
			s.log.Warn("upstream failed", "proxy", p.URL.Host, "target", r.URL.Host, "err", err.Error())
			continue
		}
		if retryStatus(resp.StatusCode) {
			lastResp, lastErr = resp, nil
			lastBody, _ = io.ReadAll(io.LimitReader(resp.Body, 4<<20))
			resp.Body.Close()
			s.pool.ReportFailure(p, fmt.Errorf("target status %d", resp.StatusCode))
			exclude[p] = true
			s.rotations.Add(1)
			s.log.Warn("rotating on target status", "proxy", p.URL.Host, "target", r.URL.Host, "status", resp.StatusCode)
			continue
		}
		s.pool.ReportSuccess(p)
		s.writeResponse(w, resp)
		s.log.Info("request",
			"method", r.Method, "target", r.URL.Host, "via", p.URL.Host,
			"status", resp.StatusCode, "attempts", attempt+1, "dur", time.Since(start).Truncate(time.Millisecond).String())
		return
	}

	if lastResp != nil {
		lastResp.Body = io.NopCloser(bytes.NewReader(lastBody))
		if lastResp.ContentLength != int64(len(lastBody)) {
			lastResp.Header.Del("Content-Length")
		}
		s.writeResponse(w, lastResp)
		s.log.Warn("exhausted on retryable status",
			"target", r.URL.Host, "status", lastResp.StatusCode, "attempts", attempts,
			"dur", time.Since(start).Truncate(time.Millisecond).String())
		return
	}
	msg := "all upstream proxies failed"
	if lastErr != nil {
		msg = msg + ": " + lastErr.Error()
	}
	http.Error(w, msg, http.StatusBadGateway)
	s.log.Warn("request failed", "target", r.URL.Host, "attempts", attempts,
		"dur", time.Since(start).Truncate(time.Millisecond).String())
}

// buildOutbound clones the client request for one rotation attempt; body
// (nil for streaming) is replayed from the in-memory buffer.
func buildOutbound(r *http.Request, body []byte) *http.Request {
	out := r.Clone(r.Context())
	out.RequestURI = "" // required by http.Transport
	out.Close = false
	if body != nil {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
	} else {
		out.Body = nil
		out.ContentLength = 0
	}
	return out
}

func (s *Server) writeResponse(w http.ResponseWriter, resp *http.Response) {
	stripHopByHop(resp.Header)
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
	resp.Body.Close()
}

// handleTunnel relays a CONNECT tunnel through the pool. Retries happen only
// while the tunnel is being established; once "200" is sent, bytes flow
// verbatim with no total deadline.
func (s *Server) handleTunnel(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	target := r.URL.Host
	if _, _, err := net.SplitHostPort(target); err != nil {
		target = net.JoinHostPort(r.URL.Host, "443")
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "tunneling unsupported", http.StatusInternalServerError)
		return
	}
	clientConn, brw, err := hj.Hijack()
	if err != nil {
		s.log.Error("hijack failed", "err", err.Error())
		return
	}
	s.trackConn(clientConn)
	defer s.untrackConn(clientConn)

	// Data pipelined with CONNECT (rare, but legal).
	var prefix []byte
	if n := brw.Reader.Buffered(); n > 0 {
		prefix = make([]byte, n)
		io.ReadFull(brw.Reader, prefix)
	}

	exclude := map[*pool.Proxy]bool{}
	var upstream net.Conn
	var chosen *pool.Proxy
	var attempts int
	for attempt := 0; attempt < s.cfg.MaxRetries; attempt++ {
		attempts = attempt + 1
		p := s.pool.Pick(exclude)
		if p == nil {
			break
		}
		up, err := dialVia(r.Context(), p.URL, target, s.cfg.ConnectTimeout, s.cfg.UpstreamTLSInsecure)
		if err != nil {
			s.pool.ReportFailure(p, err)
			exclude[p] = true
			s.rotations.Add(1)
			s.log.Warn("tunnel upstream failed", "proxy", p.URL.Host, "target", target, "err", err.Error())
			continue
		}
		s.pool.ReportSuccess(p)
		upstream, chosen = up, p
		break
	}
	if upstream == nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		clientConn.Close()
		s.log.Warn("tunnel failed", "target", target, "attempts", attempts,
			"dur", time.Since(start).Truncate(time.Millisecond).String())
		return
	}
	if prefix != nil {
		upstream.Write(prefix)
	}
	brw.Writer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n")
	brw.Writer.Flush()
	s.log.Info("tunnel", "target", target, "via", chosen.URL.Host, "attempts", attempts)

	go func() {
		io.Copy(clientConn, upstream)
		clientConn.Close()
	}()
	io.Copy(upstream, clientConn)
	upstream.Close()
	clientConn.Close() // unblocks the other direction
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
// not track hijacked conns, so shutdown calls this after its grace period.
func (s *Server) CloseTunnels() {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	for c := range s.conns {
		c.Close()
	}
}

func (s *Server) transportFor(p *pool.Proxy) *http.Transport {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	key := p.URL.String()
	if tr, ok := s.transports[key]; ok {
		return tr
	}
	tr := &http.Transport{
		Proxy:               http.ProxyURL(p.URL),
		DialContext:         (&net.Dialer{Timeout: s.cfg.ConnectTimeout}).DialContext,
		TLSHandshakeTimeout: s.cfg.ConnectTimeout,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: s.cfg.UpstreamTLSInsecure},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
	}
	s.transports[key] = tr
	return tr
}

// ResetTransports drops cached upstream transports (after a pool reload);
// their idle connections are closed.
func (s *Server) ResetTransports() {
	s.tmu.Lock()
	defer s.tmu.Unlock()
	for _, tr := range s.transports {
		tr.CloseIdleConnections()
	}
	s.transports = map[string]*http.Transport{}
}

// AdminMux serves the health and status endpoints for the admin listener.
func (s *Server) AdminMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		io.WriteString(w, "ok\n")
	})
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"version":   s.version,
			"uptime":    time.Since(s.startTime).Truncate(time.Second).String(),
			"requests":  s.requests.Load(),
			"rotations": s.rotations.Load(),
			"pool":      s.pool.Snapshot(),
		})
	})
	return mux
}
