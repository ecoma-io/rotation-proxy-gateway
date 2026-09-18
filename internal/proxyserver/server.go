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

// Server is the inbound HTTP forward-proxy handler.
type Server struct {
	pool    *pool.Pool
	cfg     *config.Config
	log     *slog.Logger
	version string

	cmu   sync.Mutex
	conns map[net.Conn]struct{}

	startTime time.Time
	requests  atomic.Uint64
	rotations atomic.Uint64
}

// New builds a proxy Server.
func New(pl *pool.Pool, cfg *config.Config, log *slog.Logger, version string) *Server {
	return &Server{
		pool:      pl,
		cfg:       cfg,
		log:       log,
		version:   version,
		conns:     map[net.Conn]struct{}{},
		startTime: time.Now(),
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

// handleHTTP forwards a plain absolute-form request through a SOCKS5 route.
func (s *Server) handleHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	if !r.URL.IsAbs() || r.Host == "" {
		http.Error(w, "proxy request requires an absolute URI", http.StatusBadRequest)
		return
	}
	if r.URL.Scheme != "http" && r.URL.Scheme != "https" {
		http.Error(w, "proxy request requires an http or https URI", http.StatusBadRequest)
		return
	}

	// Buffer the body up to the cap. When it is larger, its buffered prefix is
	// replayable only until a route succeeds in establishing SOCKS setup.
	var body []byte
	streamMode := false
	b, err := io.ReadAll(io.LimitReader(r.Body, s.cfg.MaxBodyBuffer+1))
	if err != nil {
		r.Body.Close()
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}
	if int64(len(b)) > s.cfg.MaxBodyBuffer {
		streamMode = true
	} else {
		body = b
		r.Body.Close()
	}
	stripHopByHop(r.Header)

	exclude := map[*pool.Proxy]bool{}
	for attempt := 0; attempt < s.cfg.MaxRetries; attempt++ {
		if r.Context().Err() != nil {
			return
		}
		p := s.pool.Pick(exclude)
		if p == nil {
			break
		}
		out := buildOutbound(r, body)
		if streamMode {
			out.Body = io.NopCloser(io.MultiReader(bytes.NewReader(b), r.Body))
			out.ContentLength = r.ContentLength
		}
		resp, err := s.roundTripViaSOCKS(r.Context(), p, out)
		if streamMode && !isProxyDialError(err) && !isProxyAuthError(err) {
			r.Body.Close()
		}
		if err != nil {
			switch {
			case isProxyDialError(err):
				s.pool.ReportFailure(p, err)
				exclude[p] = true
				s.rotations.Add(1)
				s.log.Warn("SOCKS endpoint dial failed", "proxy", p.URL.Host, "target", r.URL.Host, "err", err.Error())
				continue
			case isProxyAuthError(err):
				s.pool.ReportAuthBlocked(p, err)
				exclude[p] = true
				s.rotations.Add(1)
				s.log.Warn("SOCKS route authentication failed", "proxy", p.URL.Host, "target", r.URL.Host, "err", err.Error())
				continue
			default:
				if r.Context().Err() != nil {
					return
				}
				http.Error(w, "upstream SOCKS setup failed", http.StatusBadGateway)
				s.log.Warn("request failed after SOCKS endpoint dial", "proxy", p.URL.Host, "target", r.URL.Host, "err", err.Error())
				return
			}
		}

		if streamMode {
			r.Body.Close()
		}
		s.pool.ReportSuccess(p)
		s.writeResponse(w, resp)
		s.log.Info("request", "method", r.Method, "target", r.URL.Host, "via", p.URL.Host,
			"status", resp.StatusCode, "attempts", attempt+1, "dur", time.Since(start).Truncate(time.Millisecond).String())
		return
	}

	if streamMode {
		r.Body.Close()
	}
	http.Error(w, "no usable upstream SOCKS routes", http.StatusBadGateway)
	s.log.Warn("request failed", "target", r.URL.Host, "dur", time.Since(start).Truncate(time.Millisecond).String())
}

// buildOutbound clones the client request for a route attempt; body is replayed
// from memory when non-nil.
func buildOutbound(r *http.Request, body []byte) *http.Request {
	out := r.Clone(r.Context())
	out.RequestURI = "" // http.Request.Write derives origin-form from URL.
	out.Close = true    // each SOCKS tunnel is scoped to this request.
	if body != nil {
		out.Body = io.NopCloser(bytes.NewReader(body))
		out.ContentLength = int64(len(body))
	} else {
		out.Body = nil
		out.ContentLength = 0
	}
	return out
}

// roundTripViaSOCKS establishes a SOCKS tunnel and exchanges one HTTP request.
// Only errors returned from dialVia can be ProxyDialError or ProxyAuthError.
func (s *Server) roundTripViaSOCKS(ctx context.Context, p *pool.Proxy, out *http.Request) (*http.Response, error) {
	target, err := targetAddress(out.URL)
	if err != nil {
		return nil, err
	}
	conn, err := dialVia(ctx, p.URL, target, s.cfg.ConnectTimeout)
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
			InsecureSkipVerify: s.cfg.TargetTLSInsecure,
		})
		hsCtx, cancel := context.WithTimeout(ctx, s.cfg.ConnectTimeout)
		err := tlsConn.HandshakeContext(hsCtx)
		cancel()
		if err != nil {
			return fail(fmt.Errorf("target TLS handshake: %w", err))
		}
		conn = tlsConn
	}
	if err := out.Write(conn); err != nil {
		return fail(fmt.Errorf("write target request: %w", err))
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), out)
	if err != nil {
		return fail(fmt.Errorf("read target response: %w", err))
	}
	resp.Body = &connReadCloser{ReadCloser: resp.Body, conn: conn}
	return resp, nil
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

// handleTunnel relays an inbound CONNECT tunnel through the SOCKS5 pool.
// Retries occur only before the SOCKS target connection succeeds.
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
	for attempt := 0; attempt < s.cfg.MaxRetries; attempt++ {
		attempts = attempt + 1
		if r.Context().Err() != nil {
			clientConn.Close()
			return
		}
		p := s.pool.Pick(exclude)
		if p == nil {
			break
		}
		up, err := dialVia(r.Context(), p.URL, target, s.cfg.ConnectTimeout)
		if err != nil {
			switch {
			case isProxyDialError(err):
				s.pool.ReportFailure(p, err)
				exclude[p] = true
				s.rotations.Add(1)
				s.log.Warn("SOCKS endpoint dial failed", "proxy", p.URL.Host, "target", target, "err", err.Error())
				continue
			case isProxyAuthError(err):
				s.pool.ReportAuthBlocked(p, err)
				exclude[p] = true
				s.rotations.Add(1)
				s.log.Warn("SOCKS route authentication failed", "proxy", p.URL.Host, "target", target, "err", err.Error())
				continue
			default:
				clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
				clientConn.Close()
				s.log.Warn("tunnel failed after SOCKS endpoint dial", "proxy", p.URL.Host, "target", target, "err", err.Error())
				return
			}
		}
		s.pool.ReportSuccess(p)
		upstream, chosen = up, p
		break
	}
	if upstream == nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		clientConn.Close()
		s.log.Warn("tunnel failed", "target", target, "attempts", attempts, "dur", time.Since(start).Truncate(time.Millisecond).String())
		return
	}
	if len(prefix) > 0 {
		upstream.Write(prefix) //nolint:errcheck // relay shutdown handles write failure
	}
	brw.Writer.WriteString("HTTP/1.1 200 Connection established\r\n\r\n") //nolint:errcheck
	brw.Writer.Flush()                                                    //nolint:errcheck
	s.log.Info("tunnel", "target", target, "via", chosen.URL.Host, "attempts", attempts)

	go func() {
		io.Copy(clientConn, upstream) //nolint:errcheck // tunnel close is expected
		clientConn.Close()
	}()
	io.Copy(upstream, clientConn) //nolint:errcheck // tunnel close is expected
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
// not track hijacked connections, so shutdown calls this after its grace period.
func (s *Server) CloseTunnels() {
	s.cmu.Lock()
	defer s.cmu.Unlock()
	for c := range s.conns {
		c.Close()
	}
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
