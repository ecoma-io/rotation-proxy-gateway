package e2e_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"
)

// The inbound listeners speak HTTP forward-proxy: CONNECT opens a
// byte-transparent tunnel, and an absolute-form request is forwarded to its
// origin in origin form. These helpers are the test-side client. Outbound
// stays SOCKS5H, so hostnames are never resolved by the gateway — a target
// host in a CONNECT or absolute-form URL reaches the route untouched.

// proxyTransport returns an http.Transport routed through a gateway listener
// as an HTTP forward proxy. Go's client then emits CONNECT for https:// targets
// and absolute-form for http:// ones, so a single transport exercises both
// ingress shapes.
func proxyTransport(proxyAddr string, insecureTLS bool) *http.Transport {
	t := &http.Transport{
		Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
	}
	if insecureTLS {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only target
	}
	return t
}

// connectTunnel connects through a gateway listener to targetAddr (host:port)
// and returns the established tunnel.
func connectTunnel(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetAddr, targetAddr)
	if _, err := conn.Write([]byte(req)); err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	// A bufio.Reader may pull the 200 line plus the first tunneled bytes in one
	// read, so the tunnel reads through it: handing back the bare conn would
	// drop whatever it already buffered.
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = conn.Close()
		return nil, &httpStatusError{status: resp.StatusCode}
	}
	_ = resp.Body.Close()
	_ = conn.SetDeadline(time.Time{})
	return &bufferedConn{Conn: conn, r: br}, nil
}

// bufferedConn is a net.Conn whose reads drain the bufio.Reader that consumed
// the CONNECT response head first, so no tunneled byte is lost.
type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

// CloseWrite preserves TCP half-close support through the buffered wrapper.
// The e2e client always dials TCP, and forwarding it lets teardown tests keep
// asserting that an upstream reply survives a client write-side FIN.
func (c *bufferedConn) CloseWrite() error {
	return c.Conn.(*net.TCPConn).CloseWrite()
}

// httpStatusError reports a gateway ingress refusal by status code, so tests
// that assert on a reject can read the code instead of matching message text.
type httpStatusError struct {
	status int
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("gateway rejected the request with status %d (%s)",
		e.status, http.StatusText(e.status))
}

// httpStatusOf returns the ingress status carried by err, or 0 when err is not
// a gateway status rejection.
func httpStatusOf(err error) int {
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.status
	}
	return 0
}

// isHTTPGatewayFailure reports the two contract statuses a route-selection
// failure may produce: an upstream pre-tunnel failure is 502, while no_route
// and retry_exhausted are 503. Other HTTP rejects have their own precise
// tests, so route-health coverage does not accidentally accept them here.
func isHTTPGatewayFailure(status int) bool {
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable
}

// tunnelFor establishes one inbound CONNECT tunnel through a gateway listener,
// failing the test on any protocol or reply error. Callers speak HTTP, TLS, or
// raw bytes over the returned connection.
func tunnelFor(t testing.TB, proxyAddr, targetAddr string) net.Conn {
	t.Helper()
	conn, err := connectTunnel(context.Background(), proxyAddr, targetAddr)
	if err != nil {
		t.Fatalf("CONNECT tunnel to %s via %s: %v", targetAddr, proxyAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// httpProbeResult is one raw ingress exchange: the parsed response head plus
// the bytes the reader buffered past it.
type httpProbeResult struct {
	StatusCode int
	Status     string
	Proto      string
	Header     http.Header
	Rest       []byte
}

// httpProbe writes request verbatim to a gateway listener and parses the
// response head. method is the request's own method, which
// http.ReadResponse needs to frame the body correctly. A raw request string
// keeps the malformed-request cases expressible.
func httpProbe(t testing.TB, proxyAddr, method, request string) (httpProbeResult, error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(request)); err != nil {
		return httpProbeResult{}, err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		return httpProbeResult{}, err
	}
	rest := make([]byte, br.Buffered())
	if len(rest) > 0 {
		if _, err := io.ReadFull(br, rest); err != nil {
			return httpProbeResult{}, err
		}
	}
	return httpProbeResult{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Proto:      resp.Proto,
		Header:     resp.Header.Clone(),
		Rest:       rest,
	}, nil
}
