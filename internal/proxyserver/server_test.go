package proxyserver

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func captureLogger(w io.Writer, level slog.Level) *slog.Logger {
	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

type safeLogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *safeLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *safeLogBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

func waitForLog(t *testing.T, logs *safeLogBuffer, want string) string {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		output := logs.String()
		if strings.Contains(output, want) {
			return output
		}
		if time.Now().After(deadline) {
			t.Fatalf("logs missing %q:\n%s", want, output)
		}
		time.Sleep(time.Millisecond)
	}
}

func defaultRuntime() *config.RuntimeConfig {
	return &config.RuntimeConfig{
		MaxRetries:        3,
		DialTimeout:       2 * time.Second,
		MaxBodyBuffer:     64 << 20,
		CooldownBase:      30 * time.Second,
		CooldownMax:       time.Minute,
		TargetTLSInsecure: false,
	}
}

func mixedRoutes(urls ...*url.URL) []config.RouteSpec {
	routes := make([]config.RouteSpec, 0, len(urls))
	for _, u := range urls {
		routes = append(routes, config.RouteSpec{URL: u, Kind: config.EgressV4})
	}
	return routes
}

func newRuntimeServer(pl *pool.Pool, runtime *config.RuntimeConfig, log *slog.Logger) *Server {
	// The store shares the test pool pointer so existing health assertions on
	// pl keep observing the serving pool until a test publishes a new
	// generation (which installs a reconfigured pool snapshot).
	return NewRuntime(pool.NewStore(runtime, pl), log, "test", "mixed", config.EgressV4, config.EgressV6)
}

func newForwarderCfg(t *testing.T, pl *pool.Pool, runtime *config.RuntimeConfig) *httptest.Server {
	return newForwarderCfgLogger(t, pl, runtime, testLogger())
}

func newForwarderCfgLogger(t *testing.T, pl *pool.Pool, runtime *config.RuntimeConfig, log *slog.Logger) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(newRuntimeServer(pl, runtime, log))
	t.Cleanup(ts.Close)
	return ts
}

func newForwarder(t *testing.T, socks ...*fakeSocks) (*httptest.Server, *pool.Pool) {
	t.Helper()
	urls := make([]*url.URL, 0, len(socks))
	for _, fs := range socks {
		urls = append(urls, fs.URL)
	}
	pl := pool.NewRoutes(mixedRoutes(urls...), 30*time.Second, time.Minute)
	return newForwarderCfg(t, pl, defaultRuntime()), pl
}

func proxiedClient(t *testing.T, proxyURL string) *http.Client {
	t.Helper()
	pu, err := url.Parse(proxyURL)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(pu)},
		Timeout:   10 * time.Second,
	}
}

func startStatusTarget(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Proxy-Authorization", "must-not-reach-client")
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func startEchoBodyTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		w.Write(b)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func TestStripHopByHop(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "X-Drop, Keep-Alive")
	h.Add("Connection", " x-second-drop ")
	h.Set("X-Drop", "yes")
	h.Set("X-Second-Drop", "yes")
	h.Set("X-Keep", "1")
	h.Set("Proxy-Authorization", "secret")
	stripHopByHop(h)
	for _, name := range []string{"X-Drop", "X-Second-Drop", "Keep-Alive", "Proxy-Authorization", "Connection"} {
		if h.Get(name) != "" {
			t.Errorf("%s survived strip", name)
		}
	}
	if h.Get("X-Keep") != "1" {
		t.Error("X-Keep should have been kept")
	}
}

func TestPlainHTTPForwardThroughSOCKS(t *testing.T) {
	target := startEchoTarget(t)
	fs := startSocks5Proxy(t, socksOptions{})
	ts, pl := newForwarder(t, fs)

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "dial-via-ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if snap := pl.Snapshot(); snap[0].Successes != 1 || snap[0].Failures != 0 || snap[0].AuthFailures != 0 {
		t.Fatalf("pool snapshot = %+v", snap[0])
	}
}

// Only absolute-form http/https requests are forwardable. Anything else is
// rejected before a route is considered: 400, a bad_request log line, and an
// untouched pool.
func TestInvalidInboundRequestsAreRejectedBeforeDialing(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs, slog.LevelDebug))

	for _, tc := range []struct{ name, target string }{
		{"origin-form path", "/only-a-path"},
		{"unsupported scheme", "ftp://example.test/file"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			rec := httptest.NewRecorder()
			s.ServeHTTP(rec, req)
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status=%d, want 400", rec.Code)
			}
			if body := rec.Body.String(); !strings.Contains(body, "proxy request requires") {
				t.Fatalf("body=%q, want a rejection message", body)
			}
		})
	}
	if got := len(fs.hits); got != 0 {
		t.Fatalf("SOCKS dialed %d times for rejected requests, want 0", got)
	}
	if snap := pl.Snapshot()[0]; snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("rejected requests changed pool state: %+v", snap)
	}
	if out := logs.String(); strings.Count(out, "error_kind=bad_request") != 2 {
		t.Fatalf("logs = %s, want one bad_request line per rejected request", out)
	}
}

func TestHTTPSRoundTripThroughSOCKS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "https-via-socks")
	}))
	defer target.Close()
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	cfg := defaultRuntime()
	cfg.TargetTLSInsecure = true
	s := newRuntimeServer(pl, cfg, testLogger())

	out, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.roundTripWithSettings(context.Background(), pl.PickFor(nil, nil), out, s.settings())
	if err != nil {
		t.Fatalf("roundTripWithSettings: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "https-via-socks" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestTargetStatusesPassThroughWithoutRotation(t *testing.T) {
	for _, status := range []int{http.StatusProxyAuthRequired, http.StatusRequestTimeout, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			target := startStatusTarget(t, status, "target-status")
			fs := startSocks5Proxy(t, socksOptions{})
			ts, pl := newForwarder(t, fs)

			resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != status || string(body) != "target-status" {
				t.Fatalf("status=%d body=%q", resp.StatusCode, body)
			}
			if resp.Header.Get("Proxy-Authorization") != "" {
				t.Fatal("Proxy-Authorization response header was forwarded")
			}
			snap := pl.Snapshot()[0]
			if snap.Successes != 1 || snap.Failures != 0 || snap.AuthFailures != 0 {
				t.Fatalf("status %d changed route health: %+v", status, snap)
			}
			if got := len(fs.hits); got != 1 {
				t.Fatalf("SOCKS attempts = %d, want 1", got)
			}
		})
	}
}

func TestRotatesOnEndpointDialFailure(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := &url.URL{Scheme: "socks5", Host: closed.Addr().String()}
	closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	target := startEchoTarget(t)
	pl := pool.NewRoutes(mixedRoutes(deadURL, good.URL), 30*time.Second, time.Minute)
	ts := newForwarderCfg(t, pl, defaultRuntime())

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	snap := pl.Snapshot()
	if snap[0].Failures != 1 || snap[0].Available || snap[1].Successes != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestLogsCorrelateDialFallbackAndRedactCredentials(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := &url.URL{Scheme: "socks5", User: url.UserPassword("route-user", "route-password"), Host: closed.Addr().String()}
	closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	target := startEchoTarget(t)
	pl := pool.NewRoutes(mixedRoutes(deadURL, good.URL), 30*time.Second, time.Minute)
	var logs safeLogBuffer
	ts := newForwarderCfgLogger(t, pl, defaultRuntime(), captureLogger(&logs, slog.LevelDebug))

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}

	output := logs.String()
	for _, want := range []string{
		"request_id=1",
		"msg=\"upstream dial failed\"",
		"error_kind=proxy_connect",
		"cooldown=30s",
		"msg=request",
		"attempts=2",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("logs missing %q:\n%s", want, output)
		}
	}
	for _, secret := range []string{"route-user", "route-password"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked %q:\n%s", secret, output)
		}
	}
}

func TestAuthFailureFallsBackWithoutDialCooldown(t *testing.T) {
	bad := startSocks5Proxy(t, socksOptions{user: "u", pass: "p"})
	good := startSocks5Proxy(t, socksOptions{})
	target := startEchoTarget(t)
	ts, pl := newForwarder(t, bad, good)

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	snap := pl.Snapshot()
	if !snap[0].AuthBlocked || snap[0].AuthFailures != 1 || snap[0].Failures != 0 || snap[0].CooldownFor != "0s" {
		t.Fatalf("bad auth state = %+v", snap[0])
	}
	if snap[1].Successes != 1 {
		t.Fatalf("good route state = %+v", snap[1])
	}
}

func TestRotatesOnHandshakeFailure(t *testing.T) {
	reject := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	good := startSocks5Proxy(t, socksOptions{})
	target := startEchoTarget(t)
	pl := pool.NewRoutes(mixedRoutes(reject.URL, good.URL), 30*time.Second, time.Minute)
	ts := newForwarderCfg(t, pl, defaultRuntime())

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d, want 200", resp.StatusCode)
	}
	snap := pl.Snapshot()
	if snap[0].Failures != 1 || snap[0].Available || snap[1].Successes != 1 {
		t.Fatalf("snapshot = %+v", snap)
	}
}

func TestSOCKSHandshakeFailureExhaustsToNoRoute(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	ts, pl := newForwarder(t, fs)

	resp, err := proxiedClient(t, ts.URL).Get("http://example.com/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway || string(body) != "no usable upstream SOCKS routes\n" {
		t.Fatalf("status=%d body=%q, want sanitized no-route 502", resp.StatusCode, body)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 0 || snap.AuthFailures != 0 || snap.Failures != 1 || snap.Available {
		t.Fatalf("handshake failure did not record route health: %+v", snap)
	}
	if got := len(fs.hits); got != 1 {
		t.Fatalf("SOCKS attempts = %d, want 1", got)
	}
}

func TestPOSTReplaysOnlyAfterDialFailure(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := &url.URL{Scheme: "socks5", Host: closed.Addr().String()}
	closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(deadURL, good.URL), 30*time.Second, time.Minute)
	ts := newForwarderCfg(t, pl, defaultRuntime())

	resp, err := proxiedClient(t, ts.URL).Post("http://"+startEchoBodyTarget(t)+"/", "text/plain", strings.NewReader("payload-123"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "payload-123" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

type stagedBody struct {
	first   []byte
	release <-chan struct{}
	rest    []byte

	mu       sync.Mutex
	read     bool
	released bool
}

func (b *stagedBody) Read(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.read {
		b.read = true
		n := copy(p, b.first)
		b.first = b.first[n:]
		return n, nil
	}
	if !b.released {
		b.mu.Unlock()
		<-b.release
		b.mu.Lock()
		b.released = true
	}
	if len(b.rest) == 0 {
		return 0, io.EOF
	}
	n := copy(p, b.rest)
	b.rest = b.rest[n:]
	return n, nil
}

func (b *stagedBody) Close() error { return nil }

func TestKnownLargePOSTStreamsBeforeFullBodyIsAvailable(t *testing.T) {
	allowRest := make(chan struct{})
	payload := "streamed-payload"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		w.Write(b)
	}))
	defer target.Close()
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &url.URL{Scheme: "socks5", Host: closed.Addr().String()}
	closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), time.Second, time.Minute)
	cfg := defaultRuntime()
	cfg.MaxBodyBuffer = 4
	forwarder := newRuntimeServer(pl, cfg, testLogger())

	body := &stagedBody{first: []byte(payload[:4]), rest: []byte(payload[4:]), release: allowRest}
	req := httptest.NewRequest(http.MethodPost, target.URL+"/", body)
	req.ContentLength = int64(len(payload))
	rw := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		forwarder.ServeHTTP(rw, req)
		close(done)
	}()

	select {
	case <-good.hits:
	case <-time.After(time.Second):
		t.Fatal("SOCKS setup did not begin before the full body was available")
	}
	close(allowRest)
	<-done

	resp := rw.Result()
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(got) != payload {
		t.Fatalf("status=%d body=%q", resp.StatusCode, got)
	}
	snap := pl.Snapshot()
	if snap[0].Failures != 1 || snap[1].Successes != 1 {
		t.Fatalf("pool state=%+v", snap)
	}
}

func TestRequestBodyBufferBoundaries(t *testing.T) {
	for _, tc := range []struct {
		name string
		cap  int64
		body string
	}{
		{"zero streams nonempty body", 0, "x"},
		{"exact cap is replayable", 3, "abc"},
		{"above cap streams", 3, "abcd"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fs := startSocks5Proxy(t, socksOptions{})
			pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
			cfg := defaultRuntime()
			cfg.MaxBodyBuffer = tc.cap
			ts := newForwarderCfg(t, pl, cfg)

			resp, err := proxiedClient(t, ts.URL).Post("http://"+startEchoBodyTarget(t)+"/", "text/plain", strings.NewReader(tc.body))
			if err != nil {
				t.Fatalf("POST: %v", err)
			}
			got, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(got) != tc.body {
				t.Fatalf("status=%d body=%q, want %q", resp.StatusCode, got, tc.body)
			}
		})
	}
}

func TestBufferedRequestFraming(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch} {
		t.Run(method+" empty", func(t *testing.T) {
			r := httptest.NewRequest(method, "http://example.test/", nil)
			out := buildOutbound(r, []byte{})
			var wire bytes.Buffer
			if err := out.Write(&wire); err != nil {
				t.Fatalf("write outbound request: %v", err)
			}
			got := wire.String()
			if !strings.Contains(got, "Content-Length: 0\r\n") {
				t.Fatalf("missing zero content length:\n%s", got)
			}
			if strings.Contains(got, "Transfer-Encoding: chunked") {
				t.Fatalf("empty request was chunked:\n%s", got)
			}
		})
	}
	t.Run("GET no body", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		out := buildOutbound(r, nil)
		var wire bytes.Buffer
		if err := out.Write(&wire); err != nil {
			t.Fatalf("write outbound request: %v", err)
		}
		got := wire.String()
		for _, unexpected := range []string{"Content-Length:", "Transfer-Encoding:"} {
			if strings.Contains(got, unexpected) {
				t.Fatalf("bodyless GET contained %q:\n%s", unexpected, got)
			}
		}
	})
	t.Run("chunked body without trailers", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
		r.TransferEncoding = []string{"chunked"}
		out := buildOutbound(r, []byte("abc"))
		var wire bytes.Buffer
		if err := out.Write(&wire); err != nil {
			t.Fatalf("write outbound request: %v", err)
		}
		got := wire.String()
		if !strings.Contains(got, "Content-Length: 3\r\n") || strings.Contains(got, "Transfer-Encoding:") {
			t.Fatalf("chunked buffered request was not normalized:\n%s", got)
		}
	})
	t.Run("empty body with trailer", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "http://example.test/", nil)
		r.TransferEncoding = []string{"chunked"}
		r.Trailer = http.Header{"X-Checksum": {"done"}}
		out := buildOutbound(r, []byte{})
		var wire bytes.Buffer
		if err := out.Write(&wire); err != nil {
			t.Fatalf("write outbound request: %v", err)
		}
		got := wire.String()
		for _, want := range []string{"Transfer-Encoding: chunked\r\n", "Trailer: X-Checksum\r\n", "0\r\nX-Checksum: done\r\n\r\n"} {
			if !strings.Contains(got, want) {
				t.Fatalf("trailer request missing %q:\n%s", want, got)
			}
		}
	})
}

type trailerReadCloser struct {
	body    []byte
	trailer http.Header
	done    bool
}

func (b *trailerReadCloser) Read(p []byte) (int, error) {
	if len(b.body) > 0 {
		n := copy(p, b.body)
		b.body = b.body[n:]
		return n, nil
	}
	if !b.done {
		b.done = true
		b.trailer.Set("X-Checksum", "streamed")
	}
	return 0, io.EOF
}

func (b *trailerReadCloser) Close() error { return nil }

func TestStreamedChunkedBodyForwardsTrailers(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		fmt.Fprintf(w, "%s:%s", body, r.Trailer.Get("X-Checksum"))
	}))
	defer target.Close()
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	cfg := defaultRuntime()
	cfg.MaxBodyBuffer = 3
	s := newRuntimeServer(pl, cfg, testLogger())

	trailer := http.Header{"X-Checksum": nil}
	body := &trailerReadCloser{body: []byte("abcd"), trailer: trailer}
	req := httptest.NewRequest(http.MethodPost, target.URL+"/", body)
	req.ContentLength = -1
	req.TransferEncoding = []string{"chunked"}
	req.Trailer = trailer
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	got, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(got) != "abcd:streamed" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, got)
	}
}

func TestStreamedPOSTReplaysAfterDialFallback(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &url.URL{Scheme: "socks5", Host: closed.Addr().String()}
	closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), time.Second, time.Minute)
	cfg := defaultRuntime()
	cfg.MaxBodyBuffer = 3
	ts := newForwarderCfg(t, pl, cfg)

	resp, err := proxiedClient(t, ts.URL).Post("http://"+startEchoBodyTarget(t)+"/", "text/plain", strings.NewReader("abcd"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(got) != "abcd" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, got)
	}
	snap := pl.Snapshot()
	if snap[0].Failures != 1 || snap[1].Successes != 1 {
		t.Fatalf("pool state = %+v", snap)
	}
}

func TestPOSTReplaysAfterAuthFallback(t *testing.T) {
	bad := startSocks5Proxy(t, socksOptions{user: "TEST-user", pass: "TEST-pass"})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(bad.URL, good.URL), time.Second, time.Minute)
	cfg := defaultRuntime()
	cfg.MaxBodyBuffer = 3
	ts := newForwarderCfg(t, pl, cfg)

	resp, err := proxiedClient(t, ts.URL).Post("http://"+startEchoBodyTarget(t)+"/", "text/plain", strings.NewReader("abc"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(got) != "abc" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, got)
	}
	snap := pl.Snapshot()
	if snap[0].AuthFailures != 1 || snap[0].Failures != 0 || snap[1].Successes != 1 {
		t.Fatalf("pool state = %+v", snap)
	}
}

type errorReadCloser struct {
	err    error
	closed bool
}

func (b *errorReadCloser) Read([]byte) (int, error) { return 0, b.err }
func (b *errorReadCloser) Close() error {
	b.closed = true
	return nil
}

func TestBodyReadErrorIsLoggedAndDoesNotChangePool(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs, slog.LevelDebug))
	body := &errorReadCloser{err: errors.New("TEST body read failure")}
	req := httptest.NewRequest(http.MethodPost, "http://TEST-target.invalid/", body)
	req.Host = "TEST-target.invalid"
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status=%d, want 400", rec.Code)
	}
	if !body.closed {
		t.Fatal("request body was not closed")
	}
	if snap := pl.Snapshot()[0]; snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("body read failure changed pool state: %+v", snap)
	}
	output := logs.String()
	for _, want := range []string{"request_id=1", "msg=\"request rejected\"", "error_kind=body_read"} {
		if !strings.Contains(output, want) {
			t.Errorf("logs missing %q:\n%s", want, output)
		}
	}
}

type blockingCloseBody struct {
	closed chan struct{}
	once   sync.Once
	sent   bool
}

func (b *blockingCloseBody) Read(p []byte) (int, error) {
	if b.sent {
		return 0, io.EOF
	}
	b.sent = true
	p[0] = 'x'
	return 1, nil
}
func (b *blockingCloseBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestCanceledStreamedRequestDoesNotMutatePoolOrRetry(t *testing.T) {
	first, err := url.Parse("socks5://TEST-first.invalid:1080")
	if err != nil {
		t.Fatal(err)
	}
	second, err := url.Parse("socks5://TEST-second.invalid:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes(mixedRoutes(first, second), time.Second, time.Minute)
	cfg := defaultRuntime()
	cfg.MaxBodyBuffer = 0
	s := newRuntimeServer(pl, cfg, testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	body := &blockingCloseBody{closed: make(chan struct{})}
	req := httptest.NewRequest(http.MethodPost, "http://TEST-target.invalid/", body).WithContext(ctx)
	req.Host = "TEST-target.invalid"
	s.dial = func(context.Context, *url.URL, string, time.Duration) (net.Conn, error) {
		cancel()
		return nil, &ProxyDialError{Err: context.Canceled}
	}
	rec := httptest.NewRecorder()

	s.ServeHTTP(rec, req)
	select {
	case <-body.closed:
	case <-time.After(time.Second):
		t.Fatal("streamed request body was not closed")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want unwritten recorder", rec.Code)
	}
	if s.failovers.Load() != 0 {
		t.Fatalf("failovers=%d, want 0", s.failovers.Load())
	}
	for _, snap := range pl.Snapshot() {
		if snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 || !snap.Available {
			t.Fatalf("cancellation changed pool state: %+v", snap)
		}
	}
}

func TestDialTCPCancellationIsNotEndpointFailure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := dialTCP(ctx, "127.0.0.1:1", time.Second)
	if !errors.Is(err, context.Canceled) || isProxyDialError(err) {
		t.Fatalf("dialTCP cancellation = %T %v, want plain context cancellation", err, err)
	}
}

type hijackerResponseWriter struct {
	conn net.Conn
}

func (w *hijackerResponseWriter) Header() http.Header         { return http.Header{} }
func (w *hijackerResponseWriter) Write(p []byte) (int, error) { return len(p), nil }
func (w *hijackerResponseWriter) WriteHeader(int)             {}
func (w *hijackerResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return w.conn, bufio.NewReadWriter(bufio.NewReader(w.conn), bufio.NewWriter(w.conn)), nil
}

func TestCanceledTunnelDoesNotMutatePoolOrSend502(t *testing.T) {
	first, err := url.Parse("socks5://TEST-first.invalid:1080")
	if err != nil {
		t.Fatal(err)
	}
	second, err := url.Parse("socks5://TEST-second.invalid:1080")
	if err != nil {
		t.Fatal(err)
	}
	pl := pool.NewRoutes(mixedRoutes(first, second), time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	ctx, cancel := context.WithCancel(context.Background())
	s.dial = func(context.Context, *url.URL, string, time.Duration) (net.Conn, error) {
		cancel()
		return nil, &ProxyDialError{Err: context.Canceled}
	}
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	req := httptest.NewRequest(http.MethodConnect, "http://TEST-target.invalid:443", nil).WithContext(ctx)
	writer := &hijackerResponseWriter{conn: serverConn}
	done := make(chan struct{})
	go func() {
		s.ServeHTTP(writer, req)
		close(done)
	}()
	clientConn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	n, readErr := clientConn.Read(one[:])
	if n != 0 || readErr == nil {
		t.Fatalf("canceled tunnel response = %q, %v; want closed connection without 502", one[:n], readErr)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("canceled tunnel handler did not return")
	}
	if s.failovers.Load() != 0 {
		t.Fatalf("failovers=%d, want 0", s.failovers.Load())
	}
	for _, snap := range pl.Snapshot() {
		if snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 || !snap.Available {
			t.Fatalf("cancellation changed pool state: %+v", snap)
		}
	}
}

func connectThrough(t *testing.T, proxyAddr, targetHostPort string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	pu, err := url.Parse(proxyAddr)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", pu.Host)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	fmt.Fprintf(conn, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", targetHostPort, targetHostPort)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		t.Fatalf("read CONNECT response: %v", err)
	}
	return conn, br, resp
}

func TestConnectTunnelThroughSOCKS(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "tunnel-ok")
	}))
	defer tlsSrv.Close()
	tu, _ := url.Parse(tlsSrv.URL)
	fs := startSocks5Proxy(t, socksOptions{})
	ts, pl := newForwarder(t, fs)

	conn, _, resp := connectThrough(t, ts.URL, tu.Host)
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d", resp.StatusCode)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{DialTLSContext: func(context.Context, string, string) (net.Conn, error) {
		return tlsConn, nil
	}}}
	get, err := client.Get(tlsSrv.URL)
	if err != nil {
		t.Fatalf("GET through tunnel: %v", err)
	}
	body, _ := io.ReadAll(get.Body)
	get.Body.Close()
	if string(body) != "tunnel-ok" {
		t.Fatalf("body=%q", body)
	}
	if snap := pl.Snapshot()[0]; snap.Successes != 1 || snap.Failures != 0 {
		t.Fatalf("pool state=%+v", snap)
	}
}

func TestTunnelAuthFailureFallsBack(t *testing.T) {
	bad := startSocks5Proxy(t, socksOptions{user: "u", pass: "p"})
	good := startSocks5Proxy(t, socksOptions{})
	target := startEchoTarget(t)
	ts, pl := newForwarder(t, bad, good)

	conn, _, resp := connectThrough(t, ts.URL, target)
	conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", resp.StatusCode)
	}
	snap := pl.Snapshot()
	if !snap[0].AuthBlocked || snap[0].Failures != 0 || snap[1].Successes != 1 {
		t.Fatalf("pool state=%+v", snap)
	}
}

func TestTunnelLogsCorrelateDialFallback(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := &url.URL{Scheme: "socks5", User: url.UserPassword("TEST-user", "TEST-pass"), Host: closed.Addr().String()}
	closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(dead, good.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	ts := newForwarderCfgLogger(t, pl, defaultRuntime(), captureLogger(&logs, slog.LevelDebug))

	conn, _, resp := connectThrough(t, ts.URL, startEchoTarget(t))
	conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", resp.StatusCode)
	}
	output := waitForLog(t, &logs, "msg=tunnel")
	for _, want := range []string{
		"request_id=1",
		"msg=\"upstream dial failed\"",
		"error_kind=proxy_connect",
		"cooldown=1s",
		"msg=tunnel",
		"attempts=2",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("logs missing %q:\n%s", want, output)
		}
	}
	for _, secret := range []string{"TEST-user", "TEST-pass"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked %q:\n%s", secret, output)
		}
	}
}

func TestTunnelAuthFallbackLogsWithoutCooldown(t *testing.T) {
	bad := startSocks5Proxy(t, socksOptions{user: "TEST-user", pass: "TEST-pass"})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(bad.URL, good.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	ts := newForwarderCfgLogger(t, pl, defaultRuntime(), captureLogger(&logs, slog.LevelDebug))

	conn, _, resp := connectThrough(t, ts.URL, startEchoTarget(t))
	conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", resp.StatusCode)
	}
	output := waitForLog(t, &logs, "msg=tunnel")
	if !strings.Contains(output, "error_kind=auth_route") || !strings.Contains(output, "attempts=2") {
		t.Fatalf("logs did not record auth fallback and success:\n%s", output)
	}
	if strings.Contains(output, "cooldown=") {
		t.Fatalf("auth fallback logged a cooldown:\n%s", output)
	}
}

func TestTunnelHandshakeFailureExhaustsToNoRoute(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	ts, pl := newForwarder(t, fs)

	conn, _, resp := connectThrough(t, ts.URL, "example.com:443")
	conn.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("CONNECT status=%d, want 502", resp.StatusCode)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 0 || snap.AuthFailures != 0 || snap.Failures != 1 || snap.Available {
		t.Fatalf("handshake failure did not record route health: %+v", snap)
	}
	if got := len(fs.hits); got != 1 {
		t.Fatalf("SOCKS attempts=%d, want 1", got)
	}
}

func TestTunnelLogsCorrelateHandshakeFallback(t *testing.T) {
	reject := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	good := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(reject.URL, good.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	ts := newForwarderCfgLogger(t, pl, defaultRuntime(), captureLogger(&logs, slog.LevelDebug))

	conn, _, resp := connectThrough(t, ts.URL, startEchoTarget(t))
	conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", resp.StatusCode)
	}
	output := waitForLog(t, &logs, "msg=tunnel")
	for _, want := range []string{
		"request_id=1",
		"msg=\"upstream handshake failed\"",
		"error_kind=socks_connect",
		"cooldown=1s",
		"msg=tunnel",
		"attempts=2",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("logs missing %q:\n%s", want, output)
		}
	}
}

func TestTunnelRelaysPipelinedClientBytes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len("TEST-prefix"))
		if _, err := io.ReadFull(conn, buf); err == nil {
			received <- string(buf)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	fs := startSocks5Proxy(t, socksOptions{})
	ts, _ := newForwarder(t, fs)
	pu, err := url.Parse(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", pu.Host)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	request := "CONNECT " + ln.Addr().String() + " HTTP/1.1\r\nHost: " + ln.Addr().String() + "\r\n\r\nTEST-prefix"
	if _, err := conn.Write([]byte(request)); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", resp.StatusCode)
	}
	select {
	case got := <-received:
		if got != "TEST-prefix" {
			t.Fatalf("pipelined bytes=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("target did not receive pipelined bytes")
	}
}

type blockingCloseConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	once    sync.Once
}

func (c *blockingCloseConn) Close() error {
	c.once.Do(func() { close(c.started) })
	<-c.release
	return c.Conn.Close()
}

func TestCloseTunnelsDoesNotHoldConnectionMapLockWhileClosing(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	conn := &blockingCloseConn{
		Conn:    serverSide,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	s := newRuntimeServer(pool.NewRoutes(nil, time.Second, time.Minute), defaultRuntime(), testLogger())
	s.trackConn(conn)
	closed := make(chan struct{})
	go func() {
		s.CloseTunnels()
		close(closed)
	}()
	select {
	case <-conn.started:
	case <-time.After(time.Second):
		t.Fatal("CloseTunnels did not call connection Close")
	}
	untracked := make(chan struct{})
	go func() {
		s.untrackConn(conn)
		close(untracked)
	}()
	select {
	case <-untracked:
	case <-time.After(time.Second):
		t.Fatal("connection map lock remained held while Close blocked")
	}
	close(conn.release)
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("CloseTunnels did not return after Close unblocked")
	}
}

func TestCloseTunnelsClosesIdleHijackedTunnel(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	s := newRuntimeServer(pl, defaultRuntime(), testLogger())
	ts := httptest.NewServer(s)
	defer ts.Close()

	conn, _, resp := connectThrough(t, ts.URL, startEchoTarget(t))
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", resp.StatusCode)
	}
	s.CloseTunnels()
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	if _, err := conn.Read(one[:]); err == nil {
		t.Fatal("idle hijacked tunnel stayed open after CloseTunnels")
	}
	conn.Close()
}

func TestAdminEndpoints(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), 30*time.Second, time.Minute)
	s := NewRuntime(pool.NewStore(defaultRuntime(), pl), testLogger(), "9.9.9-test", "mixed", config.EgressV4, config.EgressV6)
	admin := httptest.NewServer(s.AdminMux())
	defer admin.Close()

	hresp, err := http.Get(admin.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	body, _ := io.ReadAll(hresp.Body)
	hresp.Body.Close()
	if hresp.StatusCode != http.StatusOK || strings.TrimSpace(string(body)) != "ok" {
		t.Fatalf("healthz status=%d body=%q", hresp.StatusCode, body)
	}

	sresp, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer sresp.Body.Close()
	if sresp.StatusCode != http.StatusOK {
		t.Fatalf("status code=%d", sresp.StatusCode)
	}
	var got map[string]any
	if err := json.NewDecoder(sresp.Body).Decode(&got); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	if got["version"] != "9.9.9-test" {
		t.Fatalf("status=%v", got)
	}
}

// startAbortTarget answers each request with a partial body under an
// oversized Content-Length, then resets the connection — modeling a target or
// provider that drops a live stream mid-flight.
func startAbortTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go abortTargetConn(conn)
		}
	}()
	return ln.Addr().String()
}

func abortTargetConn(conn net.Conn) {
	defer conn.Close()
	// No request is read: over CONNECT the client only opens the tunnel and
	// reads, so the partial response goes out unprompted.
	fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\npartial") //nolint:errcheck
	if tc, ok := conn.(*net.TCPConn); ok {
		tc.SetLinger(0) // reset instead of a clean close
	}
}

// An upstream that ends the tunnel abnormally produces a broken-tunnel close
// record at warn without touching route health.
func TestTunnelUpstreamResetLogsBrokenClose(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	ts := newForwarderCfgLogger(t, pl, defaultRuntime(), captureLogger(&logs, slog.LevelDebug))

	conn, _, resp := connectThrough(t, ts.URL, startAbortTarget(t))
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status=%d, want 200", resp.StatusCode)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err == nil {
		t.Fatal("tunnel stayed open after the target aborted the stream")
	}

	output := waitForLog(t, &logs, `msg="tunnel broken"`)
	for _, want := range []string{
		"close_reason=upstream_broken",
		"client_to_upstream_bytes=",
		"upstream_to_client_bytes=",
		"duration=",
		"error=",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("close record missing %q:\n%s", want, output)
		}
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 1 || snap.Failures != 0 || snap.AuthFailures != 0 {
		t.Fatalf("broken tunnel mutated route health: %+v", snap)
	}
}
