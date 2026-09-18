package proxyserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"proxy-auto-rotate-forwarder/internal/config"
	"proxy-auto-rotate-forwarder/internal/pool"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeUpstream is a double for an upstream proxy: it forwards plain
// absolute-form requests to the real target via the default transport,
// answers CONNECT by tunneling (optionally demanding auth), and can be told
// to return a fixed status on the plain path.
type fakeUpstream struct {
	URL         *url.URL
	plainHits   atomic.Int32
	connectHits atomic.Int32
	plainStatus int    // 0 = forward to target
	auth        string // required CONNECT Proxy-Authorization, "" = none
}

func newFakeUpstream(t *testing.T, plainStatus int) *fakeUpstream {
	t.Helper()
	fu := &fakeUpstream{plainStatus: plainStatus}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			fu.connectHits.Add(1)
			hj, ok := w.(http.Hijacker)
			if !ok {
				return
			}
			conn, _, err := hj.Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			if fu.auth != "" && r.Header.Get("Proxy-Authorization") != fu.auth {
				conn.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n"))
				return
			}
			up, err := net.Dial("tcp", r.URL.Host)
			if err != nil {
				conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n"))
				return
			}
			defer up.Close()
			conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
			go func() {
				io.Copy(up, conn)
				up.Close()
			}()
			io.Copy(conn, up)
			return
		}

		fu.plainHits.Add(1)
		if fu.plainStatus != 0 {
			w.Header().Set("Connection", "X-Up") // must be stripped end to end
			w.Header().Set("Proxy-Authorization", "up-secret")
			w.WriteHeader(fu.plainStatus)
			io.WriteString(w, "upstream-status")
			return
		}
		resp, err := http.DefaultTransport.RoundTrip(r)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vv := range resp.Header {
			for _, v := range vv {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		io.Copy(w, resp.Body)
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	fu.URL = u
	return fu
}

func newForwarderCfg(t *testing.T, pl *pool.Pool, cfg *config.Config) *httptest.Server {
	t.Helper()
	s := New(pl, cfg, testLogger(), "test")
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts
}

func defaultCfg() *config.Config {
	return &config.Config{
		MaxRetries:          3,
		ConnectTimeout:      2 * time.Second,
		MaxBodyBuffer:       64 << 20,
		CooldownBase:        30 * time.Second,
		CooldownMax:         time.Minute,
		UpstreamTLSInsecure: false,
	}
}

func newForwarder(t *testing.T, ups ...*fakeUpstream) (*httptest.Server, *pool.Pool) {
	t.Helper()
	urls := make([]*url.URL, 0, len(ups))
	for _, up := range ups {
		urls = append(urls, up.URL)
	}
	pl := pool.New(urls, 30*time.Second, time.Minute)
	return newForwarderCfg(t, pl, defaultCfg()), pl
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

// startEchoBodyTarget echoes the request body back in the response body.
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
	h.Set("Connection", "X-Drop, Keep-Alive")
	h.Set("X-Drop", "yes")
	h.Set("X-Keep", "1")
	h.Set("Proxy-Authorization", "secret")
	stripHopByHop(h)
	for _, name := range []string{"X-Drop", "Keep-Alive", "Proxy-Authorization", "Connection"} {
		if h.Get(name) != "" {
			t.Errorf("%s survived strip", name)
		}
	}
	if h.Get("X-Keep") != "1" {
		t.Error("X-Keep should have been kept")
	}
}

func TestRetryStatus(t *testing.T) {
	for _, code := range []int{408, 429, 500, 502, 503} {
		if !retryStatus(code) {
			t.Errorf("%d should rotate", code)
		}
	}
	for _, code := range []int{200, 403, 404} {
		if retryStatus(code) {
			t.Errorf("%d should not rotate", code)
		}
	}
}

func TestPlainHTTPForward(t *testing.T) {
	target := startEchoTarget(t)
	up := newFakeUpstream(t, 0)
	ts, pl := newForwarder(t, up)

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "dial-via-ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	snap := pl.Snapshot()
	if len(snap) != 1 || snap[0].Successes != 1 || snap[0].Failures != 0 {
		t.Fatalf("pool snapshot = %+v", snap)
	}
}

func TestRotatesPastDeadUpstream(t *testing.T) {
	target := startEchoTarget(t)
	dead := newFakeUpstream(t, 503)
	good := newFakeUpstream(t, 0)
	ts, pl := newForwarder(t, dead, good)

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200 after rotation", resp.StatusCode)
	}
	if dead.plainHits.Load() != 1 || good.plainHits.Load() != 1 {
		t.Fatalf("hits dead=%d good=%d", dead.plainHits.Load(), good.plainHits.Load())
	}
	snap := pl.Snapshot()
	if snap[0].Available || snap[0].Failures != 1 {
		t.Fatalf("dead proxy state = %+v", snap[0])
	}
	if !snap[1].Available || snap[1].Successes != 1 {
		t.Fatalf("good proxy state = %+v", snap[1])
	}
}

func TestRetryableStatusExhaustedPassesThrough(t *testing.T) {
	target := startEchoTarget(t)
	up1 := newFakeUpstream(t, 429)
	up2 := newFakeUpstream(t, 429)
	up3 := newFakeUpstream(t, 429)
	ts, pl := newForwarder(t, up1, up2, up3)

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 429 {
		t.Fatalf("status = %d, want 429 passthrough", resp.StatusCode)
	}
	if string(body) != "upstream-status" {
		t.Fatalf("body = %q, want buffered passthrough body", body)
	}
	for i, up := range []*fakeUpstream{up1, up2, up3} {
		if up.plainHits.Load() != 1 {
			t.Fatalf("upstream %d hits = %d, want exactly 1 attempt", i, up.plainHits.Load())
		}
	}
	for i, p := range pl.Snapshot() {
		if p.Failures != 1 {
			t.Fatalf("proxy %d failures = %d, want 1", i, p.Failures)
		}
	}
}

func TestNonRetryablePassthrough(t *testing.T) {
	target := startEchoTarget(t)
	up := newFakeUpstream(t, 404)
	ts, pl := newForwarder(t, up)

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
	if up.plainHits.Load() != 1 {
		t.Fatalf("hits = %d, want 1 (no rotation)", up.plainHits.Load())
	}
	if snap := pl.Snapshot(); snap[0].Successes != 1 || snap[0].Failures != 0 {
		t.Fatalf("snapshot = %+v", snap[0])
	}
}

func TestPOSTReplayOnRotation(t *testing.T) {
	target := startEchoBodyTarget(t)
	dead := newFakeUpstream(t, 503)
	good := newFakeUpstream(t, 0)
	ts, _ := newForwarder(t, dead, good)

	resp, err := proxiedClient(t, ts.URL).Post("http://"+target+"/", "text/plain", strings.NewReader("payload-123"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != "payload-123" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func TestStreamModeNoRetry(t *testing.T) {
	target := startEchoBodyTarget(t)
	dead := newFakeUpstream(t, 503)
	good := newFakeUpstream(t, 0)

	urls := []*url.URL{dead.URL, good.URL}
	pl := pool.New(urls, 30*time.Second, time.Minute)
	cfg := defaultCfg()
	cfg.MaxBodyBuffer = 16
	ts := newForwarderCfg(t, pl, cfg)

	resp, err := proxiedClient(t, ts.URL).Post("http://"+target+"/", "text/plain", strings.NewReader("01234567890123456789012345678901"))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != 503 {
		t.Fatalf("status = %d, want 503 from single attempt", resp.StatusCode)
	}
	if good.plainHits.Load() != 0 {
		t.Fatalf("good upstream hit %d times, want 0 (no retry beyond buffer)", good.plainHits.Load())
	}
}

func TestResponseHopByHopStripped(t *testing.T) {
	target := startEchoTarget(t)
	up := newFakeUpstream(t, 404) // response carries Proxy-Authorization + Connection
	ts, _ := newForwarder(t, up)

	resp, err := proxiedClient(t, ts.URL).Get("http://" + target + "/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("Proxy-Authorization"); got != "" {
		t.Errorf("Proxy-Authorization leaked: %q", got)
	}
	if got := resp.Header.Get("Connection"); got != "" {
		t.Errorf("Connection leaked: %q", got)
	}
}

// connectThrough dials the proxy, issues CONNECT, and returns the raw client
// conn ready for the tunnel payload.
func connectThrough(t *testing.T, proxyAddr, targetHostPort string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	conn, err := net.Dial("tcp", hostOnly(proxyAddr))
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

func hostOnly(addr string) string {
	u, err := url.Parse(addr)
	if err != nil {
		return addr
	}
	return u.Host
}

func TestConnectTunnel(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "dial-via-ok")
	}))
	defer tlsSrv.Close()
	tu, _ := url.Parse(tlsSrv.URL)
	targetHostPort := tu.Host

	up := newFakeUpstream(t, 0)
	ts, _ := newForwarder(t, up)

	conn, br, resp := connectThrough(t, ts.URL, targetHostPort)
	defer conn.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake through tunnel: %v", err)
	}
	client := &http.Client{Transport: &http.Transport{
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tlsConn, nil
		},
	}}
	get, err := client.Get("https://" + targetHostPort + "/")
	if err != nil {
		t.Fatalf("GET via tunnel: %v", err)
	}
	defer get.Body.Close()
	body, _ := io.ReadAll(get.Body)
	if string(body) != "dial-via-ok" {
		t.Fatalf("body = %q", body)
	}
	if n := br.Buffered(); n > 0 {
		t.Logf("proxy buffered %d pipelined bytes after CONNECT", n)
	}
	if up.connectHits.Load() != 1 {
		t.Fatalf("connect hits = %d, want 1", up.connectHits.Load())
	}
}

func TestConnectRetriesPastBadUpstream(t *testing.T) {
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "dial-via-ok")
	}))
	defer tlsSrv.Close()
	tu, _ := url.Parse(tlsSrv.URL)

	bad := newFakeUpstream(t, 0)
	bad.auth = "Basic bm9wZTpub3Bl" // any request without creds gets 407
	good := newFakeUpstream(t, 0)
	ts, _ := newForwarder(t, bad, good)

	conn, _, resp := connectThrough(t, ts.URL, tu.Host)
	defer conn.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("CONNECT status = %d, want 200 after rotation", resp.StatusCode)
	}
	if bad.connectHits.Load() != 1 {
		t.Fatalf("bad upstream hits = %d, want 1", bad.connectHits.Load())
	}
}

func TestConnectExhausted(t *testing.T) {
	badAuth := "Basic bm9wZTpub3Bl"
	up1 := newFakeUpstream(t, 0)
	up1.auth = badAuth
	up2 := newFakeUpstream(t, 0)
	up2.auth = badAuth
	up3 := newFakeUpstream(t, 0)
	up3.auth = badAuth
	ts, pl := newForwarder(t, up1, up2, up3)

	conn, _, resp := connectThrough(t, ts.URL, "127.0.0.1:443")
	defer conn.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("CONNECT status = %d, want 502", resp.StatusCode)
	}
	for i, up := range []*fakeUpstream{up1, up2, up3} {
		if up.connectHits.Load() != 1 {
			t.Fatalf("upstream %d connect hits = %d, want exactly 1 attempt", i, up.connectHits.Load())
		}
	}
	for i, p := range pl.Snapshot() {
		if p.Failures != 1 {
			t.Fatalf("proxy %d failures = %d, want 1", i, p.Failures)
		}
	}
}

func TestAdminEndpoints(t *testing.T) {
	up := newFakeUpstream(t, 0)
	pl := pool.New([]*url.URL{up.URL}, 30*time.Second, time.Minute)
	s := New(pl, defaultCfg(), testLogger(), "9.9.9-test")

	admin := httptest.NewServer(s.AdminMux())
	defer admin.Close()

	hresp, err := http.Get(admin.URL + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	hb, _ := io.ReadAll(hresp.Body)
	hresp.Body.Close()
	if hresp.StatusCode != 200 || strings.TrimSpace(string(hb)) != "ok" {
		t.Fatalf("healthz status=%d body=%q", hresp.StatusCode, hb)
	}

	sresp, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatalf("status: %v", err)
	}
	defer sresp.Body.Close()
	sb, _ := io.ReadAll(sresp.Body)
	if sresp.StatusCode != 200 {
		t.Fatalf("status code = %d", sresp.StatusCode)
	}
	for _, want := range []string{`"version":"9.9.9-test"`, `"requests":0`, `"pool":`} {
		if !strings.Contains(string(sb), want) {
			t.Errorf("/status missing %s in %s", want, sb)
		}
	}
}

func TestStreamBodyForwardedIntact(t *testing.T) {
	target := startEchoBodyTarget(t)
	good := newFakeUpstream(t, 0)

	pl := pool.New([]*url.URL{good.URL}, 30*time.Second, time.Minute)
	cfg := defaultCfg()
	cfg.MaxBodyBuffer = 16
	ts := newForwarderCfg(t, pl, cfg)

	payload := strings.Repeat("x", 64)
	resp, err := proxiedClient(t, ts.URL).Post("http://"+target+"/", "text/plain", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || string(body) != payload {
		t.Fatalf("status=%d body len=%d, want 200 and 64 intact bytes", resp.StatusCode, len(body))
	}
	if good.plainHits.Load() != 1 {
		t.Fatalf("hits = %d, want 1", good.plainHits.Load())
	}
}
