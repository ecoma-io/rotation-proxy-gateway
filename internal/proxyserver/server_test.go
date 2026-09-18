package proxyserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"proxy-auto-rotate-forwarder/internal/config"
	"proxy-auto-rotate-forwarder/internal/pool"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func defaultCfg() *config.Config {
	return &config.Config{
		MaxRetries:        3,
		ConnectTimeout:    2 * time.Second,
		MaxBodyBuffer:     64 << 20,
		CooldownBase:      30 * time.Second,
		CooldownMax:       time.Minute,
		TargetTLSInsecure: false,
	}
}

func newForwarderCfg(t *testing.T, pl *pool.Pool, cfg *config.Config) *httptest.Server {
	t.Helper()
	s := New(pl, cfg, testLogger(), "test")
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts
}

func newForwarder(t *testing.T, socks ...*fakeSocks) (*httptest.Server, *pool.Pool) {
	t.Helper()
	urls := make([]*url.URL, 0, len(socks))
	for _, fs := range socks {
		urls = append(urls, fs.URL)
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

func TestHTTPSRoundTripThroughSOCKS(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "https-via-socks")
	}))
	defer target.Close()
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.New([]*url.URL{fs.URL}, 30*time.Second, time.Minute)
	cfg := defaultCfg()
	cfg.TargetTLSInsecure = true
	s := New(pl, cfg, testLogger(), "test")

	out, err := http.NewRequest(http.MethodGet, target.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := s.roundTripViaSOCKS(context.Background(), fs.URLProxy(t, pl), out)
	if err != nil {
		t.Fatalf("roundTripViaSOCKS: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "https-via-socks" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
}

func (s *fakeSocks) URLProxy(t *testing.T, pl *pool.Pool) *pool.Proxy {
	t.Helper()
	p := pl.Pick(nil)
	if p == nil || p.URL.String() != s.URL.String() {
		t.Fatalf("pool did not return expected SOCKS route")
	}
	return p
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

func TestRotatesOnlyOnEndpointDialFailure(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadURL := &url.URL{Scheme: "socks5", Host: closed.Addr().String()}
	closed.Close()
	good := startSocks5Proxy(t, socksOptions{})
	target := startEchoTarget(t)
	pl := pool.New([]*url.URL{deadURL, good.URL}, 30*time.Second, time.Minute)
	ts := newForwarderCfg(t, pl, defaultCfg())

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

func TestSOCKSTargetFailureDoesNotRetryOrMutateHealth(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	ts, pl := newForwarder(t, fs)

	resp, err := proxiedClient(t, ts.URL).Get("http://example.com/")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("status=%d, want 502", resp.StatusCode)
	}
	snap := pl.Snapshot()[0]
	if snap.Successes != 0 || snap.Failures != 0 || snap.AuthFailures != 0 || !snap.Available {
		t.Fatalf("target failure changed route health: %+v", snap)
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
	pl := pool.New([]*url.URL{deadURL, good.URL}, 30*time.Second, time.Minute)
	ts := newForwarderCfg(t, pl, defaultCfg())

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

func TestAdminEndpoints(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.New([]*url.URL{fs.URL}, 30*time.Second, time.Minute)
	s := New(pl, defaultCfg(), testLogger(), "9.9.9-test")
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
