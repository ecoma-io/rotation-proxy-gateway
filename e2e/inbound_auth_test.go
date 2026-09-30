package e2e_test

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// proxyAuthHeader renders the Proxy-Authorization value a client sends for one
// account. An empty user or pass still produces a well-formed Basic value, so
// the empty-password account stays expressible.
func proxyAuthHeader(username, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(username+":"+password))
}

// authedConnect performs the account-gated request against a gateway listener:
// one CONNECT carrying Proxy-Authorization, and — when the credentials are
// accepted — an established tunnel. It returns the CONNECT status and, on
// success, the established tunnel.
func authedConnect(t *testing.T, proxyAddr, username, password, targetAddr string) (int, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: %s\r\n\r\n",
		targetAddr, targetAddr, proxyAuthHeader(username, password))
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("send connect: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return resp.StatusCode, nil
	}
	_ = conn.SetDeadline(time.Time{})
	return http.StatusOK, &bufferedConn{Conn: conn, r: br}
}

// The full account-gated story against the real binary: correct credentials
// reach an established tunnel through the real route, wrong credentials and
// no-auth clients never reach route selection, and no credential byte reaches
// the process logs or /status.
func TestE2E_InboundAccountAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_ACCOUNT=e2e-user:e2e-pass")

	status, conn := authedConnect(t, g.MixedAddr, "e2e-user", "e2e-pass", target.Host)
	if status != http.StatusOK || conn == nil {
		t.Fatalf("authenticated CONNECT status = %d, want 200 with a tunnel", status)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET /hello HTTP/1.0\r\nHost: e2e\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(out), "200") || !strings.Contains(string(out), "e2e-echo:/hello") {
		t.Fatalf("response = %q, want the echoed body", out)
	}
	_ = conn.Close()

	// Wrong password: 407 and a close, before any route selection.
	if status, _ := authedConnect(t, g.MixedAddr, "e2e-user", "wrong-pass", target.Host); status != http.StatusProxyAuthRequired {
		t.Fatalf("wrong-password CONNECT status = %d, want 407", status)
	}

	// A no-auth client is refused before route selection too — the open-proxy
	// quiet direction the account exists to close.
	noAuth, err := net.DialTimeout("tcp", g.V4Addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = noAuth.Close() })
	_ = noAuth.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := noAuth.Write([]byte("CONNECT " + target.Host + " HTTP/1.1\r\nHost: " + target.Host + "\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(noAuth)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read connect response: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("no-auth CONNECT status = %d, want 407", resp.StatusCode)
	}
	if got := resp.Header.Get("Proxy-Authenticate"); !strings.Contains(got, `Basic realm="rotation-proxy-gateway"`) {
		t.Fatalf("Proxy-Authenticate = %q, want the gateway's Basic realm", got)
	}

	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Listeners["mixed"].Requests != 1 || st.Listeners["v4"].Requests != 0 {
		t.Fatalf("listener requests = %+v, want exactly the one authenticated CONNECT on mixed", st.Listeners)
	}
	if len(st.Pool) != 1 || st.Pool[0].Successes != 1 {
		t.Fatalf("pool = %+v, want one successful route use", st.Pool)
	}

	logs := g.Logs()
	for _, secret := range []string{"e2e-user", "e2e-pass", "wrong-pass"} {
		if strings.Contains(logs, secret) {
			t.Errorf("gateway logs leaked %q:\n%s", secret, logs)
		}
	}
}

// An account with an empty password is armed authentication like any other:
// the Basic value carries an empty password, the constant-time comparison must
// accept exactly that pair, and any non-empty password or wrong username is
// rejected before route selection.
func TestE2E_InboundAccountEmptyPasswordAuthenticates(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_ACCOUNT=e2e-user:")

	status, conn := authedConnect(t, g.MixedAddr, "e2e-user", "", target.Host)
	if status != http.StatusOK || conn == nil {
		t.Fatalf("empty-password CONNECT status = %d, want 200 with a tunnel", status)
	}
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte("GET /empty-pass HTTP/1.0\r\nHost: e2e\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	out, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !strings.Contains(string(out), "200") || !strings.Contains(string(out), "e2e-echo:/empty-pass") {
		t.Fatalf("response = %q, want the echoed body", out)
	}
	_ = conn.Close()

	// A non-empty password against the empty-password account is refused; so
	// does the right password under a wrong username.
	if status, _ := authedConnect(t, g.MixedAddr, "e2e-user", "non-empty", target.Host); status != http.StatusProxyAuthRequired {
		t.Fatalf("non-empty password CONNECT status = %d, want 407", status)
	}
	if status, _ := authedConnect(t, g.MixedAddr, "e2e-other-user", "", target.Host); status != http.StatusProxyAuthRequired {
		t.Fatalf("wrong-username CONNECT status = %d, want 407", status)
	}

	st, err := g.Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Listeners["mixed"].Requests != 1 || len(st.Pool) != 1 || st.Pool[0].Successes != 1 {
		t.Fatalf("status = %+v, want exactly the one authenticated CONNECT served", st)
	}
}

// A malformed RPGW_ACCOUNT must refuse to start rather than serve without
// the authentication its operator believes is on. The error names the
// variable and never quotes the rejected value.
func TestE2E_InboundAccountMalformedRefusesStartup(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	if testBinaryPath == "" {
		t.Skip("e2e binary not built (short mode?)")
	}
	cmd := exec.Command(testBinaryPath)
	cmd.Env = []string{
		// LoadBootstrap fails before the runtime config is ever read, so the
		// path only has to be shaped; no file is created.
		"RPGW_CONFIG_FILE=" + filepath.Join(t.TempDir(), "config.yaml"),
		"RPGW_ADMIN_ADDR=" + freeAddr(t),
		"RPGW_MIXED_LISTEN_ADDR=" + freeAddr(t),
		"RPGW_V4_LISTEN_ADDR=" + freeAddr(t),
		"RPGW_V6_LISTEN_ADDR=" + freeAddr(t),
		"RPGW_ACCOUNT=value-without-a-colon",
		"PATH=" + os.Getenv("PATH"),
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("gateway started on a malformed RPGW_ACCOUNT; output:\n%s", out)
	}
	if !strings.Contains(string(out), "RPGW_ACCOUNT") {
		t.Fatalf("startup error does not name RPGW_ACCOUNT:\n%s", out)
	}
	if strings.Contains(string(out), "value-without-a-colon") {
		t.Fatalf("startup error quotes the rejected account value:\n%s", out)
	}
}
