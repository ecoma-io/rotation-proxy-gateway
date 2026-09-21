package e2e_test

import (
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// authedConnect performs the account-gated handshake against a gateway
// listener: a greeting offering both methods (the armed account must select
// 0x02 over 0x00), the RFC 1929 exchange, and — when the credentials are
// accepted — one CONNECT. It returns the RFC 1929 status and, on success, the
// established tunnel with its reply code.
func authedConnect(t *testing.T, proxyAddr, username, password, targetAddr string) (byte, net.Conn, byte) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x02, 0x00, 0x02}); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(conn, selection); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if selection[0] != 0x05 || selection[1] != 0x02 {
		t.Fatalf("method selection = % x, want 05 02 — an armed account must not accept NO AUTHENTICATION", selection)
	}
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("send auth: %v", err)
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if status[1] != 0x00 {
		return status[1], nil, 0
	}
	req, err := socksConnectRequestBytes(targetAddr)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("send connect: %v", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("read connect reply: %v", err)
	}
	if err := discardSocksBND(conn, head[3]); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Time{})
	return 0x00, conn, head[1]
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

	authStatus, conn, reply := authedConnect(t, g.MixedAddr, "e2e-user", "e2e-pass", target.Host)
	if authStatus != 0x00 || reply != 0x00 {
		t.Fatalf("auth status=%#02x connect reply=%#02x, want 00/00", authStatus, reply)
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

	// Wrong password: the RFC 1929 failure reply and a close, before any
	// route selection.
	if status, _, _ := authedConnect(t, g.MixedAddr, "e2e-user", "wrong-pass", target.Host); status != 0xff {
		t.Fatalf("wrong-password auth status = %#02x, want ff", status)
	}

	// A no-auth client is refused at method negotiation — the open-proxy
	// quiet direction the account exists to close.
	noAuth, err := net.DialTimeout("tcp", g.V4Addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = noAuth.Close() })
	_ = noAuth.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := noAuth.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	selection := make([]byte, 2)
	if _, err := io.ReadFull(noAuth, selection); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if selection[0] != 0x05 || selection[1] != 0xff {
		t.Fatalf("method selection = % x, want 05 ff for a no-auth client", selection)
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
// the RFC 1929 frame carries a zero-length password (PLEN=0), the
// constant-time comparison must accept exactly that pair, and any non-empty
// password or wrong username is rejected before route selection.
func TestE2E_InboundAccountEmptyPasswordAuthenticates(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := NewEchoTarget(t)
	g := NewGatewayWithEnv(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}), "RPGW_ACCOUNT=e2e-user:")

	authStatus, conn, reply := authedConnect(t, g.MixedAddr, "e2e-user", "", target.Host)
	if authStatus != 0x00 || reply != 0x00 {
		t.Fatalf("empty-password auth status=%#02x connect reply=%#02x, want 00/00", authStatus, reply)
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

	// A non-empty password against the empty-password account fails the
	// exchange; so does the right password under a wrong username.
	if status, _, _ := authedConnect(t, g.MixedAddr, "e2e-user", "non-empty", target.Host); status != 0xff {
		t.Fatalf("non-empty password auth status = %#02x, want ff", status)
	}
	if status, _, _ := authedConnect(t, g.MixedAddr, "e2e-other-user", "", target.Host); status != 0xff {
		t.Fatalf("wrong-username auth status = %#02x, want ff", status)
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
