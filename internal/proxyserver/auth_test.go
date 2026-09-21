package proxyserver

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/pool"
)

// userPassAuthFrame encodes one RFC 1929 client frame: VER ULEN UNAME PLEN
// PASSWD.
func userPassAuthFrame(username, password string) []byte {
	u, p := []byte(username), []byte(password)
	frame := []byte{authUPVersion, byte(len(u))}
	frame = append(frame, u...)
	frame = append(frame, byte(len(p)))
	return append(frame, p...)
}

// authIngressRequest drives readSocksRequest over a pipe with account armed:
// greeting exchange, RFC 1929 exchange, then one CONNECT frame. It returns the
// method selection, the auth status reply (nil when none arrived before the
// close), and the parser outcome.
func authIngressRequest(t *testing.T, account *inboundAccount, greeting []byte, authFrame, request []byte) (method, authStatus []byte, req socksRequest, err error) {
	t.Helper()
	serverSide, clientSide := net.Pipe()
	defer func() { _ = serverSide.Close(); _ = clientSide.Close() }()
	type outcome struct {
		req socksRequest
		err error
	}
	results := make(chan outcome, 1)
	go func() {
		req, err := readSocksRequest(bufio.NewReader(serverSide), serverSide, account)
		results <- outcome{req: req, err: err}
		// Closing unblocks a client read waiting for a reply the malformed
		// paths never write (the silent-close doctrine).
		_ = serverSide.Close()
	}()
	if _, werr := clientSide.Write(greeting); werr != nil {
		t.Fatal(werr)
	}
	method = make([]byte, 2)
	if _, rerr := io.ReadFull(clientSide, method); rerr != nil {
		t.Fatalf("read method selection: %v", rerr)
	}
	if authFrame != nil {
		if _, werr := clientSide.Write(authFrame); werr != nil {
			t.Fatal(werr)
		}
		// The failure and success paths both answer two bytes; a silent
		// close (malformed frame) ends this read with an error or a
		// deadline, never a hang.
		authStatus = make([]byte, 2)
		_ = clientSide.SetReadDeadline(time.Now().Add(time.Second))
		if _, rerr := io.ReadFull(clientSide, authStatus); rerr != nil {
			authStatus = nil
		}
		_ = clientSide.SetReadDeadline(time.Time{})
	}
	if request != nil {
		if _, werr := clientSide.Write(request); werr != nil {
			t.Fatal(werr)
		}
	} else {
		// No request follows: unblock a server still waiting for frame
		// bytes (the truncated-frame case) so the parser outcome arrives.
		_ = clientSide.Close()
	}
	select {
	case got := <-results:
		return method, authStatus, got.req, got.err
	case <-time.After(2 * time.Second):
		t.Fatal("readSocksRequest did not finish")
	}
	return nil, nil, socksRequest{}, nil
}

var testAccount = &inboundAccount{username: []byte("gw-user"), password: []byte("gw-pass")}

func connectFrame(t *testing.T, target string) []byte {
	t.Helper()
	frame, err := socksRequestFrame(socksCmdConnect, target)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// An armed account must switch the accepted method to username/password, and
// a client offering both methods must see 0x02 selected — 0x00 alongside 0x02
// is not permission to skip authentication.
func TestReadSocksRequestUserPassAuth(t *testing.T) {
	for _, tc := range []struct {
		name     string
		greeting []byte
	}{
		{"both methods offered", socksGreetingFrame(socksAuthNone, socksAuthUserPass)},
		{"only userpass offered", socksGreetingFrame(socksAuthUserPass)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			method, authStatus, req, err := authIngressRequest(t,
				testAccount, tc.greeting, userPassAuthFrame("gw-user", "gw-pass"), connectFrame(t, "example.test:443"))
			if err != nil {
				t.Fatalf("readSocksRequest: %v", err)
			}
			if method[0] != socksVersion || method[1] != socksAuthUserPass {
				t.Fatalf("method selection = %#02x %#02x, want 05 02", method[0], method[1])
			}
			if authStatus == nil || authStatus[0] != authUPVersion || authStatus[1] != authUPSuccess {
				t.Fatalf("auth reply = %v, want 01 00", authStatus)
			}
			if req.cmd != socksCmdConnect || req.target.Addr() != "example.test:443" {
				t.Fatalf("request = %+v, want CONNECT example.test:443", req)
			}
		})
	}
}

func TestReadSocksRequestUserPassWrongCredentials(t *testing.T) {
	for _, tc := range []struct {
		name string
		user string
		pass string
	}{
		{"wrong password", "gw-user", "other"},
		{"wrong username", "other", "gw-pass"},
		{"wrong username length", "gw-use", "gw-pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, authStatus, _, err := authIngressRequest(t,
				testAccount, socksGreetingFrame(socksAuthUserPass), userPassAuthFrame(tc.user, tc.pass), nil)
			if !errors.Is(err, errInboundAuth) {
				t.Fatalf("error = %v, want errInboundAuth", err)
			}
			if authStatus == nil || authStatus[0] != authUPVersion || authStatus[1] != authUPFailure {
				t.Fatalf("auth reply = %v, want 01 ff", authStatus)
			}
			// The rejection must not echo what the client presented.
			if err != nil && (strings.Contains(err.Error(), tc.user) || strings.Contains(err.Error(), tc.pass)) {
				t.Fatalf("error carries credential bytes: %v", err)
			}
		})
	}
}

// A configured account makes authentication mandatory: NO AUTHENTICATION
// REQUIRED alone is no longer an acceptable method.
func TestReadSocksRequestAccountRejectsNoAuthClient(t *testing.T) {
	method, authStatus, _, err := authIngressRequest(t,
		testAccount, socksGreetingFrame(socksAuthNone), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no acceptable authentication method") {
		t.Fatalf("error = %v, want no acceptable authentication method", err)
	}
	if method[0] != socksVersion || method[1] != socksAuthUnaccepted {
		t.Fatalf("method selection = %#02x %#02x, want 05 ff", method[0], method[1])
	}
	if authStatus != nil {
		t.Fatalf("auth reply = %v, want none", authStatus)
	}
}

// Without an account the historical handshake holds: username/password alone
// is unacceptable — the unset deployment never advertises RFC 1929.
func TestReadSocksRequestNilAccountRejectsUserPassClient(t *testing.T) {
	method, _, _, err := authIngressRequest(t,
		nil, socksGreetingFrame(socksAuthUserPass), nil, nil)
	if err == nil || !strings.Contains(err.Error(), "no acceptable authentication method") {
		t.Fatalf("error = %v, want no acceptable authentication method", err)
	}
	if method[1] != socksAuthUnaccepted {
		t.Fatalf("method selection = %#02x, want ff", method[1])
	}
}

// Malformed RFC 1929 frames close without a reply — the same silent-close
// doctrine as the rest of the inbound framing.
func TestReadSocksRequestUserPassMalformedClosesSilently(t *testing.T) {
	t.Run("wrong subnegotiation version", func(t *testing.T) {
		bad := userPassAuthFrame("gw-user", "gw-pass")
		bad[0] = 0x02
		_, authStatus, _, err := authIngressRequest(t,
			testAccount, socksGreetingFrame(socksAuthUserPass), bad, nil)
		if err == nil || errors.Is(err, errInboundAuth) {
			t.Fatalf("error = %v, want a framing error", err)
		}
		if authStatus != nil {
			t.Fatalf("auth reply = %v, want none", authStatus)
		}
	})
	t.Run("truncated password", func(t *testing.T) {
		frame := []byte{authUPVersion, 0x01, 'a', 0x05, 'p'} // PLEN says 5, one byte arrives
		_, authStatus, _, err := authIngressRequest(t,
			testAccount, socksGreetingFrame(socksAuthUserPass), frame, nil)
		if err == nil || errors.Is(err, errInboundAuth) {
			t.Fatalf("error = %v, want a framing error", err)
		}
		if authStatus != nil {
			t.Fatalf("auth reply = %v, want none", authStatus)
		}
	})
}

// authConnectReply performs the full account-gated handshake against a live
// server and returns the connection with the RFC 1929 status (0x00 success)
// before the CONNECT exchange continues.
func authConnectReply(t *testing.T, gatewayAddr, username, password, target string) (net.Conn, byte) {
	t.Helper()
	conn, err := net.Dial("tcp", gatewayAddr)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	// Offer both methods the way real clients do; the armed account must
	// select 0x02.
	if _, err := conn.Write(socksGreetingFrame(socksAuthNone, socksAuthUserPass)); err != nil {
		t.Fatalf("write greeting: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if method[0] != socksVersion || method[1] != socksAuthUserPass {
		t.Fatalf("method selection = %#02x %#02x, want 05 02", method[0], method[1])
	}
	if _, err := conn.Write(userPassAuthFrame(username, password)); err != nil {
		t.Fatalf("write auth: %v", err)
	}
	status := make([]byte, 2)
	if _, err := io.ReadFull(conn, status); err != nil {
		t.Fatalf("read auth reply: %v", err)
	}
	if status[1] != authUPSuccess {
		return conn, status[1]
	}
	frame, err := socksRequestFrame(socksCmdConnect, target)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read SOCKS reply: %v", err)
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, reply[1]
}

// The account gates the whole server: valid credentials reach an established
// tunnel through the real route pool, wrong credentials and no-auth clients
// never reach route selection, and no credential byte reaches the logs.
func TestInboundAccountGatesServing(t *testing.T) {
	route := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(route.URL), 30*time.Second, time.Minute)
	var logs safeLogBuffer
	s := newRuntimeServer(pl, defaultRuntime(), captureLogger(&logs))
	s.UseInboundAccount([]byte("gw-user"), []byte("gw-pass"))
	addr := startServer(t, s)
	target := startRawEchoTarget(t)

	conn, code := authConnectReply(t, addr, "gw-user", "gw-pass", target)
	if code != socksReplySuccess {
		t.Fatalf("CONNECT reply = %#02x, want success", code)
	}
	if banner := readBanner(t, conn); banner != "banner\n" {
		t.Fatalf("banner = %q", banner)
	}
	_ = conn.Close()

	// Wrong password: RFC 1929 failure reply and a close, before any route
	// selection — the listener request counter must not move.
	if _, status := authConnectReply(t, addr, "gw-user", "wrong", target); status != authUPFailure {
		t.Fatalf("auth status = %#02x, want ff", status)
	}

	// A no-auth client is refused at method negotiation.
	noAuth, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = noAuth.Close() })
	_ = noAuth.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := noAuth.Write(socksGreetingFrame(socksAuthNone)); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(noAuth, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	if method[0] != socksVersion || method[1] != socksAuthUnaccepted {
		t.Fatalf("method selection = %#02x %#02x, want 05 ff", method[0], method[1])
	}

	output := waitForRecord(t, &logs, map[string]string{"msg": "socks authentication rejected", "level": "warn", "error_kind": "auth_rejected"})
	if status := s.ListenerStatus(); status.Requests != 1 || status.Failovers != 0 {
		t.Fatalf("listener status = %+v, want exactly the one authenticated request", status)
	}
	snap := pl.Snapshot()
	if len(snap) != 1 || snap[0].Successes != 1 || snap[0].Failures != 0 || !snap[0].Available {
		t.Fatalf("route state = %+v, want one success and a healthy route", snap)
	}
	for _, secret := range []string{"gw-user", "gw-pass", "wrong"} {
		if strings.Contains(output, secret) {
			t.Errorf("logs leaked %q:\n%s", secret, output)
		}
	}
}
