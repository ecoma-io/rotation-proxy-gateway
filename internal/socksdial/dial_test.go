package socksdial

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"
)

const dialTestTimeout = 5 * time.Second

// socksScript programs one scripted SOCKS5 endpoint conversation. Zero values
// mean "happy path": accept the offered methods, succeed authentication, and
// answer CONNECT with code 0x00.
type socksScript struct {
	method     byte // server method choice; 0x00 when unset
	authStatus byte
	replyCode  byte
	atyp       byte   // bound-address type in the reply; 0x01 when unset
	bound      []byte // raw bound address bytes after atyp
	pipeline   []byte // extra bytes sent immediately with the reply
	dropGreet  bool   // close before answering the greeting
	dropAuth   bool   // close before answering the auth request
	dropConn   bool   // close before answering CONNECT
	wantUser   string
	wantPass   string
	wantHost   string // expected CONNECT target host; empty skips the check
	wantPort   uint16 // expected CONNECT target port; 0 skips the check
}

func startScriptedSocks(t *testing.T, script socksScript) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				_ = conn.SetDeadline(time.Now().Add(dialTestTimeout))
				handleScriptedConn(t, conn, script)
			}()
		}
	}()
	return ln.Addr().String()
}

// end the script.
func scriptRead(br *bufio.Reader, n int) ([]byte, bool) {
	buf := make([]byte, n)
	_, err := io.ReadFull(br, buf)
	return buf, err == nil
}

func handleScriptedConn(t *testing.T, conn net.Conn, script socksScript) {
	t.Helper()
	br := bufio.NewReader(conn)
	greet, ok := scriptRead(br, 2)
	if !ok {
		return
	}
	if _, ok := scriptRead(br, int(greet[1])); !ok {
		return
	}
	if script.dropGreet {
		return
	}
	if _, err := conn.Write([]byte{0x05, script.method}); err != nil {
		return
	}
	if script.method == 0x02 {
		ver, ok := scriptRead(br, 1)
		if !ok || ver[0] != 0x01 {
			return
		}
		ulen, ok := scriptRead(br, 1)
		if !ok {
			return
		}
		user, ok := scriptRead(br, int(ulen[0]))
		if !ok {
			return
		}
		plen, ok := scriptRead(br, 1)
		if !ok {
			return
		}
		pass, ok := scriptRead(br, int(plen[0]))
		if !ok {
			return
		}
		if script.wantUser != "" || script.wantPass != "" {
			if string(user) != script.wantUser || string(pass) != script.wantPass {
				t.Errorf("auth credentials = %q:%q, want %q:%q", user, pass, script.wantUser, script.wantPass)
			}
		}
		if script.dropAuth {
			return
		}
		if _, err := conn.Write([]byte{0x01, script.authStatus}); err != nil {
			return
		}
		if script.authStatus != 0x00 {
			return
		}
	}
	head, ok := scriptRead(br, 4)
	if !ok {
		return
	}
	host, port, ok := scriptReadConnectTarget(br, head[3])
	if !ok {
		return
	}
	if script.wantHost != "" && host != script.wantHost {
		t.Errorf("CONNECT host = %q, want %q", host, script.wantHost)
	}
	if script.wantPort != 0 && port != script.wantPort {
		t.Errorf("CONNECT port = %d, want %d", port, script.wantPort)
	}
	if script.dropConn {
		return
	}
	atypOut := script.atyp
	if atypOut == 0x00 {
		atypOut = 0x01
	}
	reply := append([]byte{0x05, script.replyCode, 0x00, atypOut}, script.bound...)
	if len(script.bound) == 0 {
		switch atypOut {
		case 0x01:
			reply = append(reply, 1, 2, 3, 4, 0x16, 0x2e)
		case 0x03:
			reply = append(reply, 3, 'b', 'n', 'd', 0x00, 0x50)
		case 0x04:
			reply = append(reply, make([]byte, 18)...)
		}
	}
	reply = append(reply, script.pipeline...)
	if _, err := conn.Write(reply); err != nil {
		return
	}
	if script.replyCode != 0x00 {
		return
	}
	// Echo relay for the established tunnel.
	buf := make([]byte, 1024)
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func scriptReadConnectTarget(br *bufio.Reader, atyp byte) (string, uint16, bool) {
	switch atyp {
	case 0x01:
		raw, ok := scriptRead(br, 6)
		if !ok {
			return "", 0, false
		}
		return net.IP(raw[:4]).String(), uint16(raw[4])<<8 | uint16(raw[5]), true
	case 0x03:
		n, ok := scriptRead(br, 1)
		if !ok {
			return "", 0, false
		}
		raw, ok := scriptRead(br, int(n[0])+2)
		if !ok {
			return "", 0, false
		}
		host := string(raw[:len(raw)-2])
		port := uint16(raw[len(raw)-2])<<8 | uint16(raw[len(raw)-1])
		return host, port, true
	case 0x04:
		raw, ok := scriptRead(br, 18)
		if !ok {
			return "", 0, false
		}
		return net.IP(raw[:16]).String(), uint16(raw[16])<<8 | uint16(raw[17]), true
	default:
		return "", 0, false
	}
}

func dialURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// assertTaxonomy pins the contract error classification: exactly the expected
// predicate is true. Wrapped errors must classify identically.
func assertTaxonomy(t *testing.T, err error, dial, auth, hs bool) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if got := IsDialError(err); got != dial {
		t.Errorf("IsDialError(%v) = %v, want %v", err, got, dial)
	}
	if got := IsAuthError(err); got != auth {
		t.Errorf("IsAuthError(%v) = %v, want %v", err, got, auth)
	}
	if got := IsHandshakeError(err); got != hs {
		t.Errorf("IsHandshakeError(%v) = %v, want %v", err, got, hs)
	}
	if _, isProto := err.(*SocksProtocolError); isProto && (dial || auth || hs) {
		t.Errorf("SocksProtocolError must not classify as dial/auth/handshake: %v", err)
	}
}

func TestDialSuccessRoundTripNoAuth(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{})
	conn, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q, want ping", got)
	}
}

func TestDialConnectRequestTargetEncoding(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{wantHost: "example.com", wantPort: 8443})
	conn, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:8443", dialTestTimeout)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	_ = conn.Close()
}

func TestDialSuccessWithAuth(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{method: 0x02, wantUser: "route-user", wantPass: "route-pass"})
	conn, err := Dial(context.Background(), dialURL(t, "socks5://route-user:route-pass@"+addr), "example.com:443", dialTestTimeout)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
		t.Fatalf("echo = %q, err = %v", got, err)
	}
}

func TestDialBoundAddressTypes(t *testing.T) {
	for _, atyp := range []byte{0x01, 0x03, 0x04} {
		t.Run(fmt.Sprintf("atyp-%#02x", atyp), func(t *testing.T) {
			addr := startScriptedSocks(t, socksScript{atyp: atyp})
			conn, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
			if err != nil {
				t.Fatalf("Dial: %v", err)
			}
			defer func() { _ = conn.Close() }()
			if _, err := conn.Write([]byte("ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			got := make([]byte, 4)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "ping" {
				t.Fatalf("echo = %q, err = %v", got, err)
			}
		})
	}
}

// Bytes pipelined with the handshake reply must be delivered before the live
// stream (withBufferedPrefix path).
func TestDialPipelinedHandshakeData(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{pipeline: []byte("PRE")})
	conn, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = conn.Close() }()
	got := make([]byte, 3)
	if _, err := io.ReadFull(conn, got); err != nil || string(got) != "PRE" {
		t.Fatalf("prefix = %q, err = %v", got, err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	echo := make([]byte, 4)
	if _, err := io.ReadFull(conn, echo); err != nil || string(echo) != "ping" {
		t.Fatalf("echo = %q, err = %v", echo, err)
	}
}

func TestDialAuthenticationFailures(t *testing.T) {
	t.Run("rejected credentials", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{method: 0x02, authStatus: 0x01})
		_, err := Dial(context.Background(), dialURL(t, "socks5://u:p@"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, true, false)
	})
	t.Run("no acceptable method", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{method: 0xff})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, true, false)
	})
	t.Run("credentials required but none configured", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{method: 0x02})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, true, false)
	})
}

func TestDialHandshakeFailures(t *testing.T) {
	t.Run("closed before greeting reply", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{dropGreet: true})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, false, true)
	})
	t.Run("unsupported method choice", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{method: 0x01})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, false, true)
	})
	t.Run("closed before connect reply", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{dropConn: true})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, false, true)
	})
	t.Run("nonzero reply code", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{replyCode: 0x05})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, false, true)
		if !IsConnectTargetError(err) {
			t.Fatalf("explicit CONNECT refusal must classify as connect-target: %v", err)
		}
		var reply *SocksReplyError
		if !errors.As(err, &reply) || reply.Reply != 0x05 {
			t.Fatalf("err = %v, want wrapped SocksReplyError{0x05}", err)
		}
		if want := "SOCKS handshake failed during connect target: SOCKS reply 0x05"; err.Error() != want {
			t.Fatalf("err text = %q, want %q", err.Error(), want)
		}
	})
	t.Run("unsupported bound address type", func(t *testing.T) {
		addr := startScriptedSocks(t, socksScript{atyp: 0x06, bound: []byte{}})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, false, true)
	})
}

func TestDialLocalSetupFailures(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{})
	for _, tc := range []struct{ name, target string }{
		{"missing port", "example.com"},
		{"empty target", ""},
		{"bad port", "example.com:notaport"},
		{"zero port", "example.com:0"},
		{"oversized hostname", strings.Repeat("a", 256) + ":443"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), tc.target, dialTestTimeout)
			var proto *SocksProtocolError
			if !errors.As(err, &proto) {
				t.Fatalf("err = %v, want SocksProtocolError", err)
			}
			if IsDialError(err) || IsAuthError(err) || IsHandshakeError(err) {
				t.Fatalf("setup error must not classify as dial/auth/handshake: %v", err)
			}
		})
	}
	t.Run("unsupported scheme", func(t *testing.T) {
		_, err := Dial(context.Background(), dialURL(t, "http://"+addr), "example.com:443", dialTestTimeout)
		var proto *SocksProtocolError
		if !errors.As(err, &proto) {
			t.Fatalf("err = %v, want SocksProtocolError", err)
		}
	})
	t.Run("oversized credentials", func(t *testing.T) {
		big := strings.Repeat("u", 256)
		srv := startScriptedSocks(t, socksScript{method: 0x02})
		_, err := Dial(context.Background(), dialURL(t, "socks5://"+big+":p@"+srv), "example.com:443", dialTestTimeout)
		var proto *SocksProtocolError
		if !errors.As(err, &proto) {
			t.Fatalf("err = %v, want SocksProtocolError", err)
		}
		assertTaxonomy(t, err, false, false, false)
		if !strings.Contains(err.Error(), "encode credentials") {
			t.Fatalf("err = %v, want op context", err)
		}
	})
}

// Only an explicit non-zero reply to the CONNECT request is target-scoped;
// every other handshake failure stays route-scoped.
func TestDialConnectTargetScope(t *testing.T) {
	t.Run("refusal carries the endpoint's reply code", func(t *testing.T) {
		for _, code := range []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08} {
			addr := startScriptedSocks(t, socksScript{replyCode: code})
			_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
			assertTaxonomy(t, err, false, false, true)
			if !IsConnectTargetError(err) {
				t.Fatalf("reply 0x%02x must classify as connect-target: %v", code, err)
			}
		}
	})
	t.Run("route-scoped handshake failures are not connect-target", func(t *testing.T) {
		for _, script := range []socksScript{
			{dropGreet: true},
			{method: 0x01},
			{dropConn: true},
			{atyp: 0x06, bound: []byte{}},
		} {
			addr := startScriptedSocks(t, script)
			_, err := Dial(context.Background(), dialURL(t, "socks5://"+addr), "example.com:443", dialTestTimeout)
			assertTaxonomy(t, err, false, false, true)
			if IsConnectTargetError(err) {
				t.Fatalf("handshake failure %v must stay route-scoped", err)
			}
		}
	})
	t.Run("auth and dial failures are not connect-target", func(t *testing.T) {
		authAddr := startScriptedSocks(t, socksScript{method: 0x02, authStatus: 0x01})
		_, err := Dial(context.Background(), dialURL(t, "socks5://u:p@"+authAddr), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, false, true, false)
		if IsConnectTargetError(err) {
			t.Fatalf("auth failure must not classify as connect-target: %v", err)
		}
		ln, lerr := net.Listen("tcp", "127.0.0.1:0")
		if lerr != nil {
			t.Fatalf("listen: %v", lerr)
		}
		refused := ln.Addr().String()
		_ = ln.Close()
		_, err = Dial(context.Background(), dialURL(t, "socks5://"+refused), "example.com:443", dialTestTimeout)
		assertTaxonomy(t, err, true, false, false)
		if IsConnectTargetError(err) {
			t.Fatalf("dial failure must not classify as connect-target: %v", err)
		}
	})
}

func TestDialEndpointRefused(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	refused := ln.Addr().String()
	_ = ln.Close()
	_, err = Dial(context.Background(), dialURL(t, "socks5://"+refused), "example.com:443", dialTestTimeout)
	assertTaxonomy(t, err, true, false, false)
}

// A canceled context surfaces the caller's cancellation, never a dial-health
// error: the pool must not cool a route the client abandoned.
func TestDialTCPCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := DialTCP(ctx, "127.0.0.1:1", dialTestTimeout)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if IsDialError(err) {
		t.Fatalf("canceled dial must not classify as ProxyDialError: %v", err)
	}
}

func TestErrorPredicatesWrapAndNil(t *testing.T) {
	dialErr := fmt.Errorf("wrap: %w", &ProxyDialError{Err: errors.New("boom")})
	if !IsDialError(dialErr) || IsAuthError(dialErr) || IsHandshakeError(dialErr) {
		t.Fatalf("wrapped ProxyDialError misclassified: %v", dialErr)
	}
	authErr := fmt.Errorf("wrap: %w", &ProxyAuthError{Reason: "no"})
	if !IsAuthError(authErr) || IsDialError(authErr) || IsHandshakeError(authErr) {
		t.Fatalf("wrapped ProxyAuthError misclassified: %v", authErr)
	}
	hsErr := fmt.Errorf("wrap: %w", &SocksHandshakeError{Op: "read greeting"})
	if !IsHandshakeError(hsErr) || IsDialError(hsErr) || IsAuthError(hsErr) {
		t.Fatalf("wrapped SocksHandshakeError misclassified: %v", hsErr)
	}
	plainHS := &SocksHandshakeError{Op: "read connect", Err: errors.New("eof")}
	if IsConnectTargetError(plainHS) {
		t.Fatalf("handshake error without SocksReplyError must not classify as connect-target: %v", plainHS)
	}
	wrappedTarget := fmt.Errorf("wrap: %w", &SocksHandshakeError{Op: "connect target", Err: &SocksReplyError{Reply: 0x01}})
	if !IsHandshakeError(wrappedTarget) || !IsConnectTargetError(wrappedTarget) {
		t.Fatalf("wrapped connect-target refusal misclassified: %v", wrappedTarget)
	}
	if IsDialError(nil) || IsAuthError(nil) || IsHandshakeError(nil) || IsConnectTargetError(nil) {
		t.Fatal("nil must not classify as any error kind")
	}
	if IsDialError(errors.New("plain")) || IsAuthError(errors.New("plain")) || IsHandshakeError(errors.New("plain")) {
		t.Fatal("plain error must not classify as any error kind")
	}
}

func TestDiscardSocksBoundAddressLimits(t *testing.T) {
	for _, tc := range []struct {
		name  string
		atyp  byte
		input []byte
	}{
		{"ipv4", 0x01, make([]byte, 6)},
		{"domain empty", 0x03, []byte{0x00, 0x00, 0x50}},
		{"domain long", 0x03, append([]byte{0x05}, make([]byte, 7)...)},
		{"ipv6", 0x04, make([]byte, 18)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := discardSocksBoundAddress(bufio.NewReader(strings.NewReader(string(tc.input))), tc.atyp); err != nil {
				t.Fatalf("discard: %v", err)
			}
		})
	}
	t.Run("truncated", func(t *testing.T) {
		if err := discardSocksBoundAddress(bufio.NewReader(strings.NewReader("ab")), 0x01); err == nil {
			t.Fatal("expected error for truncated bound address")
		}
	})
}
