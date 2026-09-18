package proxyserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

type socksOptions struct {
	user, pass string
	connectRep byte
	// greetingRaw, when non-nil, is written as the method-selection reply
	// after consuming the client greeting. It enables malformed-version,
	// unsupported-method, and truncated-reply cases without sleeps.
	greetingRaw []byte
	// greetingNoReply consumes the client greeting then closes without a
	// reply, modeling a truncated greeting.
	greetingNoReply bool
	// authRaw, when non-nil, is written as the username/password status
	// reply after consuming the client credentials. It enables malformed
	// and truncated auth replies without sleeps.
	authRaw []byte
	// authNoReply consumes the client credentials then closes without a
	// reply, modeling a truncated auth exchange.
	authNoReply bool
	// connectRaw, when non-nil, is written as the CONNECT reply after
	// consuming the client CONNECT request, then the connection closes.
	// It covers malformed, truncated, and unsupported-bound-type replies.
	connectRaw []byte
	// connectPrefix is extra stream bytes written immediately after a
	// success reply, modeling a peer that pipelines post-handshake data.
	connectPrefix []byte
}

type fakeSocks struct {
	URL  *url.URL
	opts socksOptions
	hits chan struct{}
}

func startSocks5Proxy(t *testing.T, opts socksOptions) *fakeSocks {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fs := &fakeSocks{opts: opts, hits: make(chan struct{}, 100)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go fs.handle(conn)
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	fs.URL = &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
	return fs
}

func (s *fakeSocks) handle(conn net.Conn) {
	defer conn.Close()
	select {
	case s.hits <- struct{}{}:
	default:
	}
	br := bufio.NewReader(conn)
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := readSocksGreeting(br, conn, s.opts); err != nil {
		return
	}
	target, err := readSocksConnect(br)
	if err != nil {
		return
	}
	if s.opts.connectRaw != nil {
		conn.Write(s.opts.connectRaw) //nolint:errcheck
		return
	}
	if s.opts.connectRep != 0 {
		writeSocksReply(conn, s.opts.connectRep)
		return
	}
	up, err := net.Dial("tcp", target)
	if err != nil {
		writeSocksReply(conn, 0x05)
		return
	}
	defer up.Close()
	writeSocksReply(conn, 0x00)
	if len(s.opts.connectPrefix) > 0 {
		conn.Write(s.opts.connectPrefix) //nolint:errcheck
	}
	conn.SetDeadline(time.Time{})
	if n := br.Buffered(); n > 0 {
		b := make([]byte, n)
		io.ReadFull(br, b)
		up.Write(b)
	}
	go func() {
		io.Copy(up, conn) //nolint:errcheck
		up.Close()
	}()
	if _, err := io.Copy(conn, up); err != nil {
		// The target ended the stream abnormally. Reset the SOCKS peer too so
		// it sees a broken tunnel rather than a clean close, modeling
		// providers that drop live streams mid-flight.
		if tc, ok := conn.(*net.TCPConn); ok {
			tc.SetLinger(0)
		}
	}
}

func readSocksGreeting(br *bufio.Reader, conn net.Conn, opts socksOptions) error {
	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return fmt.Errorf("bad greeting")
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return err
	}
	if opts.greetingRaw != nil {
		if _, err := conn.Write(opts.greetingRaw); err != nil {
			return err
		}
		if len(opts.greetingRaw) < 2 {
			return fmt.Errorf("truncated greeting reply")
		}
		return nil
	}
	if opts.greetingNoReply {
		return fmt.Errorf("no greeting reply")
	}
	if opts.user == "" && opts.pass == "" {
		_, err := conn.Write([]byte{0x05, 0x00})
		return err
	}
	for _, method := range methods {
		if method == 0x02 {
			if _, err := conn.Write([]byte{0x05, 0x02}); err != nil {
				return err
			}
			head = make([]byte, 2)
			if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x01 {
				return fmt.Errorf("bad auth header")
			}
			user := make([]byte, head[1])
			if _, err := io.ReadFull(br, user); err != nil {
				return err
			}
			passLen, err := br.ReadByte()
			if err != nil {
				return err
			}
			pass := make([]byte, passLen)
			if _, err := io.ReadFull(br, pass); err != nil {
				return err
			}
			if string(user) != opts.user || string(pass) != opts.pass {
				_, err := conn.Write([]byte{0x01, 0x01})
				return err
			}
			if opts.authRaw != nil {
				if _, err := conn.Write(opts.authRaw); err != nil {
					return err
				}
				if len(opts.authRaw) < 2 {
					return fmt.Errorf("truncated auth reply")
				}
				return nil
			}
			if opts.authNoReply {
				return fmt.Errorf("no auth reply")
			}
			_, err = conn.Write([]byte{0x01, 0x00})
			return err
		}
	}
	_, err := conn.Write([]byte{0x05, 0xff})
	return err
}

func readSocksConnect(br *bufio.Reader) (string, error) {
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 || head[1] != 0x01 {
		return "", fmt.Errorf("bad connect request")
	}
	var host string
	switch head[3] {
	case 0x01:
		b := make([]byte, 4)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	case 0x03:
		n, err := br.ReadByte()
		if err != nil {
			return "", err
		}
		b := make([]byte, n)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = string(b)
	case 0x04:
		b := make([]byte, 16)
		if _, err := io.ReadFull(br, b); err != nil {
			return "", err
		}
		host = net.IP(b).String()
	default:
		return "", fmt.Errorf("unknown address type")
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(br, portBytes); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(portBytes[0])<<8|int(portBytes[1]))), nil
}

func writeSocksReply(conn net.Conn, rep byte) {
	conn.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) //nolint:errcheck
}

func startEchoTarget(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, "dial-via-ok")
	}))
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}

func TestDialViaSocks5(t *testing.T) {
	target := startEchoTarget(t)
	t.Run("no auth", func(t *testing.T) {
		fs := startSocks5Proxy(t, socksOptions{})
		conn, err := dialVia(context.Background(), fs.URL, target, time.Second)
		if err != nil {
			t.Fatalf("dialVia: %v", err)
		}
		defer conn.Close()
		fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
		body, _ := io.ReadAll(conn)
		if string(body) == "" {
			t.Fatal("empty response through SOCKS")
		}
	})
	t.Run("auth", func(t *testing.T) {
		fs := startSocks5Proxy(t, socksOptions{user: "u", pass: "p"})
		fs.URL.User = url.UserPassword("u", "p")
		conn, err := dialVia(context.Background(), fs.URL, target, time.Second)
		if err != nil {
			t.Fatalf("dialVia: %v", err)
		}
		conn.Close()
	})
}

func TestDialViaClassifiesEndpointAndAuthFailures(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := closed.Addr().String()
	closed.Close()
	pu := &url.URL{Scheme: "socks5", Host: addr}
	_, err = dialVia(context.Background(), pu, "example.com:80", time.Second)
	if !isProxyDialError(err) || isProxyAuthError(err) {
		t.Fatalf("dial error classification = %T %v", err, err)
	}

	fs := startSocks5Proxy(t, socksOptions{user: "u", pass: "p"})
	_, err = dialVia(context.Background(), fs.URL, "example.com:80", time.Second)
	if !isProxyAuthError(err) || isProxyDialError(err) {
		t.Fatalf("auth error classification = %T %v", err, err)
	}
}

func TestDialViaConnectReplyIsHandshakeError(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	_, err := dialVia(context.Background(), fs.URL, "example.com:80", time.Second)
	handshakeErr := assertSocksHandshakeError(t, err, "connect target")
	if !strings.Contains(handshakeErr.Error(), "SOCKS reply 0x05") {
		t.Fatalf("handshake error = %q, want it to name the reply", handshakeErr.Error())
	}
}

func assertSocksProtocolError(t *testing.T, err error, op string) *SocksProtocolError {
	t.Helper()
	var protocolErr *SocksProtocolError
	if !errors.As(err, &protocolErr) {
		t.Fatalf("expected SocksProtocolError, got %T %v", err, err)
	}
	if protocolErr.Op != op {
		t.Fatalf("op = %q, want %q (err %v)", protocolErr.Op, op, err)
	}
	if isProxyDialError(err) || isProxyAuthError(err) || isSocksHandshakeError(err) {
		t.Fatalf("protocol error misclassified as dial/auth/handshake: %T %v", err, err)
	}
	return protocolErr
}

func assertSocksHandshakeError(t *testing.T, err error, op string) *SocksHandshakeError {
	t.Helper()
	var handshakeErr *SocksHandshakeError
	if !errors.As(err, &handshakeErr) {
		t.Fatalf("expected SocksHandshakeError, got %T %v", err, err)
	}
	if handshakeErr.Op != op {
		t.Fatalf("op = %q, want %q (err %v)", handshakeErr.Op, op, err)
	}
	if isProxyDialError(err) || isProxyAuthError(err) {
		t.Fatalf("handshake error misclassified as dial/auth: %T %v", err, err)
	}
	var protocolErr *SocksProtocolError
	if errors.As(err, &protocolErr) {
		t.Fatalf("handshake error must not be SocksProtocolError: %v", err)
	}
	return handshakeErr
}

func TestDialViaGreetingFailuresAreHandshakeErrors(t *testing.T) {
	cases := map[string]socksOptions{
		"wrong version":      {greetingRaw: []byte{0x04, 0x00}},
		"unsupported method": {greetingRaw: []byte{0x05, 0x07}},
		"truncated choice":   {greetingRaw: []byte{0x05}},
		"truncated no reply": {greetingNoReply: true},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			fs := startSocks5Proxy(t, opts)
			_, err := dialVia(context.Background(), fs.URL, "example.com:80", time.Second)
			op := "read greeting"
			if name == "unsupported method" {
				op = "negotiate authentication"
			}
			assertSocksHandshakeError(t, err, op)
		})
	}
}

func TestDialViaNoAcceptableMethodIsAuthError(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{greetingRaw: []byte{0x05, 0xff}})
	_, err := dialVia(context.Background(), fs.URL, "example.com:80", time.Second)
	if !isProxyAuthError(err) || isProxyDialError(err) || isSocksHandshakeError(err) {
		t.Fatalf("auth error classification = %T %v", err, err)
	}
	var protocolErr *SocksProtocolError
	if errors.As(err, &protocolErr) {
		t.Fatalf("auth error must not be SocksProtocolError: %v", err)
	}
}

func TestDialViaAuthFramingFailuresAreHandshakeErrors(t *testing.T) {
	cases := map[string]socksOptions{
		"wrong auth version": {user: "u", pass: "p", authRaw: []byte{0x02, 0x00}},
		"truncated auth":     {user: "u", pass: "p", authRaw: []byte{0x01}},
		"no auth reply":      {user: "u", pass: "p", authNoReply: true},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			fs := startSocks5Proxy(t, opts)
			pu := *fs.URL
			pu.User = url.UserPassword("u", "p")
			_, err := dialVia(context.Background(), &pu, "example.com:80", time.Second)
			assertSocksHandshakeError(t, err, "read authentication")
		})
	}
}

func TestDialViaConnectFramingFailuresAreHandshakeErrors(t *testing.T) {
	v4ok := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 80}
	cases := map[string]socksOptions{
		"wrong version":          {connectRaw: []byte{0x04, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}},
		"nonzero reserved":       {connectRaw: []byte{0x05, 0x00, 0x01, 0x01, 0, 0, 0, 0, 0, 0}},
		"truncated reply":        {connectRaw: []byte{0x05, 0x00}},
		"truncated bound ipv4":   {connectRaw: []byte{0x05, 0x00, 0x00, 0x01, 127, 0}},
		"unsupported bound type": {connectRaw: []byte{0x05, 0x00, 0x00, 0x07, 0, 0}},
		"ipv6 bound ok":          {connectRaw: []byte{0x05, 0x00, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 80}},
		"domain bound ok":        {connectRaw: append([]byte{0x05, 0x00, 0x00, 0x03, 4}, append([]byte("test"), 0, 80)...)},
		"ipv4 bound ok":          {connectRaw: v4ok},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			fs := startSocks5Proxy(t, opts)
			conn, err := dialVia(context.Background(), fs.URL, "example.com:80", time.Second)
			switch name {
			case "ipv6 bound ok", "domain bound ok", "ipv4 bound ok":
				if err != nil {
					t.Fatalf("dialVia: %v", err)
				}
				conn.Close()
			case "unsupported bound type", "truncated bound ipv4":
				assertSocksHandshakeError(t, err, "read bound address")
			default:
				assertSocksHandshakeError(t, err, "read connect")
			}
		})
	}
}

func TestDialViaOversizedTargetHostnameIsProtocolError(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	long := strings.Repeat("a", 256) + ".example:80"
	_, err := dialVia(context.Background(), fs.URL, long, time.Second)
	assertSocksProtocolError(t, err, "encode target")
	if got := len(fs.hits); got != 1 {
		t.Fatalf("SOCKS attempts = %d, want 1", got)
	}
}

func TestDialViaBufferedPrefixDelivered(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectPrefix: []byte("early-bytes")})
	conn, err := dialVia(context.Background(), fs.URL, startEchoTarget(t), time.Second)
	if err != nil {
		t.Fatalf("dialVia: %v", err)
	}
	defer conn.Close()
	buf := make([]byte, len("early-bytes"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read prefix: %v", err)
	}
	if string(buf) != "early-bytes" {
		t.Fatalf("prefix = %q", buf)
	}
}

// Connect-framing failures are handshake failures: with a single route the
// request exhausts to the sanitized no-route 502 while recording dial health.
func TestConnectFramingFailuresExhaustToNoRoute(t *testing.T) {
	rawCases := []struct {
		name string
		raw  []byte
	}{
		{"truncated connect reply", []byte{0x05, 0x00}},
		{"unsupported bound type", []byte{0x05, 0x00, 0x00, 0x07, 0, 0}},
	}
	for _, tc := range rawCases {
		t.Run(tc.name, func(t *testing.T) {
			fs := startSocks5Proxy(t, socksOptions{connectRaw: tc.raw})
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
		})
	}
}
