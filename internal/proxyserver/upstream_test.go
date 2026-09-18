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
	"testing"
	"time"
)

type socksOptions struct {
	user, pass string
	connectRep byte
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
	io.Copy(conn, up) //nolint:errcheck
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

func TestDialViaConnectReplyIsProtocolError(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	_, err := dialVia(context.Background(), fs.URL, "example.com:80", time.Second)
	var protocolErr *SocksProtocolError
	if !errors.As(err, &protocolErr) || isProxyDialError(err) || isProxyAuthError(err) {
		t.Fatalf("connect reply error = %T %v", err, err)
	}
}
