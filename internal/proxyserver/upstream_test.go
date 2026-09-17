package proxyserver

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// startEchoTarget starts a plain HTTP server answering every request with a
// fixed body; it plays the "final destination" behind the tunnels.
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

func startHTTPConnectProxy(t *testing.T, requireAuth string, tlsCfg *tls.Config) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if tlsCfg != nil {
		ln = tls.NewListener(ln, tlsCfg)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeConnectConn(requireAuth, c)
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	scheme := "http"
	if tlsCfg != nil {
		scheme = "https"
	}
	return &url.URL{Scheme: scheme, Host: ln.Addr().String()}
}

func handleFakeConnectConn(requireAuth string, c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	req, err := http.ReadRequest(br)
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	c.SetReadDeadline(time.Time{})
	if requireAuth != "" && req.Header.Get("Proxy-Authorization") != requireAuth {
		io.WriteString(c, "HTTP/1.1 407 Proxy Authentication Required\r\nContent-Length: 0\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", req.URL.Host)
	if err != nil {
		io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer up.Close()
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\n")
	if n := br.Buffered(); n > 0 {
		b := make([]byte, n)
		io.ReadFull(br, b)
		up.Write(b)
	}
	go func() {
		io.Copy(up, c)
		up.Close()
	}()
	io.Copy(c, up)
}

func startSocks5Proxy(t *testing.T, user, pass string) *url.URL {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleFakeSocks5Conn(user, pass, c)
		}
	}()
	t.Cleanup(func() { ln.Close(); <-done })
	return &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
}

func handleFakeSocks5Conn(user, pass string, c net.Conn) {
	defer c.Close()
	br := bufio.NewReader(c)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))

	head := make([]byte, 2)
	if _, err := io.ReadFull(br, head); err != nil || head[0] != 0x05 {
		return
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(br, methods); err != nil {
		return
	}
	wantAuth := user != "" || pass != ""
	if wantAuth {
		accepted := false
		for _, m := range methods {
			if m == 0x02 {
				accepted = true
			}
		}
		if !accepted {
			c.Write([]byte{0x05, 0xff})
			return
		}
		c.Write([]byte{0x05, 0x02})
		av := make([]byte, 2) // ver, ulen
		if _, err := io.ReadFull(br, av); err != nil {
			return
		}
		uname := make([]byte, av[1])
		if _, err := io.ReadFull(br, uname); err != nil {
			return
		}
		plen := make([]byte, 1)
		if _, err := io.ReadFull(br, plen); err != nil {
			return
		}
		passwd := make([]byte, plen[0])
		if _, err := io.ReadFull(br, passwd); err != nil {
			return
		}
		if string(uname) != user || string(passwd) != pass {
			c.Write([]byte{0x01, 0x01})
			return
		}
		c.Write([]byte{0x01, 0x00})
	} else {
		c.Write([]byte{0x05, 0x00})
	}
	c.SetReadDeadline(time.Time{})

	req := make([]byte, 4)
	if _, err := io.ReadFull(br, req); err != nil {
		return
	}
	var host string
	switch req[3] {
	case 0x01:
		b := make([]byte, 6)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.IPv4(b[0], b[1], b[2], b[3]).String() + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(b[4:6])))
	case 0x03:
		n := make([]byte, 1)
		if _, err := io.ReadFull(br, n); err != nil {
			return
		}
		b := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = string(b[:n[0]]) + ":" + strconv.Itoa(int(binary.BigEndian.Uint16(b[n[0]:])))
	case 0x04:
		b := make([]byte, 18)
		if _, err := io.ReadFull(br, b); err != nil {
			return
		}
		host = net.JoinHostPort(net.IP(b[:16]).String(), strconv.Itoa(int(binary.BigEndian.Uint16(b[16:]))))
	default:
		return
	}

	up, err := net.Dial("tcp", host)
	if err != nil {
		c.Write([]byte{0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer up.Close()
	c.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if n := br.Buffered(); n > 0 {
		b := make([]byte, n)
		io.ReadFull(br, b)
		up.Write(b)
	}
	go func() {
		io.Copy(up, c)
		up.Close()
	}()
	io.Copy(c, up)
}

// selfSignedCert builds a cert valid for DNS name "localhost" only — no IP
// SAN — so strict verification against 127.0.0.1 fails deterministically.
func selfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(crand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func requestViaTunnel(t *testing.T, conn net.Conn, hostPort string) string {
	t.Helper()
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", hostPort)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	raw, err := io.ReadAll(conn)
	if err != nil && len(raw) == 0 {
		t.Fatalf("read through tunnel: %v", err)
	}
	return string(raw)
}

func TestDialViaHTTPConnect(t *testing.T) {
	target := startEchoTarget(t)

	t.Run("plain", func(t *testing.T) {
		pu := startHTTPConnectProxy(t, "", nil)
		conn, err := dialVia(context.Background(), pu, target, 2*time.Second, false)
		if err != nil {
			t.Fatalf("dialVia: %v", err)
		}
		defer conn.Close()
		if resp := requestViaTunnel(t, conn, target); !strings.Contains(resp, "dial-via-ok") {
			t.Fatalf("response = %q", resp)
		}
	})

	t.Run("auth ok", func(t *testing.T) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
		pu := startHTTPConnectProxy(t, want, nil)
		pu.User = url.UserPassword("u", "p")
		conn, err := dialVia(context.Background(), pu, target, 2*time.Second, false)
		if err != nil {
			t.Fatalf("dialVia: %v", err)
		}
		defer conn.Close()
		if resp := requestViaTunnel(t, conn, target); !strings.Contains(resp, "dial-via-ok") {
			t.Fatalf("response = %q", resp)
		}
	})

	t.Run("auth missing rejected", func(t *testing.T) {
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
		pu := startHTTPConnectProxy(t, want, nil)
		_, err := dialVia(context.Background(), pu, target, 2*time.Second, false)
		if err == nil || !strings.Contains(err.Error(), "407") {
			t.Fatalf("err = %v, want 407 failure", err)
		}
	})
}

func TestDialHTTPConnectSuccessReturnsImmediately(t *testing.T) {
	target := startEchoTarget(t)
	proxyURL := startHTTPConnectProxy(t, "", nil)
	const timeout = time.Second

	start := time.Now()
	conn, err := dialHTTPConnect(context.Background(), proxyURL, target, timeout, false)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("dialHTTPConnect: %v", err)
	}
	defer conn.Close()
	if elapsed >= timeout/2 {
		t.Fatalf("dialHTTPConnect took %s, want well below %s", elapsed, timeout)
	}
	if resp := requestViaTunnel(t, conn, target); !strings.Contains(resp, "dial-via-ok") {
		t.Fatalf("response = %q", resp)
	}
}

func TestDialViaHTTPSConnect(t *testing.T) {
	target := startEchoTarget(t)
	cert := selfSignedCert(t)

	t.Run("insecure accepted", func(t *testing.T) {
		pu := startHTTPConnectProxy(t, "", &tls.Config{Certificates: []tls.Certificate{cert}})
		conn, err := dialVia(context.Background(), pu, target, 2*time.Second, true)
		if err != nil {
			t.Fatalf("dialVia: %v", err)
		}
		defer conn.Close()
		if resp := requestViaTunnel(t, conn, target); !strings.Contains(resp, "dial-via-ok") {
			t.Fatalf("response = %q", resp)
		}
	})

	t.Run("verification enforced", func(t *testing.T) {
		pu := startHTTPConnectProxy(t, "", &tls.Config{Certificates: []tls.Certificate{cert}})
		if _, err := dialVia(context.Background(), pu, target, 2*time.Second, false); err == nil {
			t.Fatal("dialVia succeeded, want TLS verification failure")
		}
	})
}

func TestDialViaSocks5(t *testing.T) {
	target := startEchoTarget(t)

	t.Run("no auth", func(t *testing.T) {
		pu := startSocks5Proxy(t, "", "")
		conn, err := dialVia(context.Background(), pu, target, 2*time.Second, false)
		if err != nil {
			t.Fatalf("dialVia: %v", err)
		}
		defer conn.Close()
		if resp := requestViaTunnel(t, conn, target); !strings.Contains(resp, "dial-via-ok") {
			t.Fatalf("response = %q", resp)
		}
	})

	t.Run("auth ok", func(t *testing.T) {
		pu := startSocks5Proxy(t, "u", "p")
		pu.User = url.UserPassword("u", "p")
		conn, err := dialVia(context.Background(), pu, target, 2*time.Second, false)
		if err != nil {
			t.Fatalf("dialVia: %v", err)
		}
		defer conn.Close()
		if resp := requestViaTunnel(t, conn, target); !strings.Contains(resp, "dial-via-ok") {
			t.Fatalf("response = %q", resp)
		}
	})

	t.Run("auth missing rejected", func(t *testing.T) {
		pu := startSocks5Proxy(t, "u", "p")
		_, err := dialVia(context.Background(), pu, target, 2*time.Second, false)
		if err == nil {
			t.Fatal("dialVia succeeded without credentials, want auth failure")
		}
	})
}
