package proxyserver

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// dialVia establishes a TCP connection to targetAddr (host:port) through the
// upstream proxy pu. The returned connection is ready for arbitrary byte
// transport (TLS or plain).
func dialVia(ctx context.Context, pu *url.URL, targetAddr string, timeout time.Duration, tlsInsecure bool) (net.Conn, error) {
	switch pu.Scheme {
	case "http", "https":
		return dialHTTPConnect(ctx, pu, targetAddr, timeout, tlsInsecure)
	case "socks5":
		return dialSocks5(ctx, pu, targetAddr, timeout)
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q", pu.Scheme)
	}
}

// upstreamHostPort returns the dial address of the upstream proxy itself,
// applying the scheme default port when absent.
func upstreamHostPort(pu *url.URL) string {
	if port := pu.Port(); port != "" {
		return net.JoinHostPort(pu.Hostname(), port)
	}
	switch pu.Scheme {
	case "https":
		return net.JoinHostPort(pu.Hostname(), "443")
	case "socks5":
		return net.JoinHostPort(pu.Hostname(), "1080")
	default:
		return net.JoinHostPort(pu.Hostname(), "80")
	}
}

func dialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

// dialHTTPConnect tunnels to targetAddr through an HTTP proxy via CONNECT,
// optionally over TLS to the proxy (scheme https) with Basic auth.
func dialHTTPConnect(ctx context.Context, pu *url.URL, targetAddr string, timeout time.Duration, tlsInsecure bool) (net.Conn, error) {
	conn, err := dialTCP(ctx, upstreamHostPort(pu), timeout)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", pu.Host, err)
	}
	if pu.Scheme == "https" {
		hsCtx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		tc := tls.Client(conn, &tls.Config{ServerName: pu.Hostname(), InsecureSkipVerify: tlsInsecure})
		if err := tc.HandshakeContext(hsCtx); err != nil {
			conn.Close()
			return nil, fmt.Errorf("upstream TLS handshake: %w", err)
		}
		conn = tc
	}

	req := "CONNECT " + targetAddr + " HTTP/1.1\r\nHost: " + targetAddr + "\r\n"
	if pu.User != nil && pu.User.String() != "" {
		req += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(pu.User.String())) + "\r\n"
	}
	req += "\r\n"

	conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send CONNECT: %w", err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		conn.Close()
		return nil, fmt.Errorf("upstream CONNECT failed: %s", resp.Status)
	}
	conn.SetDeadline(time.Time{})
	return withBufferedPrefix(conn, br), nil
}

// dialSocks5 tunnels to targetAddr through a SOCKS5 proxy per RFC 1928 with
// optional username/password authentication (RFC 1929). The target host is
// sent as a domain name; the proxy resolves it.
func dialSocks5(ctx context.Context, pu *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	conn, err := dialTCP(ctx, upstreamHostPort(pu), timeout)
	if err != nil {
		return nil, fmt.Errorf("dial upstream %s: %w", pu.Host, err)
	}

	user, pass := "", ""
	if pu.User != nil {
		user = pu.User.Username()
		pass, _ = pu.User.Password()
	}
	wantAuth := user != "" || pass != ""

	conn.SetDeadline(time.Now().Add(timeout))
	br := bufio.NewReader(conn)

	methods := []byte{0x00} // no auth
	if wantAuth {
		methods = []byte{0x00, 0x02}
	}
	if _, err := conn.Write(append([]byte{0x05, byte(len(methods))}, methods...)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting: %w", err)
	}
	choice := make([]byte, 2)
	if _, err := io.ReadFull(br, choice); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 greeting reply: %w", err)
	}
	if choice[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("socks5: not a SOCKS5 server")
	}
	switch choice[1] {
	case 0x00: // no auth needed
	case 0x02:
		if !wantAuth {
			conn.Close()
			return nil, fmt.Errorf("socks5: proxy requires auth, none configured")
		}
		b := append([]byte{0x01, byte(len(user))}, user...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		if _, err := conn.Write(b); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth: %w", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(br, reply); err != nil {
			conn.Close()
			return nil, fmt.Errorf("socks5 auth reply: %w", err)
		}
		if reply[1] != 0x00 {
			conn.Close()
			return nil, fmt.Errorf("socks5: auth rejected")
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("socks5: no acceptable auth method (0x%02x)", choice[1])
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 target: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		conn.Close()
		return nil, fmt.Errorf("socks5 target: bad port %q", portStr)
	}
	req := append([]byte{0x05, 0x01, 0x00, 0x03, byte(len(host))}, host...)
	req = append(req, byte(port>>8), byte(port&0xff))
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("socks5 connect reply: %w", err)
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("socks5: connect failed (rep=0x%02x)", head[1])
	}
	switch head[3] { // skip bound address
	case 0x01:
		io.CopyN(io.Discard, br, 6)
	case 0x03:
		n := make([]byte, 1)
		io.ReadFull(br, n)
		io.CopyN(io.Discard, br, int64(n[0])+2)
	case 0x04:
		io.CopyN(io.Discard, br, 18)
	}
	conn.SetDeadline(time.Time{})
	return withBufferedPrefix(conn, br), nil
}

// withBufferedPrefix wraps conn so bytes already buffered in br (an upstream
// may pipeline data with its handshake reply) are delivered before the raw
// stream.
func withBufferedPrefix(conn net.Conn, br *bufio.Reader) net.Conn {
	if br.Buffered() == 0 {
		return conn
	}
	prefix := make([]byte, br.Buffered())
	io.ReadFull(br, prefix)
	return &prefixConn{Conn: conn, prefix: prefix}
}

type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(b []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(b, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(b)
}
