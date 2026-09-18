package proxyserver

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"time"
)

// ProxyDialError means DNS resolution or TCP dialing of the configured SOCKS
// endpoint failed. It is the only error category that changes dial health.
type ProxyDialError struct{ Err error }

func (e *ProxyDialError) Error() string { return fmt.Sprintf("dial SOCKS endpoint: %v", e.Err) }
func (e *ProxyDialError) Unwrap() error { return e.Err }

// ProxyAuthError means a connected SOCKS endpoint could not authenticate this
// route. It is distinct from endpoint reachability.
type ProxyAuthError struct{ Reason string }

func (e *ProxyAuthError) Error() string { return "SOCKS authentication failed: " + e.Reason }

// SocksProtocolError covers every SOCKS or target setup failure after endpoint
// TCP dialing succeeded. It must not change route health or trigger a retry.
type SocksProtocolError struct {
	Op  string
	Err error
}

func (e *SocksProtocolError) Error() string {
	if e.Err == nil {
		return "SOCKS protocol error during " + e.Op
	}
	return fmt.Sprintf("SOCKS protocol error during %s: %v", e.Op, e.Err)
}
func (e *SocksProtocolError) Unwrap() error { return e.Err }

func isProxyDialError(err error) bool {
	var dialErr *ProxyDialError
	return errorAs(err, &dialErr)
}

func isProxyAuthError(err error) bool {
	var authErr *ProxyAuthError
	return errorAs(err, &authErr)
}

// errorAs is a narrow seam that keeps the public classifiers above together.
func errorAs(err error, target any) bool {
	return errors.As(err, target)
}

// dialVia establishes a TCP connection to targetAddr through a SOCKS5 upstream.
// The returned connection is ready for arbitrary byte transport.
func dialVia(ctx context.Context, pu *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	if pu.Scheme != "socks5" {
		return nil, &SocksProtocolError{Op: "validate scheme", Err: fmt.Errorf("unsupported upstream scheme %q", pu.Scheme)}
	}
	return dialSocks5(ctx, pu, targetAddr, timeout)
}

// upstreamHostPort returns the dial address of the SOCKS endpoint, applying its
// default port when absent.
func upstreamHostPort(pu *url.URL) string {
	if port := pu.Port(); port != "" {
		return net.JoinHostPort(pu.Hostname(), port)
	}
	return net.JoinHostPort(pu.Hostname(), "1080")
}

func dialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, &ProxyDialError{Err: err}
	}
	return conn, nil
}

// dialSocks5 tunnels to targetAddr through a SOCKS5 proxy per RFC 1928 with
// optional username/password authentication per RFC 1929. Hostnames are sent
// as domain names so the SOCKS endpoint resolves them.
func dialSocks5(ctx context.Context, pu *url.URL, targetAddr string, timeout time.Duration) (net.Conn, error) {
	conn, err := dialTCP(ctx, upstreamHostPort(pu), timeout)
	if err != nil {
		return nil, err
	}
	failProtocol := func(op string, err error) (net.Conn, error) {
		conn.Close()
		return nil, &SocksProtocolError{Op: op, Err: err}
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
		return failProtocol("send greeting", err)
	}
	choice := make([]byte, 2)
	if _, err := io.ReadFull(br, choice); err != nil {
		return failProtocol("read greeting", err)
	}
	if choice[0] != 0x05 {
		return failProtocol("read greeting", fmt.Errorf("unexpected SOCKS version 0x%02x", choice[0]))
	}
	switch choice[1] {
	case 0x00: // no auth needed
	case 0x02:
		if !wantAuth {
			conn.Close()
			return nil, &ProxyAuthError{Reason: "endpoint requires credentials but none are configured"}
		}
		if len(user) > 255 || len(pass) > 255 {
			return failProtocol("encode credentials", fmt.Errorf("username or password exceeds SOCKS5 length limit"))
		}
		b := append([]byte{0x01, byte(len(user))}, user...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		if _, err := conn.Write(b); err != nil {
			return failProtocol("send authentication", err)
		}
		reply := make([]byte, 2)
		if _, err := io.ReadFull(br, reply); err != nil {
			return failProtocol("read authentication", err)
		}
		if reply[0] != 0x01 {
			return failProtocol("read authentication", fmt.Errorf("unexpected auth version 0x%02x", reply[0]))
		}
		if reply[1] != 0x00 {
			conn.Close()
			return nil, &ProxyAuthError{Reason: "endpoint rejected credentials"}
		}
	case 0xff:
		conn.Close()
		return nil, &ProxyAuthError{Reason: "endpoint accepted no offered authentication method"}
	default:
		return failProtocol("negotiate authentication", fmt.Errorf("unsupported method 0x%02x", choice[1]))
	}

	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return failProtocol("parse target", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return failProtocol("parse target", fmt.Errorf("invalid target port %q", portStr))
	}
	req, err := socksConnectRequest(host, uint16(port))
	if err != nil {
		return failProtocol("encode target", err)
	}
	if _, err := conn.Write(req); err != nil {
		return failProtocol("send connect", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(br, head); err != nil {
		return failProtocol("read connect", err)
	}
	if head[0] != 0x05 || head[2] != 0x00 {
		return failProtocol("read connect", fmt.Errorf("invalid SOCKS response"))
	}
	if head[1] != 0x00 {
		return failProtocol("connect target", fmt.Errorf("SOCKS reply 0x%02x", head[1]))
	}
	if err := discardSocksBoundAddress(br, head[3]); err != nil {
		return failProtocol("read bound address", err)
	}
	conn.SetDeadline(time.Time{})
	return withBufferedPrefix(conn, br), nil
}

func socksConnectRequest(host string, port uint16) ([]byte, error) {
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			req = append(req, 0x01)
			req = append(req, v4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		if len(host) == 0 || len(host) > 255 {
			return nil, fmt.Errorf("target hostname length %d is invalid", len(host))
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, host...)
	}
	return append(req, byte(port>>8), byte(port)), nil
}

func discardSocksBoundAddress(br *bufio.Reader, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.CopyN(io.Discard, br, 6)
		return err
	case 0x03:
		n, err := br.ReadByte()
		if err != nil {
			return err
		}
		_, err = io.CopyN(io.Discard, br, int64(n)+2)
		return err
	case 0x04:
		_, err := io.CopyN(io.Discard, br, 18)
		return err
	default:
		return fmt.Errorf("unsupported bound address type 0x%02x", atyp)
	}
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
