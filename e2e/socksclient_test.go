package e2e_test

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"testing"
	"time"
)

// The inbound listeners speak RFC 1928 SOCKS5 with no authentication. These
// helpers are the test-side client: they greet, send one CONNECT (hostnames
// stay domain addresses, so resolution happens at the outbound route, exactly
// like socks5h://), validate the reply, and hand back the raw tunnel.

// socksTransport returns an http.Transport whose dialer establishes one
// inbound SOCKS5 tunnel per connection; HTTP and TLS then run inside it.
func socksTransport(proxyAddr string, insecureTLS bool) *http.Transport {
	t := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, addr string) (net.Conn, error) {
			return dialSocksTunnel(ctx, proxyAddr, addr)
		},
	}
	if insecureTLS {
		t.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // test-only target
	}
	return t
}

// dialSocksTunnel connects through a gateway listener to targetAddr
// (host:port) and returns the established tunnel.
func dialSocksTunnel(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial gateway: %w", err)
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send greeting: %w", err)
	}
	choice := make([]byte, 2)
	if _, err := io.ReadFull(conn, choice); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read method selection: %w", err)
	}
	if choice[0] != 0x05 || choice[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("unexpected method selection 0x%02x 0x%02x", choice[0], choice[1])
	}
	req, err := socksConnectRequestBytes(targetAddr)
	if err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := conn.Write(req); err != nil {
		conn.Close()
		return nil, fmt.Errorf("send connect: %w", err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		conn.Close()
		return nil, fmt.Errorf("read connect reply: %w", err)
	}
	if head[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("unexpected reply version 0x%02x", head[0])
	}
	if head[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("gateway rejected CONNECT with reply 0x%02x", head[1])
	}
	// BND.ADDR/PORT must be ignored, but the frame must still be consumed.
	if err := discardSocksBND(conn, head[3]); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// socksConnectRequestBytes renders a CONNECT request for host:port, sending
// hostnames as domain addresses (ATYP 0x03).
func socksConnectRequestBytes(targetAddr string) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("parse target %q: %w", targetAddr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", portStr)
	}
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
	var portBytes [2]byte
	binary.BigEndian.PutUint16(portBytes[:], uint16(port))
	return append(req, portBytes[:]...), nil
}

// discardSocksBND consumes the bound-address portion of a reply frame.
func discardSocksBND(conn net.Conn, atyp byte) error {
	switch atyp {
	case 0x01:
		_, err := io.CopyN(io.Discard, conn, 6)
		return err
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return err
		}
		_, err := io.CopyN(io.Discard, conn, int64(n[0])+2)
		return err
	case 0x04:
		_, err := io.CopyN(io.Discard, conn, 18)
		return err
	default:
		return fmt.Errorf("unsupported bound address type 0x%02x", atyp)
	}
}

// socksTunnel establishes one inbound SOCKS5 tunnel through a gateway
// listener, failing the test on any protocol or reply error. Callers speak
// HTTP, TLS, or raw bytes over the returned connection.
func socksTunnel(t testing.TB, proxyAddr, targetAddr string) net.Conn {
	t.Helper()
	conn, err := dialSocksTunnel(context.Background(), proxyAddr, targetAddr)
	if err != nil {
		t.Fatalf("socks tunnel to %s via %s: %v", targetAddr, proxyAddr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// socksProbe connects and sends a CONNECT built from raw fields, returning the
// full raw reply frame (after the 4-byte head) for conformance assertions. A
// greetingReply of nil uses the standard 05 01 00; a non-nil request replaces
// the standard CONNECT frame entirely. It returns the reply head (4 bytes),
// the remainder of the reply frame per the reply's own ATYP, and any error.
func socksProbe(t testing.TB, proxyAddr string, greeting []byte, request []byte) (head [4]byte, rest []byte, err error) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial gateway: %v", err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if greeting == nil {
		greeting = []byte{0x05, 0x01, 0x00}
	}
	if _, err := conn.Write(greeting); err != nil {
		return head, nil, err
	}
	greetReply := make([]byte, 2)
	if _, err := io.ReadFull(conn, greetReply); err != nil {
		return head, nil, fmt.Errorf("read method selection: %w", err)
	}
	if greetReply[0] != 0x05 || greetReply[1] != 0x00 {
		return head, nil, fmt.Errorf("method selection 0x%02x 0x%02x", greetReply[0], greetReply[1])
	}
	if _, err := conn.Write(request); err != nil {
		return head, nil, err
	}
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return head, nil, err
		}
		return head, nil, err
	}
	var want int
	switch head[3] {
	case 0x01:
		want = 6
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			return head, nil, err
		}
		rest = append(rest, n[0])
		want = int(n[0]) + 2
	case 0x04:
		want = 18
	default:
		return head, nil, fmt.Errorf("unsupported reply ATYP 0x%02x", head[3])
	}
	rest = append(rest, make([]byte, want)...)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return head, nil, err
	}
	return head, rest, nil
}
