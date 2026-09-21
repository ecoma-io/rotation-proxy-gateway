// Package socksdial dials TCP targets through SOCKS5 upstream routes. It is
// shared by the proxy server and the rotation engine so both speak identical
// SOCKS semantics and error classification. Every dial carries its target's
// address type explicitly: the CONNECT request encodes exactly the type the
// caller hands over and never re-infers it from the host string.
package socksdial

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// handshakeBufPool lends the buffered readers that frame the outbound SOCKS5
// exchange: method choice, auth reply, connect reply, and bound address — a
// few dozen bytes, so one 512B fill covers the whole handshake. An upstream
// that pipelines data behind its success reply front-runs at most one buffer
// into the relay prefix and streams the rest from the socket.
const handshakeBufSize = 512

var handshakeBufPool = sync.Pool{
	New: func() any { return bufio.NewReaderSize(nil, handshakeBufSize) },
}

// ProxyDialError means DNS resolution or TCP dialing of the configured SOCKS
// endpoint failed. It is the only error category that changes dial health.
type ProxyDialError struct{ Err error }

func (e *ProxyDialError) Error() string { return fmt.Sprintf("dial SOCKS endpoint: %v", e.Err) }
func (e *ProxyDialError) Unwrap() error { return e.Err }

// ProxyAuthError means a connected SOCKS endpoint could not authenticate this
// route. It is distinct from endpoint reachability.
type ProxyAuthError struct{ Reason string }

func (e *ProxyAuthError) Error() string { return "SOCKS authentication failed: " + e.Reason }

// SocksProtocolError covers local request-scoped failures that behave the
// same on every route: an unsupported upstream scheme, oversized configured
// credentials, and invalid target encoding. It must not change route health
// or trigger a retry.
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

// SocksHandshakeError means the network exchange with a connected SOCKS
// endpoint failed before the target tunnel was established: greeting, method
// or authentication framing, CONNECT framing or reply, and bound-address
// reads. No client bytes have crossed the tunnel, so like ProxyDialError it
// records dial health and permits a distinct-route retry; it logs under its
// own error kind. When the endpoint itself answered the CONNECT request with
// an explicit non-zero reply code the Err chain carries a SocksReplyError:
// the route works and the refusal is about this target, so the failure is
// target-scoped rather than route-scoped (see IsConnectTargetError).
type SocksHandshakeError struct {
	Op  string
	Err error
}

func (e *SocksHandshakeError) Error() string {
	if e.Err == nil {
		return "SOCKS handshake failed during " + e.Op
	}
	return fmt.Sprintf("SOCKS handshake failed during %s: %v", e.Op, e.Err)
}
func (e *SocksHandshakeError) Unwrap() error { return e.Err }

// IsDialError reports whether err is a SOCKS endpoint dial failure.
func IsDialError(err error) bool {
	var dialErr *ProxyDialError
	return errors.As(err, &dialErr)
}

// IsAuthError reports whether err is a SOCKS authentication failure.
func IsAuthError(err error) bool {
	var authErr *ProxyAuthError
	return errors.As(err, &authErr)
}

// IsHandshakeError reports whether err is a connected-endpoint handshake
// failure that occurred before the target tunnel carried any client bytes.
func IsHandshakeError(err error) bool {
	var handshakeErr *SocksHandshakeError
	return errors.As(err, &handshakeErr)
}

// SocksReplyError marks the CONNECT-stage failure where a connected endpoint
// answered the CONNECT request itself with an explicit non-zero reply code
// (RFC 1928 REP). The greeting succeeded and a complete reply arrived, so the
// route demonstrably works; what is refused is this target. It always travels
// wrapped in a SocksHandshakeError — same stage, same retry treatment — but
// the pool scopes the resulting cooldown to the (route, target) pair instead
// of the route.
type SocksReplyError struct {
	Reply byte
}

func (e *SocksReplyError) Error() string { return fmt.Sprintf("SOCKS reply 0x%02x", e.Reply) }

// IsConnectTargetError reports whether err is a CONNECT request the endpoint
// explicitly refused with a non-zero reply code — the target-scoped half of
// the handshake taxonomy. Every other handshake failure (greeting, auth
// framing, CONNECT framing or reply I/O, bound-address reads) stays
// route-scoped.
func IsConnectTargetError(err error) bool {
	var replyErr *SocksReplyError
	return errors.As(err, &replyErr)
}

// AddrType is a SOCKS5 address type (ATYP, RFC 1928): the wire encoding a
// CONNECT request carries for its target. The values match the RFC constants
// so a type can travel to and from raw frames without a mapping table.
type AddrType uint8

const (
	// AddrIPv4 sends the target as a 4-byte IPv4 address (ATYP 0x01).
	AddrIPv4 AddrType = 0x01
	// AddrDomain sends the target as a length-prefixed hostname (ATYP 0x03):
	// the SOCKS endpoint resolves it, and nothing between the caller and the
	// wire may resolve or rewrite it.
	AddrDomain AddrType = 0x03
	// AddrIPv6 sends the target as a 16-byte IPv6 address (ATYP 0x04).
	AddrIPv6 AddrType = 0x04
)

// Target is one CONNECT destination whose address type is fixed by the
// caller. The type is authoritative: encoding reproduces exactly the type
// given here and never re-derives it from Host, so a target the inbound
// client framed as IPv4, IPv6, or a domain arrives at the SOCKS endpoint
// framed the same way.
type Target struct {
	// Host is the literal address or hostname. It is never resolved locally.
	Host string
	Port uint16
	Type AddrType
}

// Addr renders the host:port identity used for pool state and logs.
func (t Target) Addr() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}

// TargetFromAddr parses host:port and classifies the host into its address
// type once, at target creation. It exists for dials that originate inside
// the gateway — the rotation engine's ip-check endpoint, whose address comes
// from configuration rather than from an inbound frame. Callers reproducing
// an inbound frame must carry the frame's own ATYP instead of re-deriving it
// here.
func TargetFromAddr(addr string) (Target, error) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return Target{}, fmt.Errorf("invalid target address: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return Target{}, fmt.Errorf("invalid target port %q", portStr)
	}
	t := Target{Host: host, Port: uint16(port), Type: AddrDomain}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			t.Type = AddrIPv4
		} else {
			t.Type = AddrIPv6
		}
	}
	return t, nil
}

// Dial establishes a TCP connection to t through a SOCKS5 upstream, encoding
// t.Type as the CONNECT address type. The returned connection is ready for
// arbitrary byte transport.
func Dial(ctx context.Context, pu *url.URL, t Target, timeout time.Duration) (net.Conn, error) {
	if pu.Scheme != "socks5" {
		return nil, &SocksProtocolError{Op: "validate scheme", Err: fmt.Errorf("unsupported upstream scheme %q", pu.Scheme)}
	}
	return dialSocks5(ctx, pu, t, timeout)
}

// DialTCP dials addr directly; endpoint failures wrap ProxyDialError.
func DialTCP(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	return dialTCP(ctx, addr, timeout)
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
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, &ProxyDialError{Err: err}
	}
	return conn, nil
}

// failSetup and failHandshake close the endpoint connection and wrap the
// cause in the error class the proxy server's failure classification reads.
// Plain functions rather than closures over conn: the failure paths then
// allocate no extra escape-to-heap bookkeeping per call.
func failSetup(conn net.Conn, op string, err error) (net.Conn, error) {
	_ = conn.Close()
	return nil, &SocksProtocolError{Op: op, Err: err}
}

func failHandshake(conn net.Conn, op string, err error) (net.Conn, error) {
	_ = conn.Close()
	return nil, &SocksHandshakeError{Op: op, Err: err}
}

// dialSocks5 tunnels to t through a SOCKS5 proxy per RFC 1928 with optional
// username/password authentication per RFC 1929. The CONNECT request carries
// t.Type exactly as given; a domain target reaches the endpoint as a name for
// it to resolve.
func dialSocks5(ctx context.Context, pu *url.URL, t Target, timeout time.Duration) (net.Conn, error) {
	conn, err := dialTCP(ctx, upstreamHostPort(pu), timeout)
	if err != nil {
		return nil, err
	}
	user, pass := "", ""
	if pu.User != nil {
		user = pu.User.Username()
		pass, _ = pu.User.Password()
	}
	wantAuth := user != "" || pass != ""

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return failHandshake(conn, "set handshake deadline", err)
	}
	br := handshakeBufPool.Get().(*bufio.Reader)
	br.Reset(conn)
	defer func() {
		br.Reset(nil)
		handshakeBufPool.Put(br)
	}()

	// VER NMETHODS METHODS...: no auth, plus username/password when the route
	// carries credentials (RFC 1929). One exact-cap buffer, one write.
	greet := make([]byte, 0, 4)
	greet = append(greet, 0x05, 0x01, 0x00)
	if wantAuth {
		greet[1] = 0x02
		greet = append(greet, 0x02)
	}
	if _, err := conn.Write(greet); err != nil {
		return failHandshake(conn, "send greeting", err)
	}
	var hdr [4]byte
	choice := hdr[:2]
	if _, err := io.ReadFull(br, choice); err != nil {
		return failHandshake(conn, "read greeting", err)
	}
	if choice[0] != 0x05 {
		return failHandshake(conn, "read greeting", fmt.Errorf("unexpected SOCKS version 0x%02x", choice[0]))
	}
	switch choice[1] {
	case 0x00: // no auth needed
	case 0x02:
		if !wantAuth {
			_ = conn.Close()
			return nil, &ProxyAuthError{Reason: "endpoint requires credentials but none are configured"}
		}
		if len(user) > 255 || len(pass) > 255 {
			return failSetup(conn, "encode credentials", fmt.Errorf("username or password exceeds SOCKS5 length limit"))
		}
		// ULEN UNAME PLEN PASSWD, one exact-cap buffer: credentials are
		// bounded by the 255-byte length checks above.
		b := make([]byte, 0, 3+len(user)+len(pass))
		b = append(b, 0x01, byte(len(user)))
		b = append(b, user...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		if _, err := conn.Write(b); err != nil {
			return failHandshake(conn, "send authentication", err)
		}
		reply := hdr[:2]
		if _, err := io.ReadFull(br, reply); err != nil {
			return failHandshake(conn, "read authentication", err)
		}
		if reply[0] != 0x01 {
			return failHandshake(conn, "read authentication", fmt.Errorf("unexpected auth version 0x%02x", reply[0]))
		}
		if reply[1] != 0x00 {
			_ = conn.Close()
			return nil, &ProxyAuthError{Reason: "endpoint rejected credentials"}
		}
	case 0xff:
		_ = conn.Close()
		return nil, &ProxyAuthError{Reason: "endpoint accepted no offered authentication method"}
	default:
		return failHandshake(conn, "negotiate authentication", fmt.Errorf("unsupported method 0x%02x", choice[1]))
	}

	req, err := socksConnectRequest(t)
	if err != nil {
		return failSetup(conn, "encode target", err)
	}
	if _, err := conn.Write(req); err != nil {
		return failHandshake(conn, "send connect", err)
	}
	head := hdr[:4]
	if _, err := io.ReadFull(br, head); err != nil {
		return failHandshake(conn, "read connect", err)
	}
	if head[0] != 0x05 || head[2] != 0x00 {
		return failHandshake(conn, "read connect", fmt.Errorf("invalid SOCKS response"))
	}
	if head[1] != 0x00 {
		// The endpoint spoke a complete reply refusing this target: the route
		// works, the (route, target) pair does not. SocksReplyError inside the
		// handshake error is what splits pair-scoped from route-scoped health.
		return failHandshake(conn, "connect target", &SocksReplyError{Reply: head[1]})
	}
	if err := discardSocksBoundAddress(br, head[3]); err != nil {
		return failHandshake(conn, "read bound address", err)
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		_ = conn.Close()
		return nil, &SocksHandshakeError{Op: "clear handshake deadline", Err: err}
	}
	return withBufferedPrefix(conn, br), nil
}

// socksConnectRequest encodes the CONNECT request — VER CMD RSV ATYP
// DST.ADDR DST.PORT — carrying exactly t.Type. IPv4 goes out as four address
// bytes, IPv6 as sixteen, and a domain as the original hostname with its
// length prefix for the endpoint to resolve. The caller's type is never
// second-guessed from Host, and a mismatched Host fails locally as a setup
// error rather than silently changing address families.
func socksConnectRequest(t Target) ([]byte, error) {
	if t.Port == 0 {
		return nil, errors.New("target port is zero")
	}
	// The largest form carries a 255-byte domain name. One exact-cap buffer
	// instead of an append-grown one.
	req := make([]byte, 0, 4+1+255+2)
	req = append(req, 0x05, 0x01, 0x00)
	switch t.Type {
	case AddrIPv4:
		ip := net.ParseIP(t.Host)
		if ip == nil || ip.To4() == nil {
			return nil, errors.New("target host does not encode as an IPv4 address")
		}
		req = append(req, byte(AddrIPv4))
		req = append(req, ip.To4()...)
	case AddrIPv6:
		ip := net.ParseIP(t.Host)
		if ip == nil {
			return nil, errors.New("target host does not encode as an IPv6 address")
		}
		req = append(req, byte(AddrIPv6))
		req = append(req, ip.To16()...)
	case AddrDomain:
		if len(t.Host) == 0 || len(t.Host) > 255 {
			return nil, fmt.Errorf("target hostname length %d is invalid", len(t.Host))
		}
		req = append(req, byte(AddrDomain), byte(len(t.Host)))
		req = append(req, t.Host...)
	default:
		return nil, fmt.Errorf("unsupported target address type %d", t.Type)
	}
	return append(req, byte(t.Port>>8), byte(t.Port)), nil
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
	// Buffered reports the bytes available to read immediately, so this exact
	// read cannot block or truncate the prefix.
	_, _ = io.ReadFull(br, prefix)
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
