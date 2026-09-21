package socksdial

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"time"
)

// HalfConn is an upstream SOCKS5 connection that has completed the TCP dial,
// greeting, and method/auth negotiation but has not yet sent a CONNECT — so
// it carries no target-specific state and can be parked between the stages
// and later completed for any target.
//
// A HalfConn owns exactly one endpoint connection and one pooled handshake
// reader. Close releases both; CompleteConnect consumes the HalfConn (its
// endpoint connection moves to the returned net.Conn on success and is closed
// on failure). After either, the HalfConn must not be used again.
type HalfConn struct {
	conn net.Conn
	br   *bufio.Reader
	// deadline is the absolute handshake deadline armed during the half
	// stage. Dial hands the remainder of this one window to CompleteConnect
	// so a back-to-back dial keeps the single-budget behavior of the
	// undivided dial; a parked HalfConn ignores it because CompleteConnect
	// re-arms before any I/O.
	deadline time.Time
}

// DialHalf establishes the endpoint connection and negotiates the SOCKS5
// greeting and optional RFC 1929 username/password authentication. The
// returned HalfConn is ready to CompleteConnect against any target.
//
// Failure classes are the ones the proxy server's classification reads:
// ProxyDialError for endpoint dialing, ProxyAuthError for credential
// rejection, SocksHandshakeError for greeting/auth framing, and
// SocksProtocolError for request-scoped input problems (scheme, credential
// length). The endpoint connection is closed on every failure path.
func DialHalf(ctx context.Context, pu *url.URL, timeout time.Duration) (*HalfConn, error) {
	if pu.Scheme != "socks5" {
		return nil, &SocksProtocolError{Op: "validate scheme", Err: fmt.Errorf("unsupported upstream scheme %q", pu.Scheme)}
	}
	conn, err := dialTCP(ctx, upstreamHostPort(pu), timeout)
	if err != nil {
		return nil, err
	}
	hc := &HalfConn{conn: conn, deadline: time.Now().Add(timeout)}
	if err := conn.SetDeadline(hc.deadline); err != nil {
		_ = conn.Close()
		return nil, &SocksHandshakeError{Op: "set handshake deadline", Err: err}
	}
	hc.br = handshakeBufPool.Get().(*bufio.Reader)
	hc.br.Reset(conn)
	if err := hc.negotiate(pu); err != nil {
		_ = hc.Close()
		return nil, err
	}
	return hc, nil
}

// Close releases the half connection: the endpoint socket is closed and the
// pooled handshake reader recycled. Closing after CompleteConnect consumed
// the HalfConn, or closing twice, is safe for the reader (recycled once) and
// harmless for the socket (second close only reports an error, which is
// ignored); but the intended use is Close on a parked half connection that
// will never be completed.
func (hc *HalfConn) Close() error {
	if hc.br != nil {
		br := hc.br
		hc.br = nil
		br.Reset(nil)
		handshakeBufPool.Put(br)
	}
	return hc.conn.Close()
}

// failSetup and failHandshake release the half connection and wrap the cause
// in the error class the proxy server's failure classification reads.
func (hc *HalfConn) failSetup(op string, err error) (net.Conn, error) {
	_ = hc.Close()
	return nil, &SocksProtocolError{Op: op, Err: err}
}

func (hc *HalfConn) failHandshake(op string, err error) (net.Conn, error) {
	_ = hc.Close()
	return nil, &SocksHandshakeError{Op: op, Err: err}
}

// recycle returns the drained handshake reader to the pool without touching
// the endpoint connection — the success path of CompleteConnect, where the
// reader has nothing left buffered and the socket belongs to the caller.
func (hc *HalfConn) recycle() {
	if hc.br != nil {
		br := hc.br
		hc.br = nil
		br.Reset(nil)
		handshakeBufPool.Put(br)
	}
}

// negotiate performs the SOCKS5 greeting and optional RFC 1929
// username/password exchange. It reports failures as raw typed errors; the
// caller (DialHalf) releases the half connection.
func (hc *HalfConn) negotiate(pu *url.URL) error {
	user, pass := "", ""
	if pu.User != nil {
		user = pu.User.Username()
		pass, _ = pu.User.Password()
	}
	wantAuth := user != "" || pass != ""

	// VER NMETHODS METHODS...: no auth, plus username/password when the route
	// carries credentials (RFC 1929). One exact-cap buffer, one write.
	greet := make([]byte, 0, 4)
	greet = append(greet, 0x05, 0x01, 0x00)
	if wantAuth {
		greet[1] = 0x02
		greet = append(greet, 0x02)
	}
	if _, err := hc.conn.Write(greet); err != nil {
		return &SocksHandshakeError{Op: "send greeting", Err: err}
	}
	var hdr [4]byte
	choice := hdr[:2]
	if _, err := io.ReadFull(hc.br, choice); err != nil {
		return &SocksHandshakeError{Op: "read greeting", Err: err}
	}
	if choice[0] != 0x05 {
		return &SocksHandshakeError{Op: "read greeting", Err: fmt.Errorf("unexpected SOCKS version 0x%02x", choice[0])}
	}
	switch choice[1] {
	case 0x00: // no auth needed
	case 0x02:
		if !wantAuth {
			return &ProxyAuthError{Reason: "endpoint requires credentials but none are configured"}
		}
		if len(user) > 255 || len(pass) > 255 {
			return &SocksProtocolError{Op: "encode credentials", Err: fmt.Errorf("username or password exceeds SOCKS5 length limit")}
		}
		// ULEN UNAME PLEN PASSWD, one exact-cap buffer: credentials are
		// bounded by the 255-byte length checks above.
		b := make([]byte, 0, 3+len(user)+len(pass))
		b = append(b, 0x01, byte(len(user)))
		b = append(b, user...)
		b = append(b, byte(len(pass)))
		b = append(b, pass...)
		if _, err := hc.conn.Write(b); err != nil {
			return &SocksHandshakeError{Op: "send authentication", Err: err}
		}
		reply := hdr[:2]
		if _, err := io.ReadFull(hc.br, reply); err != nil {
			return &SocksHandshakeError{Op: "read authentication", Err: err}
		}
		if reply[0] != 0x01 {
			return &SocksHandshakeError{Op: "read authentication", Err: fmt.Errorf("unexpected auth version 0x%02x", reply[0])}
		}
		if reply[1] != 0x00 {
			return &ProxyAuthError{Reason: "endpoint rejected credentials"}
		}
	case 0xff:
		return &ProxyAuthError{Reason: "endpoint accepted no offered authentication method"}
	default:
		return &SocksHandshakeError{Op: "negotiate authentication", Err: fmt.Errorf("unsupported method 0x%02x", choice[1])}
	}
	return nil
}

// CompleteConnect sends the CONNECT request for t and finishes the
// outbound handshake. On success the endpoint connection (with any bytes an
// upstream pipelined behind its reply) is returned ready for transport and
// the HalfConn is consumed; on failure the endpoint connection is closed and
// the HalfConn is consumed as well.
//
// The deadline is re-armed before the first byte of I/O: a HalfConn that was
// parked between the stages carries a long-expired half-stage deadline, and
// touching the socket before re-arming would fail every such completion.
// timeout is the caller's budget for this stage alone.
func (hc *HalfConn) CompleteConnect(t Target, timeout time.Duration) (net.Conn, error) {
	if hc.br == nil {
		// Already released (Close, or a prior CompleteConnect): a consumed
		// half connection cannot be completed again. Setup class — a local
		// programming error must not touch route health or trigger a retry.
		return nil, &SocksProtocolError{Op: "complete connect", Err: errors.New("half connection already released")}
	}
	if err := hc.conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return hc.failHandshake("set handshake deadline", err)
	}
	req, err := socksConnectRequest(t)
	if err != nil {
		return hc.failSetup("encode target", err)
	}
	if _, err := hc.conn.Write(req); err != nil {
		return hc.failHandshake("send connect", err)
	}
	var hdr [4]byte
	head := hdr[:4]
	if _, err := io.ReadFull(hc.br, head); err != nil {
		return hc.failHandshake("read connect", err)
	}
	if head[0] != 0x05 || head[2] != 0x00 {
		return hc.failHandshake("read connect", fmt.Errorf("invalid SOCKS response"))
	}
	if head[1] != 0x00 {
		// The endpoint spoke a complete reply refusing this target: the route
		// works, the (route, target) pair does not. SocksReplyError inside the
		// handshake error is what splits pair-scoped from route-scoped health.
		return hc.failHandshake("connect target", &SocksReplyError{Reply: head[1]})
	}
	if err := discardSocksBoundAddress(hc.br, head[3]); err != nil {
		return hc.failHandshake("read bound address", err)
	}
	if err := hc.conn.SetDeadline(time.Time{}); err != nil {
		_ = hc.Close()
		return nil, &SocksHandshakeError{Op: "clear handshake deadline", Err: err}
	}
	out := withBufferedPrefix(hc.conn, hc.br)
	// The handshake reader is fully drained here — withBufferedPrefix copied
	// any pipelined prefix out of it — so it goes back to the pool while the
	// endpoint connection belongs to the caller.
	hc.recycle()
	return out, nil
}
