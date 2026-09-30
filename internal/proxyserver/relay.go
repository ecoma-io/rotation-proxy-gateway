package proxyserver

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"rotation-proxy-gateway/internal/pool"

	"github.com/rs/zerolog"
)

// copyBufPool lends 64KiB relay buffers. Established CONNECT tunnels are a hot
// path, and io.Copy's implicit 32KiB buffer would be allocated per direction;
// retaining this pool keeps the HTTP ingress replacement from changing the
// data-plane allocation profile after a tunnel is established.
var copyBufPool = sync.Pool{
	New: func() any {
		buf := make([]byte, 64<<10)
		return &buf
	},
}

func copyWithPooledBuffer(dst io.Writer, src io.Reader) (int64, error) {
	bufp := copyBufPool.Get().(*[]byte)
	n, err := io.CopyBuffer(dst, src, *bufp)
	copyBufPool.Put(bufp)
	return n, err
}

// upstreamBreakError marks a relay failure raised on the upstream side of the
// response direction. It keeps a target read failure distinct from a client
// write failure, so the close record can say a tunnel broke without turning a
// post-establishment failure into route health feedback.
type upstreamBreakError struct{ err error }

func (e *upstreamBreakError) Error() string { return e.err.Error() }
func (e *upstreamBreakError) Unwrap() error { return e.err }

func isUpstreamBreak(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) {
		return false
	}
	var brk *upstreamBreakError
	return errors.As(err, &brk)
}

func copyToClient(client, upstream net.Conn) (int64, error) {
	bufp := copyBufPool.Get().(*[]byte)
	defer copyBufPool.Put(bufp)
	buf := *bufp
	var total int64
	for {
		n, rerr := upstream.Read(buf)
		if n > 0 {
			m, werr := client.Write(buf[:n])
			total += int64(m)
			if werr != nil {
				return total, fmt.Errorf("write to client: %w", werr)
			}
			if m < n {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, &upstreamBreakError{err: rerr}
		}
	}
}

// prefixConn serves CONNECT bytes that net/http read ahead while it parsed the
// request headers before falling through to the original client socket. It is
// deliberately only used by CONNECT; an absolute-form request body remains the
// Request.Body consumed by ReverseProxy, never a raw tunnel prefix.
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

func tcpConnOf(c net.Conn) *net.TCPConn {
	if pc, ok := c.(*prefixConn); ok {
		c = pc.Conn
	}
	tc, _ := c.(*net.TCPConn)
	return tc
}

// relayTunnel keeps the close ordering, half-close propagation, upstream-reset
// protection, and close-record behavior of the former inbound tunnel path. It
// is invoked only after CONNECT's HTTP 200 is written and all client deadlines
// are cleared; no relay result is a route-health input.
func (s *Server) relayTunnel(clientConn, upstream net.Conn, chosen *pool.Proxy, start time.Time, logTarget string, log zerolog.Logger) {
	defer upstream.Close() //nolint:errcheck // every relay exit owns the selected tunnel
	closes := make(chan relayResult, 2)
	relayDone := make(chan struct{})
	go func() {
		defer close(relayDone)
		n, err := copyToClient(clientConn, upstream)
		closes <- relayResult{direction: relayToClient, bytes: n, err: err}
		if isUpstreamBreak(err) {
			if tc := tcpConnOf(clientConn); tc != nil {
				_ = tc.SetLinger(0)
				log.Debug().Msg("upstream broke the tunnel; client side set to reset on close")
			}
		}
		_ = clientConn.Close()
	}()
	n, err := copyWithPooledBuffer(upstream, clientConn)
	if err == nil {
		if cw, ok := upstream.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		}
		select {
		case <-relayDone:
		case <-s.baseCtx.Done():
			_ = upstream.Close()
			<-relayDone
		}
		second := <-closes
		recordTunnelClose(log, logTarget, chosen, start, relayResult{direction: relayToUpstream, bytes: n}, second)
		return
	}
	closes <- relayResult{direction: relayToUpstream, bytes: n, err: err}
	_ = upstream.Close()
	_ = clientConn.Close()
	first := <-closes
	second := <-closes
	<-relayDone
	recordTunnelClose(log, logTarget, chosen, start, first, second)
}

type relayResult struct {
	direction string
	bytes     int64
	err       error
}

const (
	relayToClient   = "upstream_to_client"
	relayToUpstream = "client_to_upstream"
)

// recordTunnelClose reports tunnel end-state without emitting the target's
// bytes, route userinfo, or other unbounded input. A broken upstream read is
// visible at warn because a client received a truncated tunnel; every result is
// still strictly observational and must never modify selected-route health.
func recordTunnelClose(log zerolog.Logger, target string, p *pool.Proxy, start time.Time, first, second relayResult) {
	toClient, toUpstream := second, first
	if first.direction == relayToClient {
		toClient, toUpstream = first, second
	}
	msg, reason, cause := "tunnel closed", "client_closed", first.err
	switch {
	case first.direction == relayToClient && isUpstreamBreak(first.err):
		msg, reason = "tunnel broken", "upstream_broken"
	case second.direction == relayToClient && isUpstreamBreak(second.err):
		msg, reason, cause = "tunnel broken", "upstream_broken", second.err
	case first.direction == relayToClient && first.err == nil:
		reason = "upstream_closed"
	case first.err != nil:
		reason = "client_aborted"
	}
	ev := log.Debug()
	if msg == "tunnel broken" {
		ev = log.Warn()
	}
	ev.Str("target", target).Str("upstream", upstreamLogValue(p)).
		Str("duration", logDuration(time.Since(start))).
		Int64("client_to_upstream_bytes", toUpstream.bytes).
		Int64("upstream_to_client_bytes", toClient.bytes).
		Str("close_reason", reason)
	if cause != nil {
		ev = ev.Str("error", logErrorValue(cause))
	}
	ev.Msg(msg)
}
