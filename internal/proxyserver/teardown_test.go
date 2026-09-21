package proxyserver

import (
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/pool"
)

// A client that half-closes its write side keeps the tunnel alive: the FIN is
// propagated to the upstream, the response direction stays relayed, and a
// reply that arrives only after the half-close is still delivered before a
// clean close (issue #38).
func TestTunnelHalfCloseDeliversDelayedResponse(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	s, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn := socksDialVia(t, addr, startHalfCloseTarget(t, 300*time.Millisecond, "late-banner\n"))
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("client conn = %T, want *net.TCPConn for CloseWrite", conn)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(body) != "late-banner\n" {
		t.Fatalf("post-half-close body = %q, want the delayed banner", body)
	}

	// The close record lands once the response direction ended on its own;
	// the client half-close is the first end, so the reason stays a routine
	// client close with the response byte count.
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel closed", "close_reason": "client_closed"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "tunnel closed", "upstream_to_client_bytes": "12",
	}); !ok {
		t.Errorf("close record lost the response byte count:\n%s", output)
	}
	if _, ok := findRecord(output, map[string]string{"msg": "tunnel broken"}); ok {
		t.Errorf("half-close close classified as broken:\n%s", output)
	}
	if snap := pl.Snapshot()[0]; snap.Successes != 1 || snap.Failures != 0 {
		t.Fatalf("half-close mutated route health: %+v", snap)
	}
	if status := s.ListenerStatus(); status.Requests != 1 {
		t.Fatalf("listener status = %+v", status)
	}
}

// A pipelining client — greeting, CONNECT, and payload in one write, so the
// relay sees the client conn through the prefix wrapper — must still get the
// reset when the upstream breaks the tunnel mid-stream: the truncated stream
// stays visibly truncated instead of reading as a clean EOF (issue #37).
func TestPipelinedBurstResetOnUpstreamBreak(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
	var logs safeLogBuffer
	_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	frame, err := socksRequestFrame(socksCmdConnect, startAbortTarget(t))
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("pipelined-before-break")
	burst := append(socksGreetingFrame(socksAuthNone), frame...)
	burst = append(burst, payload...)
	if _, err := conn.Write(burst); err != nil {
		t.Fatalf("write burst: %v", err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read method selection: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read SOCKS reply: %v", err)
	}
	if reply[1] != socksReplySuccess {
		t.Fatalf("CONNECT reply = 0x%02x, want success", reply[1])
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, conn); err == nil || errors.Is(err, io.EOF) {
		t.Fatalf("pipelined client saw a clean end (%v) after the upstream broke the tunnel", err)
	}

	// The reset decision must have run despite the prefix wrapper: both the
	// debug record and the broken-tunnel close record are present.
	output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel broken"})
	if _, ok := findRecord(output, map[string]string{
		"msg": "upstream broke the tunnel; client side set to reset on close",
	}); !ok {
		t.Errorf("reset was not armed for the wrapped client conn:\n%s", output)
	}
	if _, ok := findRecord(output, map[string]string{
		"msg": "tunnel broken", "close_reason": "upstream_broken",
	}); !ok {
		t.Errorf("broken close record missing:\n%s", output)
	}
	if snap := pl.Snapshot()[0]; snap.Successes != 1 || snap.Failures != 0 {
		t.Fatalf("upstream break mutated route health: %+v", snap)
	}
}

// Clean teardowns never arm the reset: neither a client close with the
// upstream still parked (the teardown-close artifact used to arm it) nor an
// upstream that ends the stream cleanly may leave a spurious
// reset-on-close or a broken-tunnel record behind (issue #37).
func TestCleanTeardownNeverArmsReset(t *testing.T) {
	t.Run("client closes with upstream parked", func(t *testing.T) {
		fs := startSocks5Proxy(t, socksOptions{})
		pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
		var logs safeLogBuffer
		_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

		// The target parks until the FIN reaches it, then ends without a
		// reply: at client-close time the upstream direction is still live.
		conn := socksDialVia(t, addr, startHalfCloseTarget(t, 0, ""))
		_ = conn.Close()

		output := waitForRecord(t, &logs, map[string]string{"msg": "tunnel closed"})
		if _, ok := findRecord(output, map[string]string{
			"msg": "upstream broke the tunnel; client side set to reset on close",
		}); ok {
			t.Errorf("teardown artifact armed the reset:\n%s", output)
		}
		if _, ok := findRecord(output, map[string]string{"msg": "tunnel broken"}); ok {
			t.Errorf("clean close classified as broken:\n%s", output)
		}
		if snap := pl.Snapshot()[0]; snap.Successes != 1 || snap.Failures != 0 {
			t.Fatalf("clean close mutated route health: %+v", snap)
		}
	})

	t.Run("upstream closes first", func(t *testing.T) {
		fs := startSocks5Proxy(t, socksOptions{})
		pl := pool.NewRoutes(mixedRoutes(fs.URL), time.Second, time.Minute)
		var logs safeLogBuffer
		_, addr := newSocksServer(t, pl, defaultRuntime(), captureLogger(&logs))

		// A target that answers once and closes cleanly.
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = ln.Close() })
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					_, _ = c.Write([]byte("response\n"))
					_ = c.Close()
				}(c)
			}
		}()

		conn := socksDialVia(t, addr, ln.Addr().String())
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		body, err := io.ReadAll(conn)
		if err != nil {
			// A spurious reset-on-close would surface here as ECONNRESET
			// instead of the clean EOF a finished stream must produce.
			t.Fatalf("read after clean upstream close: %v", err)
		}
		if string(body) != "response\n" {
			t.Fatalf("body = %q, want the target response", body)
		}
		_ = conn.Close()

		output := waitForRecord(t, &logs, map[string]string{"close_reason": "upstream_closed"})
		if _, ok := findRecord(output, map[string]string{
			"msg": "upstream broke the tunnel; client side set to reset on close",
		}); ok {
			t.Errorf("clean upstream close armed the reset:\n%s", output)
		}
		if _, ok := findRecord(output, map[string]string{"msg": "tunnel broken"}); ok {
			t.Errorf("clean upstream close classified as broken:\n%s", output)
		}
	})
}
