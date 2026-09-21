package e2e_test

import (
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Tunnel teardown semantics against the real binary: a client half-close
// keeps the response direction relayed (issue #38), an upstream mid-stream
// break resets the client even when the client pipelined its CONNECT burst
// (issue #37), and clean teardowns never arm that reset.

// startHalfCloseTarget accepts connections, holds them until the peer ends
// its write side (EOF), waits delay, then writes one banner and closes: a
// target whose reply arrives only after the client half-closed. banner may
// be empty for a pure parked-then-close target.
func startHalfCloseTarget(t testing.TB, delay time.Duration, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer func() { _ = conn.Close() }()
				if _, err := io.Copy(io.Discard, conn); err != nil {
					return
				}
				if delay > 0 {
					time.Sleep(delay)
				}
				if banner != "" {
					_, _ = conn.Write([]byte(banner))
				}
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// A client that half-closes its write side after CONNECT must still receive
// the upstream reply that arrives later, followed by a clean end: the gateway
// propagates the FIN and keeps the response direction relayed instead of
// terminating the tunnel (issue #38).
func TestE2E_HalfCloseDeliversDelayedResponse(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := startHalfCloseTarget(t, 400*time.Millisecond, "late-banner\n")
	g := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	}))

	conn := socksTunnel(t, g.MixedAddr, target)
	tc, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("tunnel conn = %T, want *net.TCPConn for CloseWrite", conn)
	}
	if err := tc.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read after half-close: %v", err)
	}
	if string(body) != "late-banner\n" {
		t.Fatalf("post-half-close body = %q, want the delayed banner", body)
	}
}

// A pipelining client — greeting, CONNECT, and payload in one write, so the
// gateway relays through its prefix wrapper — must observe a reset, not a
// clean EOF, when the upstream drops the live stream mid-flight: the
// truncated stream stays visibly truncated (issue #37).
func TestE2E_PipelinedBurstSeesResetOnUpstreamBreak(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	socks.BreakTunnel = true
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug" // the reset decision logs at debug
	g := NewGateway(t, cfg)

	frame, err := socksConnectRequestBytes("127.0.0.1:9")
	if err != nil {
		t.Fatal(err)
	}
	for _, pipelined := range []struct {
		name  string
		burst bool
	}{{"pipelined burst", true}, {"sequential writes", false}} {
		t.Run(pipelined.name, func(t *testing.T) {
			conn, err := net.Dial("tcp", g.MixedAddr)
			if err != nil {
				t.Fatalf("dial gateway: %v", err)
			}
			defer func() { _ = conn.Close() }()
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if pipelined.burst {
				// One write: greeting, CONNECT frame, and payload together —
				// the exact case whose prefix wrapper used to swallow the
				// reset.
				burst := append([]byte{0x05, 0x01, 0x00}, frame...)
				burst = append(burst, []byte("burst-payload")...)
				if _, err := conn.Write(burst); err != nil {
					t.Fatalf("write burst: %v", err)
				}
			} else {
				if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
					t.Fatalf("write greeting: %v", err)
				}
			}
			method := make([]byte, 2)
			if _, err := io.ReadFull(conn, method); err != nil {
				t.Fatalf("read method selection: %v", err)
			}
			if method[0] != 0x05 || method[1] != 0x00 {
				t.Fatalf("method selection = % x", method)
			}
			if !pipelined.burst {
				if _, err := conn.Write(frame); err != nil {
					t.Fatalf("write connect: %v", err)
				}
			}
			reply := make([]byte, 10)
			if _, err := io.ReadFull(conn, reply); err != nil {
				t.Fatalf("read reply: %v", err)
			}
			if reply[1] != 0x00 {
				t.Fatalf("CONNECT reply = 0x%02x, want success", reply[1])
			}
			_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.Copy(io.Discard, conn); err == nil || !isConnResetError(err) {
				t.Fatalf("client read after upstream break = %v, want a connection reset (truncation must stay visible)", err)
			}
		})
	}

	// Both flavors armed the reset and logged the broken tunnel.
	deadline := time.Now().Add(10 * time.Second)
	for {
		logs := g.Logs()
		if strings.Count(logs, "upstream broke the tunnel; client side set to reset on close") >= 2 &&
			strings.Count(logs, `"msg":"tunnel broken"`) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("reset/broken records missing for one of the clients:\n%s", logs)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// A clean client close while the upstream direction is still parked must not
// arm the reset: the teardown finishes with a routine close record and no
// broken-tunnel noise (issue #37's spurious-reset half).
func TestE2E_CleanTeardownNoReset(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	socks := NewSocksSim(t, SocksOK, "", "")
	target := startHalfCloseTarget(t, 0, "")
	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: socks.RouteValue(), Kind: "v4"},
	})
	cfg.LogLevel = "debug"
	g := NewGateway(t, cfg)

	conn := socksTunnel(t, g.MixedAddr, target)
	_ = conn.Close()

	waitForLogRecord(t, g, map[string]string{"msg": "tunnel closed", "close_reason": "client_closed"}, 10*time.Second)
	logs := g.Logs()
	if strings.Contains(logs, "upstream broke the tunnel; client side set to reset on close") {
		t.Fatalf("teardown artifact armed the client reset:\n%s", logs)
	}
	if strings.Contains(logs, `"msg":"tunnel broken"`) {
		t.Fatalf("clean close classified as a broken tunnel:\n%s", logs)
	}
}
