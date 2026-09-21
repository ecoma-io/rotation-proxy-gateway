package socksdial

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// DialHalf + CompleteConnect split the outbound dial so a half connection can
// park between the stages. These tests pin the staged contract: the park must
// be transparent (deadline re-armed, framing intact, auth remembered), Close
// must be safe, and consumed half connections must refuse reuse.

func TestDialHalfParkedCompleteSucceeds(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{wantHost: "example.test", wantPort: 443})
	hc, err := DialHalf(context.Background(), dialURL(t, "socks5://"+addr), dialTestTimeout)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	conn, err := hc.CompleteConnect(Target{Host: "example.test", Port: 443, Type: AddrDomain}, dialTestTimeout)
	if err != nil {
		t.Fatalf("CompleteConnect after park: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write through completed tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "ping" {
		t.Fatalf("echo = %q, want ping", buf)
	}
}

// TestCompleteConnectReArmsExpiredHalfDeadline pins the sharpest staged-dial
// bug: a parked half connection carries a long-expired half-stage deadline, so
// CompleteConnect must re-arm its own deadline before the first byte of I/O —
// without the re-arm every completion past the park fails with i/o timeout.
func TestCompleteConnectReArmsExpiredHalfDeadline(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{wantHost: "parked.test", wantPort: 80})
	hc, err := DialHalf(context.Background(), dialURL(t, "socks5://"+addr), 200*time.Millisecond)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	// Park three times the half-stage budget: the armed deadline is deep in
	// the past by the time the completion stage starts.
	time.Sleep(600 * time.Millisecond)
	conn, err := hc.CompleteConnect(Target{Host: "parked.test", Port: 80, Type: AddrDomain}, dialTestTimeout)
	if err != nil {
		t.Fatalf("CompleteConnect with expired half deadline: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte("late")); err != nil {
		t.Fatalf("write through completed tunnel: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(buf) != "late" {
		t.Fatalf("echo = %q, want late", buf)
	}
}

func TestDialHalfAuthenticatesBeforePark(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{
		method: 0x02, wantUser: "u1", wantPass: "p1",
		wantHost: "auth.test", wantPort: 8080,
	})
	hc, err := DialHalf(context.Background(), dialURL(t, "socks5://u1:p1@"+addr), dialTestTimeout)
	if err != nil {
		t.Fatalf("DialHalf with credentials: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	conn, err := hc.CompleteConnect(Target{Host: "auth.test", Port: 8080, Type: AddrDomain}, dialTestTimeout)
	if err != nil {
		t.Fatalf("CompleteConnect after authenticated park: %v", err)
	}
	_ = conn.Close()
}

func TestDialHalfFailuresClassifyAsDial(t *testing.T) {
	// A port with no listener: dial-stage failure.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()
	_, dialErr := DialHalf(context.Background(), dialURL(t, "socks5://"+deadAddr), dialTestTimeout)
	assertTaxonomy(t, dialErr, true, false, false)

	// A non-SOCKS5 scheme: request-scoped protocol failure, no connection.
	_, schemeErr := DialHalf(context.Background(), dialURL(t, "http://example.test:80"), dialTestTimeout)
	assertTaxonomy(t, schemeErr, false, false, false)
}

func TestDialHalfEndpointRejectsCredentials(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{method: 0x02, authStatus: 0x01})
	_, err := DialHalf(context.Background(), dialURL(t, "socks5://u:p@"+addr), dialTestTimeout)
	assertTaxonomy(t, err, false, true, false)
}

// TestCompleteConnectAfterParkClassifiesTargetRefusal pins that a CONNECT
// refusal read on a borrowed-then-completed connection keeps the
// pair-scoped (connect_target) classification the pool keys on.
func TestCompleteConnectAfterParkClassifiesTargetRefusal(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{replyCode: 0x05})
	hc, err := DialHalf(context.Background(), dialURL(t, "socks5://"+addr), dialTestTimeout)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	time.Sleep(100 * time.Millisecond)
	_, err = hc.CompleteConnect(Target{Host: "refused.test", Port: 80, Type: AddrDomain}, dialTestTimeout)
	assertTaxonomy(t, err, false, false, true)
	if !IsConnectTargetError(err) {
		t.Errorf("parked CONNECT refusal lost target scope: %v", err)
	}
}

func TestHalfConnCloseIsSafeToRepeat(t *testing.T) {
	addr := startScriptedSocks(t, socksScript{})
	hc, err := DialHalf(context.Background(), dialURL(t, "socks5://"+addr), dialTestTimeout)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	if err := hc.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := hc.Close(); err == nil {
		t.Fatal("second Close should report the closed socket, got nil")
	}
	// Completing a released half connection is a setup-class refusal, never a
	// health event or a panic.
	_, err = hc.CompleteConnect(Target{Host: "any.test", Port: 80, Type: AddrDomain}, dialTestTimeout)
	assertTaxonomy(t, err, false, false, false)
}
