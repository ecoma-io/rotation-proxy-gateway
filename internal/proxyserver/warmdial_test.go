package proxyserver

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/socksdial"

	"github.com/rs/zerolog"
)

// stubWarm records the serving path's warm-pool window without a real pool.
type stubWarm struct {
	mu        sync.Mutex
	queue     []*socksdial.HalfConn
	borrowed  int
	discarded int
}

func (w *stubWarm) Borrow(_ *pool.Proxy) *socksdial.HalfConn {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.queue) == 0 {
		return nil
	}
	hc := w.queue[0]
	w.queue = w.queue[1:]
	w.borrowed++
	return hc
}

func (w *stubWarm) DiscardRoute(_ *pool.Proxy) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.discarded++
}

func (w *stubWarm) counts() (int, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.borrowed, w.discarded
}

// parkThenDie is an upstream that completes the greeting and then closes:
// a parked half connection whose endpoint vanished before CONNECT.
func parkThenDie(t *testing.T) *url.URL {
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
			go func() {
				defer func() { _ = conn.Close() }()
				br := bufio.NewReader(conn)
				head := make([]byte, 2)
				if _, err := io.ReadFull(br, head); err != nil {
					return
				}
				methods := make([]byte, head[1])
				if _, err := io.ReadFull(br, methods); err != nil {
					return
				}
				_, _ = conn.Write([]byte{0x05, 0x00})
			}()
		}
	}()
	return &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
}

// warmDialServer builds the minimal Server the dial seam needs: a logger,
// the warm window, and a (per-test) cold dial seam.
func warmDialServer() *Server {
	return &Server{log: zerolog.Nop()}
}

func warmRoute(t *testing.T) *pool.Proxy {
	t.Helper()
	pl := pool.NewRoutes(mixedRoutes(&url.URL{Scheme: "socks5", Host: "unused.test:1080"}), 30*time.Second, time.Minute)
	return pl.RoutePointers()[0]
}

// A borrowed connection completes against the target and the cold dial seam
// is never reached.
func TestDialWarmFirstUsesBorrowedConnection(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{})
	hc, err := socksdial.DialHalf(context.Background(), fs.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	warm := &stubWarm{queue: []*socksdial.HalfConn{hc}}
	s := warmDialServer()
	coldCalled := false
	s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
		coldCalled = true
		return nil, errors.New("cold dial must not run")
	}
	s.warm = warm

	conn, err := s.dialWarmFirst(context.Background(), warmRoute(t), mustTarget(t, startRawEchoTarget(t)), 2*time.Second)
	if err != nil {
		t.Fatalf("dialWarmFirst: %v", err)
	}
	defer func() { _ = conn.Close() }()
	banner := make([]byte, len("banner\n"))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(conn, banner); err != nil {
		t.Fatalf("tunnel banner: %v", err)
	}
	if string(banner) != "banner\n" {
		t.Fatalf("tunnel banner = %q", banner)
	}
	if coldCalled {
		t.Fatal("cold dial seam ran despite a ready warm connection")
	}
	if b, _ := warm.counts(); b != 1 {
		t.Fatalf("borrowed = %d, want 1", b)
	}
}

// A borrowed connection whose endpoint vanished dies at the transport level:
// siblings are discarded, no health is reported for the attempt, and the
// cold dial decides the outcome.
func TestDialWarmFirstDropsDeadBorrowAndDialsCold(t *testing.T) {
	hc, err := socksdial.DialHalf(context.Background(), parkThenDie(t), 2*time.Second)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	warm := &stubWarm{queue: []*socksdial.HalfConn{hc}}
	s := warmDialServer()
	coldDialed := 0
	s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
		coldDialed++
		c1, c2 := net.Pipe()
		go func() { _, _ = io.Copy(io.Discard, c1) }()
		return c2, nil
	}
	s.warm = warm

	conn, err := s.dialWarmFirst(context.Background(), warmRoute(t), mustTarget(t, "example.test:80"), 2*time.Second)
	if err != nil {
		t.Fatalf("dialWarmFirst after dead borrow: %v", err)
	}
	_ = conn.Close()
	if coldDialed != 1 {
		t.Fatalf("cold dials = %d, want exactly one after the dead borrow", coldDialed)
	}
	if _, d := warm.counts(); d != 1 {
		t.Fatalf("discards = %d, want the dead borrow's siblings dropped", d)
	}
}

// An endpoint that answers CONNECT itself with a refusal surfaces as the
// connect-target classification — no cold dial, no discard: the refusal is
// about the pair, not the parked connection.
func TestDialWarmFirstRefusalStaysTargetScoped(t *testing.T) {
	fs := startSocks5Proxy(t, socksOptions{connectRep: 0x05})
	hc, err := socksdial.DialHalf(context.Background(), fs.URL, 2*time.Second)
	if err != nil {
		t.Fatalf("DialHalf: %v", err)
	}
	warm := &stubWarm{queue: []*socksdial.HalfConn{hc}}
	s := warmDialServer()
	s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
		t.Fatal("cold dial seam ran for a target-scoped refusal")
		return nil, nil
	}
	s.warm = warm

	_, err = s.dialWarmFirst(context.Background(), warmRoute(t), mustTarget(t, "example.test:80"), 2*time.Second)
	if !isConnectTargetError(err) {
		t.Fatalf("error = %v, want a connect-target refusal", err)
	}
	if _, d := warm.counts(); d != 0 {
		t.Fatalf("discards = %d, want none for a target-scoped refusal", d)
	}
}

// A borrow miss is transparent: the cold dial seam runs exactly as before
// the pool existed.
func TestDialWarmFirstMissFallsBackCold(t *testing.T) {
	warm := &stubWarm{}
	s := warmDialServer()
	coldDialed := 0
	s.dial = func(context.Context, *url.URL, socksdial.Target, time.Duration) (net.Conn, error) {
		coldDialed++
		return nil, &ProxyDialError{Err: errors.New("refused")}
	}
	s.warm = warm

	_, err := s.dialWarmFirst(context.Background(), warmRoute(t), mustTarget(t, "example.test:80"), 2*time.Second)
	if !isProxyDialError(err) {
		t.Fatalf("error = %v, want the cold dial's classification", err)
	}
	if coldDialed != 1 {
		t.Fatalf("cold dials = %d, want 1", coldDialed)
	}
	if b, d := warm.counts(); b != 0 || d != 0 {
		t.Fatalf("borrowed=%d discarded=%d, want 0/0 on a miss", b, d)
	}
}
