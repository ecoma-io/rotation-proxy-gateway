package socksdial

import (
	"context"
	"io"
	"net"
	"net/url"
	"testing"
	"time"
)

// socksSimReply is the no-auth success reply with a zero IPv4 bound address.
var socksSimReply = []byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}

// benchSOCKSUpstream accepts connections and completes minimal no-auth SOCKS5
// handshakes. Its per-connection handling uses fixed-size buffers so the
// benchmark measures the dial side's allocations, not the simulator's.
func benchSOCKSUpstream(b *testing.B) *url.URL {
	b.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				var greet [2]byte
				if _, err := io.ReadFull(c, greet[:]); err != nil {
					return
				}
				if _, err := io.CopyN(io.Discard, c, int64(greet[1])); err != nil {
					return
				}
				if _, err := c.Write(socksSimReply[:2]); err != nil {
					return
				}
				var req [4]byte
				if _, err := io.ReadFull(c, req[:]); err != nil {
					return
				}
				switch req[3] {
				case 0x01:
					if _, err := io.CopyN(io.Discard, c, 6); err != nil {
						return
					}
				case 0x03:
					var l [1]byte
					if _, err := io.ReadFull(c, l[:]); err != nil {
						return
					}
					if _, err := io.CopyN(io.Discard, c, int64(l[0])+2); err != nil {
						return
					}
				case 0x04:
					if _, err := io.CopyN(io.Discard, c, 18); err != nil {
						return
					}
				default:
					return
				}
				_, _ = c.Write(socksSimReply)
			}(conn)
		}
	}()
	b.Cleanup(func() { _ = ln.Close(); <-done })
	return &url.URL{Scheme: "socks5", Host: ln.Addr().String()}
}

// BenchmarkDial measures the full outbound path — endpoint TCP dial, greeting,
// connect request, reply and bound-address read — per established tunnel.
func BenchmarkDial(b *testing.B) {
	pu := benchSOCKSUpstream(b)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		conn, err := Dial(context.Background(), pu, "example.test:443", time.Second)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}

// BenchmarkDialAuthenticated adds the RFC 1929 username/password round trip.
func BenchmarkDialAuthenticated(b *testing.B) {
	pu := benchSOCKSUpstream(b)
	u := *pu
	u.User = url.UserPassword("bench-user", "bench-pass")
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		conn, err := Dial(context.Background(), &u, "example.test:443", time.Second)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}
