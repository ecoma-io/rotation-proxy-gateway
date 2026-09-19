package e2e_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

// Benchmarks measure the gateway's end-to-end overhead with the real binary,
// a real SOCKS5 hop, and a real HTTP target. Run:
//
//	go test ./e2e/ -run=NONE -bench=. -benchmem -count=5
//
// Baselines are not recorded in the repo: hardware differs, so capture your
// own before/after on this machine and compare with benchstat — workflow and
// interpretation caveats in e2e/BENCH.md. The gateway is an inbound SOCKS5-only
// server, so one request costs exactly one inbound SOCKS5 handshake plus one
// outbound SOCKS5 handshake through the route pool; there is no HTTP parsing
// and no body buffering in the gateway — a pure TCP relay once the tunnel is
// up. The Direct vs Proxied delta is the cost those two handshakes add to a
// plain HTTP exchange.

func benchGateway(b *testing.B, routes []RouteConfig) *Gateway {
	b.Helper()
	cfg := defaultGatewayConfig(routes)
	cfg.LogLevel = "error" // keep logging cost out of the measurement
	return NewGateway(b, cfg)
}

// proxiedClient returns an HTTP client whose transport dials one inbound
// SOCKS5 tunnel per request (keep-alives off), so every iteration is a fresh
// tunnel — comparable to per-request behavior.
func proxiedClient(proxyAddr string) *http.Client {
	tr := socksTransport(proxyAddr, false)
	tr.DisableKeepAlives = true
	return &http.Client{Transport: tr, Timeout: 15 * time.Second}
}

func BenchmarkDirect_SmallGET(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	target := NewEchoTarget(b)
	client := &http.Client{Timeout: 30 * time.Second}
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Get(target.URL + "/bench")
		if err != nil {
			b.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(got) != "e2e-echo:/bench" {
			b.Fatalf("status=%d body=%q", resp.StatusCode, got)
		}
	}
}

func BenchmarkProxied_SmallGET(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewEchoTarget(b)
	g := benchGateway(b, []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	client := proxiedClient(g.MixedAddr)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Get(target.URL + "/bench")
		if err != nil {
			b.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(got) != "e2e-echo:/bench" {
			b.Fatalf("status=%d body=%q", resp.StatusCode, got)
		}
	}
}

func BenchmarkProxied_SmallGETParallel(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewEchoTarget(b)
	g := benchGateway(b, []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	client := proxiedClient(g.MixedAddr)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(target.URL + "/bench")
			if err != nil {
				b.Error(err)
				return
			}
			got, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK || string(got) != "e2e-echo:/bench" {
				b.Errorf("status=%d body=%q", resp.StatusCode, got)
				return
			}
		}
	})
}

// BenchmarkProxied_TunnelSetup isolates the setup half of a proxied request:
// the inbound SOCKS5 negotiation, the route-pool pick, and the outbound SOCKS5
// setup — then the tunnel is closed again, with no HTTP at all.
func BenchmarkProxied_TunnelSetup(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewEchoTarget(b)
	g := benchGateway(b, []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		conn, err := dialSocksTunnel(context.Background(), g.MixedAddr, target.Host)
		if err != nil {
			b.Fatal(err)
		}
		_ = conn.Close()
	}
}

// BenchmarkProxied_BulkGET_1MiB measures steady-state relay throughput: one
// tunnel is established once (before the timed loop) and reused for every
// iteration, so ns/op is the relay of one 1MiB HTTP response, not connection
// setup. SetBytes reports MB/s.
func BenchmarkProxied_BulkGET_1MiB(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewBulkBodyTarget(b, 1<<20)
	g := benchGateway(b, []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	conn := socksTunnel(b, g.MixedAddr, target.Host)
	br := bufio.NewReader(conn)
	get := []byte("GET /bench HTTP/1.1\r\nHost: " + target.Host + "\r\n\r\n")
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(1 << 20)
	for b.Loop() {
		if _, err := conn.Write(get); err != nil {
			b.Fatal(err)
		}
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			b.Fatal(err)
		}
		n, err := io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			b.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK || n != 1<<20 {
			b.Fatalf("status=%d bodyBytes=%d", resp.StatusCode, n)
		}
	}
}
