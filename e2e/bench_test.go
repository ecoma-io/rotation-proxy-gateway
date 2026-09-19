package e2e_test

import (
	"bytes"
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
// interpretation caveats in e2e/BENCH.md. The Direct vs Proxied delta is the
// cost added by one gateway hop plus one SOCKS5 hop.

func benchGateway(b *testing.B, routes []RouteConfig) *Gateway {
	b.Helper()
	cfg := defaultGatewayConfig(routes)
	cfg.LogLevel = "error" // keep logging cost out of the measurement
	return NewGateway(b, cfg)
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
	client := ProxyClient(g.MixedAddr)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Get(target.URL + "/bench")
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.ReadAll(resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkProxied_SmallGETParallel(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewEchoTarget(b)
	g := benchGateway(b, []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	client := ProxyClient(g.MixedAddr)
	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			resp, err := client.Get(target.URL + "/bench")
			if err != nil {
				b.Error(err)
				return
			}
			_, _ = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
		}
	})
}

func BenchmarkProxied_ReplayablePOST_64KiB(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewEchoBodyTarget(b)
	g := benchGateway(b, []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	client := ProxyClient(g.MixedAddr)
	payload := bytes.Repeat([]byte("x"), 64<<10) // below max-body-buffer: replayable path
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Post(target.URL+"/bench", "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkProxied_StreamingPOST_2MiB(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewEchoBodyTarget(b)
	cfg := defaultGatewayConfig([]RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	cfg.LogLevel = "error"
	cfg.MaxBodyBuffer = 64 << 10 // 2MiB body far exceeds the cap: streaming path
	g := NewGateway(b, cfg)
	client := ProxyClient(g.MixedAddr)
	payload := bytes.Repeat([]byte("y"), 2<<20)
	b.ResetTimer()
	b.ReportAllocs()
	for b.Loop() {
		resp, err := client.Post(target.URL+"/bench", "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}

func BenchmarkProxied_BulkGET_1MiB(b *testing.B) {
	if testing.Short() {
		b.Skip("e2e")
	}
	socks := NewSocksSim(b, SocksOK, "", "")
	target := NewBulkBodyTarget(b, 1<<20)
	g := benchGateway(b, []RouteConfig{{Proxy: socks.RouteValue(), Kind: "v4"}})
	client := ProxyClient(g.MixedAddr)
	b.ResetTimer()
	b.ReportAllocs()
	b.SetBytes(1 << 20)
	for b.Loop() {
		resp, err := client.Get(target.URL + "/bench")
		if err != nil {
			b.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
}
