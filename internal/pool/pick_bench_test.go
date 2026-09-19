package pool

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// benchPickPool builds a same-kind pool of n routes. A non-nil balance adds
// one route of the other family so both family branches stay live.
func benchPickPool(b *testing.B, n int, balance config.KindBalance) *Pool {
	b.Helper()
	routes := make([]config.RouteSpec, 0, n+1)
	for i := range n {
		routes = append(routes, config.RouteSpec{
			URL:  &url.URL{Scheme: "socks5", Host: fmt.Sprintf("p%d.test:1080", i)},
			Kind: config.EgressV4,
		})
	}
	if balance.V4 > 0 || balance.V6 > 0 {
		routes = append(routes, config.RouteSpec{
			URL:  &url.URL{Scheme: "socks5", Host: "p6.test:1080"},
			Kind: config.EgressV6,
		})
	}
	return NewRoutes(routes, time.Second, time.Minute, balance)
}

// BenchmarkPickFor measures the serving hot path: pick, report, release under
// full parallelism. The scan previously took the per-entry mutex three times
// per route per pick; the pick-path atomics removed those acquisitions while
// the pool mutex keeps LRU order exact.
func BenchmarkPickFor(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			pl := benchPickPool(b, n, config.KindBalance{})
			exclude := map[*Proxy]bool{} // read-only under concurrency
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if p := pl.PickFor(exclude, nil); p != nil {
						pl.ReportSuccess(p)
						p.Release()
					}
				}
			})
		})
	}
}

// BenchmarkPickForBalanced measures the same hot path with an engaged 7:3
// family split, which adds the family-clock comparison and advance per pick.
func BenchmarkPickForBalanced(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			pl := benchPickPool(b, n, config.KindBalance{V4: 7, V6: 3})
			exclude := map[*Proxy]bool{} // read-only under concurrency
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if p := pl.PickFor(exclude, nil); p != nil {
						pl.ReportSuccess(p)
						p.Release()
					}
				}
			})
		})
	}
}
