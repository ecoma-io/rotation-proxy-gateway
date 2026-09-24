package pool

import (
	"fmt"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

// benchPickPool builds a same-kind pool of n routes.
func benchPickPool(b *testing.B, n int) *Pool {
	b.Helper()
	routes := make([]config.RouteSpec, 0, n)
	for i := range n {
		routes = append(routes, config.RouteSpec{
			URL:  &url.URL{Scheme: "socks5", Host: fmt.Sprintf("p%d.test:1080", i)},
			Kind: config.EgressV4,
		})
	}
	return NewRoutes(routes, time.Second, time.Minute)
}

// BenchmarkPickFor measures the serving hot path: pick, report, release under
// full parallelism. The scan previously took the per-entry mutex three times
// per route per pick; the pick-path atomics removed those acquisitions while
// the pool mutex keeps LRU order exact.
func BenchmarkPickFor(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			pl := benchPickPool(b, n)
			exclude := map[*Proxy]bool{} // read-only under concurrency
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if p := pl.PickFor(exclude, nil, "t:443"); p != nil {
						pl.ReportSuccess(p, "t:443")
						p.Release()
					}
				}
			})
		})
	}
}

// BenchmarkPickForRouted measures the same hot path with routing active: the
// allow closure is the candidate-membership test the serving path builds per
// tunnel, so the delta against BenchmarkPickFor is the whole per-pick cost of
// routing (one map lookup per scanned route).
func BenchmarkPickForRouted(b *testing.B) {
	for _, n := range []int{1, 8, 32} {
		b.Run(fmt.Sprintf("routes=%d", n), func(b *testing.B) {
			routes := make([]config.RouteSpec, 0, n)
			for i := range n {
				routes = append(routes, config.RouteSpec{
					ID:   fmt.Sprintf("route-%d", i),
					URL:  &url.URL{Scheme: "socks5", Host: fmt.Sprintf("p%d.test:1080", i)},
					Kind: config.EgressV4,
				})
			}
			pl := NewRoutes(routes, time.Second, time.Minute)
			candidates := map[string]struct{}{"route-0": {}, "route-1": {}}
			allow := func(p *Proxy) bool {
				_, ok := candidates[p.RouteID()]
				return ok
			}
			exclude := map[*Proxy]bool{} // read-only under concurrency
			b.ReportAllocs()
			b.ResetTimer()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if p := pl.PickFor(exclude, allow, "t:443"); p != nil {
						pl.ReportSuccess(p, "t:443")
						p.Release()
					}
				}
			})
		})
	}
}
