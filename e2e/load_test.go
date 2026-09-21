package e2e_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"sort"
	"sync"
	"testing"
	"time"
)

// The load harness drives continuous traffic through a gateway listener and
// records per-operation latency and outcome, so HA scenarios compare as
// distributions instead of single observations. Benchmarks build on it
// (ha_test.go); failed operations are data here, not test failures — callers
// assert on the returned loadResult.

// loadSample is one finished load operation. ok says whether a full HTTP 200
// round trip completed inside the per-op budget.
type loadSample struct {
	at      time.Duration // completion time since the run started
	latency time.Duration
	ok      bool
}

// loadResult aggregates one load window.
type loadResult struct {
	window time.Duration

	mu sync.Mutex
	sl []loadSample
}

func (r *loadResult) add(s loadSample) {
	r.mu.Lock()
	r.sl = append(r.sl, s)
	r.mu.Unlock()
}

func (r *loadResult) snapshot() []loadSample {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]loadSample(nil), r.sl...)
}

// successRatio is the share of successful operations over the whole window.
func (r *loadResult) successRatio() float64 {
	return r.successRatioBetween(0, time.Duration(1<<62))
}

// successRatioBetween is the success share over operations completing in
// [from, to).
func (r *loadResult) successRatioBetween(from, to time.Duration) float64 {
	var ok, total int
	for _, s := range r.snapshot() {
		if s.at < from || s.at >= to {
			continue
		}
		total++
		if s.ok {
			ok++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(ok) / float64(total)
}

// percentileBetween is the p-th percentile latency in milliseconds of
// successful operations completing in [from, to).
func (r *loadResult) percentileBetween(from, to time.Duration, p float64) float64 {
	var lat []float64
	for _, s := range r.snapshot() {
		if !s.ok || s.at < from || s.at >= to {
			continue
		}
		lat = append(lat, s.latency.Seconds()*1000)
	}
	if len(lat) == 0 {
		return 0
	}
	sort.Float64s(lat)
	idx := int(float64(len(lat)) * p)
	if idx >= len(lat) {
		idx = len(lat) - 1
	}
	return lat[idx]
}

// reportLoad publishes one load window as benchmark metrics under a unit
// prefix, so several windows coexist under one benchmark name.
func reportLoad(b *testing.B, prefix string, r *loadResult) {
	b.Helper()
	var failed int
	for _, s := range r.snapshot() {
		if !s.ok {
			failed++
		}
	}
	b.ReportMetric(r.successRatio(), prefix+"success_ratio")
	b.ReportMetric(float64(failed), prefix+"failed_ops")
	b.ReportMetric(r.percentileBetween(0, time.Duration(1<<62), 0.50), prefix+"p50_ms")
	b.ReportMetric(r.percentileBetween(0, time.Duration(1<<62), 0.95), prefix+"p95_ms")
	b.ReportMetric(r.percentileBetween(0, time.Duration(1<<62), 0.99), prefix+"p99_ms")
}

// runLoad drives workers fetching one small HTTP response per fresh tunnel
// through a gateway SOCKS listener for window. Each operation is bounded by
// perOp; it returns once the window elapses and every worker finished its
// current operation. A worker stuck past perOp unwinds at worst at the
// gateway's own 30s inbound handshake deadline, which is a broken-gateway
// condition a benchmark window cannot survive anyway.
func runLoad(tb testing.TB, proxyAddr, target string, workers int, window, perOp time.Duration) *loadResult {
	tb.Helper()
	res := &loadResult{window: window}
	start := time.Now()
	deadline := start.Add(window)
	var wg sync.WaitGroup
	wg.Add(workers)
	for range workers {
		go func() {
			defer wg.Done()
			for {
				if !time.Now().Before(deadline) {
					return
				}
				ok, latency := oneLoadOp(proxyAddr, target, perOp)
				res.add(loadSample{at: time.Since(start), latency: latency, ok: ok})
			}
		}()
	}
	wg.Wait()
	return res
}

// oneLoadOp is one load operation: a fresh inbound SOCKS5 tunnel plus one
// minimal HTTP request, so the operation cost includes exactly the setup
// work a warm upstream connection could skip.
func oneLoadOp(proxyAddr, target string, timeout time.Duration) (bool, time.Duration) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := dialSocksTunnel(ctx, proxyAddr, target)
	if err != nil {
		return false, time.Since(start)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	req := fmt.Sprintf("GET /load HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := io.WriteString(conn, req); err != nil {
		return false, time.Since(start)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return false, time.Since(start)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK, time.Since(start)
}
