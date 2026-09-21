package e2e_test

// Real-proxy measurements for the warm pool's low-traffic open questions. The
// simulated upstreams in this package never drop idle connections and never
// jitter; real providers do both. Against a live config these tests answer:
//
//   - HandshakeRTT: how long each outbound leg actually takes — TCP dial +
//     greeting + auth (the leg the warm pool removes from a request), then
//     the CONNECT leg. The first leg's p50 is the per-borrow win on this
//     provider.
//   - ParkSurvival: whether a half-established connection parked T seconds is
//     still usable — the curve that picks idle-ttl and decides whether the
//     super-low-traffic band benefits at all.
//
// Both skip unless RPGW_REAL_CONFIG points at a config file with live routes:
//
//	RPGW_REAL_CONFIG=./config.yaml go test ./e2e/ -run TestRealProxy -v \
//	  -timeout 15m
//
// That file holds credentials: nothing here prints route URLs, userinfo, or
// file contents — host:port identities only — and no data is written to disk.
// The footprint stays small (a few dozen short-lived connections) to stay
// polite to the provider.

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"sort"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/socksdial"
)

// Measurement knobs: three routes, five cold dials each for RTT, and a park
// sweep out to five minutes — roughly ten minutes of wall-clock all in.
const (
	realRouteLimit = 3
	realRTTIters   = 5
	realStageWait  = 15 * time.Second
)

var realParkDurations = []time.Duration{0, 45 * time.Second, 90 * time.Second, 180 * time.Second, 300 * time.Second}

// realRoutes loads the env-pointed live config and returns its first routes
// (auto first). It never logs the parsed content.
func realRoutes(t *testing.T) []config.RouteSpec {
	t.Helper()
	path := os.Getenv("RPGW_REAL_CONFIG")
	if path == "" {
		t.Skip("RPGW_REAL_CONFIG not set — real-proxy measurements are opt-in")
	}
	cfg, err := config.LoadRuntime(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	all := cfg.AllRoutes()
	if len(all) == 0 {
		t.Fatalf("config %s has no routes", path)
	}
	if len(all) > realRouteLimit {
		all = all[:realRouteLimit]
	}
	return all
}

// probeTarget is the CONNECT destination for all probes: a dual-stack domain
// on 443, resolved at the upstream (socks5h semantics) so v6-only egress
// reaches it over AAAA — an IPv4-literal or plain-80 target is refused by
// exactly the providers worth measuring (observed: reply 0x05).
func probeTarget() socksdial.Target {
	t, err := socksdial.TargetFromAddr("www.cloudflare.com:443")
	if err != nil {
		panic(err)
	}
	return t
}

// probeHTTP runs one small HTTPS exchange through an established tunnel and
// reports whether an HTTP status line came back — the same shape as the
// rotation engine's ip-check traffic.
func probeHTTP(nc net.Conn) bool {
	_ = nc.SetDeadline(time.Now().Add(10 * time.Second))
	defer func() { _ = nc.Close() }()
	tlsConn := tls.Client(nc, &tls.Config{ServerName: "www.cloudflare.com"})
	if err := tlsConn.Handshake(); err != nil {
		return false
	}
	req := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: www.cloudflare.com\r\nConnection: close\r\n\r\n"
	if _, err := tlsConn.Write([]byte(req)); err != nil {
		return false
	}
	buf := make([]byte, 12)
	if _, err := io.ReadFull(tlsConn, buf); err != nil {
		return false
	}
	return string(buf[:5]) == "HTTP/"
}

// classifyPark labels a post-park CompleteConnect failure: a refused CONNECT
// means the parked conn was alive (the route works, the pair does not — the
// dead-borrow path), while send/read failures mean the conn died while
// parked, which is the idle-kill signal idle-ttl must stay under.
func classifyPark(err error) string {
	var reply *socksdial.SocksReplyError
	if errors.As(err, &reply) {
		return fmt.Sprintf("refused (reply 0x%02x)", reply.Reply)
	}
	var hs *socksdial.SocksHandshakeError
	if errors.As(err, &hs) {
		return fmt.Sprintf("%s: %v", hs.Op, hs.Err)
	}
	return err.Error()
}

func medianAndP95(ms []float64) (p50, p95 float64) {
	if len(ms) == 0 {
		return 0, 0
	}
	sort.Float64s(ms)
	pick := func(q float64) float64 {
		i := int(q * float64(len(ms)-1))
		return ms[i]
	}
	return pick(0.5), pick(0.95)
}

// TestRealProxy_HandshakeRTT measures the two outbound legs separately on
// live routes. The first leg (TCP + greeting + auth) is exactly the work the
// warm pool moves off the request path; its p50 is the per-borrow saving.
func TestRealProxy_HandshakeRTT(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	routes := realRoutes(t)
	target := probeTarget()
	for _, rs := range routes {
		var half, conn []float64
		for range realRTTIters {
			t0 := time.Now()
			hc, err := socksdial.DialHalf(context.Background(), rs.URL, realStageWait)
			halfLeg := time.Since(t0)
			if err != nil {
				t.Logf("host=%s dial leg failed: %v", rs.URL.Host, classifyPark(err))
				continue
			}
			// The dial leg is target-independent — it is the warm-pool win
			// even when the CONNECT leg below is refused.
			half = append(half, float64(halfLeg.Microseconds())/1000)
			t1 := time.Now()
			nc, err := hc.CompleteConnect(target, realStageWait)
			connLeg := time.Since(t1)
			if err != nil {
				t.Logf("host=%s connect leg failed: %v", rs.URL.Host, classifyPark(err))
				continue
			}
			if !probeHTTP(nc) {
				t.Logf("host=%s probe through tunnel failed", rs.URL.Host)
			}
			conn = append(conn, float64(connLeg.Microseconds())/1000)
		}
		hp50, hp95 := medianAndP95(half)
		cp50, cp95 := medianAndP95(conn)
		t.Logf("host=%s n=%d  dial+greet+auth p50=%.1fms p95=%.1fms  connect p50=%.1fms p95=%.1fms  (warm removes the first leg)",
			rs.URL.Host, len(half), hp50, hp95, cp50, cp95)
	}
}

// TestRealProxy_ParkSurvival dials a half connection, parks it for T, then
// tries to complete it. All route×duration probes start at once so the whole
// sweep costs max(T) — five minutes — not the sum.
func TestRealProxy_ParkSurvival(t *testing.T) {
	if testing.Short() {
		t.Skip("e2e")
	}
	routes := realRoutes(t)
	target := probeTarget()

	type outcome struct {
		park   time.Duration
		result string
	}
	perRoute := make([][]outcome, len(routes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for ri, rs := range routes {
		for _, d := range realParkDurations {
			wg.Add(1)
			go func(ri int, host string, pu *url.URL, d time.Duration) {
				defer wg.Done()
				hc, err := socksdial.DialHalf(context.Background(), pu, realStageWait)
				if err != nil {
					mu.Lock()
					perRoute[ri] = append(perRoute[ri], outcome{d, "dial-fail: " + classifyPark(err)})
					mu.Unlock()
					return
				}
				time.Sleep(d) // the park itself
				nc, err := hc.CompleteConnect(target, realStageWait)
				if err != nil {
					mu.Lock()
					perRoute[ri] = append(perRoute[ri], outcome{d, "dead: " + classifyPark(err)})
					mu.Unlock()
					return
				}
				res := "ok"
				if !probeHTTP(nc) {
					res = "tunnel-ok-http-fail"
				}
				mu.Lock()
				perRoute[ri] = append(perRoute[ri], outcome{d, res})
				mu.Unlock()
			}(ri, rs.URL.Host, rs.URL, d)
		}
	}
	wg.Wait()

	for ri, rs := range routes {
		sort.Slice(perRoute[ri], func(a, b int) bool {
			return perRoute[ri][a].park < perRoute[ri][b].park
		})
		for _, o := range perRoute[ri] {
			t.Logf("host=%s park=%-5s %s", rs.URL.Host, o.park, o.result)
		}
		firstFail := time.Duration(0)
		for _, o := range perRoute[ri] {
			if o.result != "ok" && (firstFail == 0 || o.park < firstFail) {
				firstFail = o.park
			}
		}
		if firstFail == 0 {
			t.Logf("host=%s survived every park up to %s — idle-ttl may exceed %s", rs.URL.Host, realParkDurations[len(realParkDurations)-1], realParkDurations[len(realParkDurations)-1])
		} else {
			t.Logf("host=%s first failure at park=%s — keep idle-ttl below that", rs.URL.Host, firstFail)
		}
	}
}
