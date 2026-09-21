package e2e_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// newRawEchoTarget is a plain TCP echo for tunnel round trips that must not
// involve HTTP or DNS: bytes in, bytes out.
func newRawEchoTarget(t testing.TB) string {
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
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// A socks5 client resolves the target itself and sends ATYP=IP; a socks5h
// client sends the name. Both speak plain SOCKS5 — the only wire difference
// is the CONNECT frame's address type, and the gateway must reproduce exactly
// that type on its egress CONNECT: IPv4 as four bytes, IPv6 as sixteen, a
// domain as the untouched hostname. The upstream simulator tunnels to a local
// echo instead of the requested destination, so the reserved example.test
// name is recorded, never resolved — if the gateway resolved a domain locally
// the recorded ATYP would flip to 0x01 and fail the case.
func TestIngressAddressTypePreservedToEgress(t *testing.T) {
	echo := newRawEchoTarget(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	sim.TunnelTo = echo
	gw := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: sim.RouteValue(), Kind: "v4"},
	}))

	cases := []struct {
		name     string
		host     string
		atyp     byte
		wantAddr []byte
	}{
		{"ipv4 frame stays ATYP 0x01", "198.51.100.7", 0x01, []byte{198, 51, 100, 7}},
		{"ipv6 frame stays ATYP 0x04", "2001:db8::1", 0x04, append([]byte{0x20, 0x01, 0x0d, 0xb8}, append(make([]byte, 11), 0x01)...)},
		{"domain frame stays ATYP 0x03", "example.test", 0x03, []byte("example.test")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frame, err := socksConnectFrameWithATYP(tc.host, 443, tc.atyp)
			if err != nil {
				t.Fatal(err)
			}
			conn, err := dialSocksTunnelFrame(context.Background(), gw.MixedAddr, frame)
			if err != nil {
				t.Fatalf("tunnel: %v", err)
			}
			defer func() { _ = conn.Close() }()
			// The tunnel must actually carry bytes: echo through the sim's
			// replacement destination.
			if _, err := conn.Write([]byte("atyp-ping")); err != nil {
				t.Fatalf("write: %v", err)
			}
			_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			got := make([]byte, 9)
			if _, err := io.ReadFull(conn, got); err != nil || string(got) != "atyp-ping" {
				t.Fatalf("echo = %q, err = %v", got, err)
			}

			records := sim.Connects()
			if len(records) == 0 {
				t.Fatal("the upstream simulator saw no CONNECT request")
			}
			rec := records[len(records)-1]
			if rec.ATYP != tc.atyp {
				t.Fatalf("egress ATYP = 0x%02x, want 0x%02x", rec.ATYP, tc.atyp)
			}
			if !bytes.Equal(rec.Addr, tc.wantAddr) {
				t.Fatalf("egress DST.ADDR = %v, want %v", rec.Addr, tc.wantAddr)
			}
			if rec.Host != tc.host || rec.Port != 443 {
				t.Fatalf("egress target = %q:%d, want %q:443", rec.Host, rec.Port, tc.host)
			}
		})
	}
}

// Route lines carry no scheme: every route is a SOCKS5 endpoint. All three
// documented bare forms must serve traffic through the same dial path.
func TestBareRouteFormsServeTraffic(t *testing.T) {
	target := NewEchoTarget(t)
	for _, tc := range []struct {
		name  string
		route func(addr string) string
		auth  bool
	}{
		{"host:port", func(addr string) string { return addr }, false},
		{"host:port:user:pass", func(addr string) string { return addr + ":route-user:route-pass" }, true},
		{"user:pass@host:port", func(addr string) string { return "route-user:route-pass@" + addr }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sim *SocksSim
			if tc.auth {
				sim = NewSocksSim(t, SocksAuthRequired, "route-user", "route-pass")
			} else {
				sim = NewSocksSim(t, SocksOK, "", "")
			}
			gw := NewGateway(t, defaultGatewayConfig([]RouteConfig{
				{Proxy: tc.route(sim.Addr), Kind: "v4"},
			}))
			code, body := GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/atyp", "e2e-echo:/atyp")
			if code != 200 {
				t.Fatalf("GET via %q route: status %d body %q", tc.name, code, body)
			}
			if sim.Hits.Load() == 0 {
				t.Fatal("the route simulator saw no connection")
			}
		})
	}
}

// A scheme'd route line is rejected outright — the endpoint protocol is not
// configurable — and a rejected config must leave the last-known-good pool
// serving untouched. The second route exists to make the surviving pool
// distinguishable from a hypothetical cold start.
func TestSchemedRouteLineRejectedKeepsServing(t *testing.T) {
	target := NewEchoTarget(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	other := NewSocksSim(t, SocksOK, "", "")
	gw := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: sim.Addr, Kind: "v4"},
		{Proxy: other.Addr, Kind: "v4"},
	}))

	GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/before", "e2e-echo:/before")

	cfg := defaultGatewayConfig([]RouteConfig{
		{Proxy: "socks5://" + sim.Addr, Kind: "v4"},
		{Proxy: other.Addr, Kind: "v4"},
	})
	gw.ReloadConfigRaw(renderConfig(cfg))
	gw.WaitForCondition(reloadSettle, "a scheme rejection warning in the logs",
		func(*Status) bool { return strings.Contains(gw.Logs(), "carry no scheme") })
	st, err := gw.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Pool) != 2 {
		t.Fatalf("pool after the rejected reload has %d routes, want the last-known-good 2", len(st.Pool))
	}
	if got := st.Pool[0].Successes; got != 1 {
		t.Fatalf("successes after the rejected reload = %d, want the serving state preserved (1)", got)
	}
	GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/after", "e2e-echo:/after")
}
