package e2e_test

import (
	"bytes"
	"context"
	"io"
	"net"
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

// socks5h:// names the same SOCKS5 upstream transport as socks5:// — both
// spellings must route traffic through the one shared dial implementation.
func TestSocks5hRouteSchemeServesTraffic(t *testing.T) {
	target := NewEchoTarget(t)
	for _, tc := range []struct {
		name     string
		proxy    string
		wantAuth bool
	}{
		{"socks5", "socks5://", false},
		{"socks5h", "socks5h://", false},
		{"SOCKS5H with credentials", "SOCKS5H://route-user:route-pass@", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var sim *SocksSim
			if tc.wantAuth {
				sim = NewSocksSim(t, SocksAuthRequired, "route-user", "route-pass")
			} else {
				sim = NewSocksSim(t, SocksOK, "", "")
			}
			gw := NewGateway(t, defaultGatewayConfig([]RouteConfig{
				{Proxy: tc.proxy + sim.Addr, Kind: "v4"},
			}))
			code, body := GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/atyp", "e2e-echo:/atyp")
			if code != 200 {
				t.Fatalf("GET via %q route: status %d body %q", tc.proxy, code, body)
			}
			if sim.Hits.Load() == 0 {
				t.Fatal("the route simulator saw no connection")
			}
		})
	}
}

// socks5:// and socks5h:// spellings of one endpoint are one canonical route:
// swapping the spelling across a reload must keep the route's live state —
// its success counter — rather than creating a second, cold route. The second
// route exists to prove the reloaded generation actually published: a config
// the gateway rejects (as socks5h:// once was) would keep the old one-route
// pool serving and look deceptively identical here.
func TestSocks5hSchemeAliasPreservesRouteIdentityAcrossReload(t *testing.T) {
	target := NewEchoTarget(t)
	sim := NewSocksSim(t, SocksOK, "", "")
	other := NewSocksSim(t, SocksOK, "", "")
	gw := NewGateway(t, defaultGatewayConfig([]RouteConfig{
		{Proxy: "socks5://" + sim.Addr, Kind: "v4"},
	}))

	GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/before", "e2e-echo:/before")

	gw.ReloadConfig(defaultGatewayConfig([]RouteConfig{
		{Proxy: "socks5h://" + sim.Addr, Kind: "v4"},
		{Proxy: "socks5://" + other.Addr, Kind: "v4"},
	}), []string{sim.Addr, other.Addr})

	st, err := gw.Status()
	if err != nil {
		t.Fatal(err)
	}
	if got := st.Pool[0].Successes; got != 1 {
		t.Fatalf("successes after the reload = %d, want the pre-reload state preserved (1)", got)
	}

	GetVia(t, ProxyClient(gw.MixedAddr), target.URL+"/after", "e2e-echo:/after")
}
