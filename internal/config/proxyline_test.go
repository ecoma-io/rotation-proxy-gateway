package config

import (
	"strings"
	"testing"
)

// The README documents exactly four accepted proxy forms plus bracketed IPv6
// literals; these tests pin that surface directly against parseRouteSpec, the
// single entry the runtime loader uses for every proxies.auto item.
func TestParseRouteSpecAcceptsDocumentedForms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		wantUser string
		wantPass string
		wantHost string
	}{
		{"socks5 url without credentials", "socks5://provider.example:1080", "", "", "provider.example:1080"},
		{"socks5 url with credentials", "socks5://route-user:route-pass@provider.example:1080", "route-user", "route-pass", "provider.example:1080"},
		{"bare host:port:user:pass", "provider.example:1080:route-user:route-pass", "route-user", "route-pass", "provider.example:1080"},
		{"bare user:pass@host:port", "route-user:route-pass@provider.example:1080", "route-user", "route-pass", "provider.example:1080"},
		{"bracketed ipv6 bare form", "[2001:db8::1]:1080:route-user:route-pass", "route-user", "route-pass", "[2001:db8::1]:1080"},
		{"bracketed ipv6 url form", "socks5://route-user:route-pass@[2001:db8::1]:1080", "route-user", "route-pass", "[2001:db8::1]:1080"},
		{"uppercase scheme normalized", "SOCKS5://provider.example:1080", "", "", "provider.example:1080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parseRouteSpec(autoProxyFileConfig{Proxy: tc.raw, Kind: "v4"})
			if err != nil {
				t.Fatalf("parseRouteSpec(%q) error = %v", tc.raw, err)
			}
			if spec.Kind != EgressV4 {
				t.Fatalf("kind = %q, want v4", spec.Kind)
			}
			if spec.URL.Host != tc.wantHost {
				t.Fatalf("host = %q, want %q", spec.URL.Host, tc.wantHost)
			}
			gotUser, gotPass := "", ""
			if spec.URL.User != nil {
				gotUser = spec.URL.User.Username()
				gotPass, _ = spec.URL.User.Password()
			}
			if gotUser != tc.wantUser || gotPass != tc.wantPass {
				t.Fatalf("userinfo = %q:%q, want %q:%q", gotUser, gotPass, tc.wantUser, tc.wantPass)
			}
		})
	}
}

func TestParseRouteSpecRejectsUndocumentedForms(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"http scheme", "http://provider.example:1080", "unsupported scheme"},
		{"https scheme", "https://provider.example:1080", "unsupported scheme"},
		{"missing port", "socks5://provider.example", "missing port"},
		{"empty host", "socks5://:1080", "missing host"},
		{"url path", "socks5://provider.example:1080/path", "path, query, and fragment"},
		{"url query", "socks5://provider.example:1080?x=1", "path, query, and fragment"},
		{"url fragment", "socks5://provider.example:1080#frag", "path, query, and fragment"},
		{"bare host:port without credentials", "provider.example:1080", "invalid proxy format"},
		{"bare form missing password", "provider.example:1080:route-user", "invalid proxy format"},
		{"bare form password with colon", "provider.example:1080:route-user:pa:ss", "invalid proxy format"},
		{"bare credentials missing port", "route-user:route-pass@provider.example", "port is required"},
		{"unterminated ipv6 bracket", "[2001:db8::1:1080:route-user:route-pass", "invalid proxy format"},
		{"port zero", "socks5://provider.example:0", "invalid proxy port"},
		{"port above range", "socks5://provider.example:70000", "invalid proxy port"},
		{"port not numeric", "socks5://provider.example:socks", "invalid proxy URL"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRouteSpec(autoProxyFileConfig{Proxy: tc.raw, Kind: "v4"})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("parseRouteSpec(%q) error = %v, want %q", tc.raw, err, tc.want)
			}
		})
	}
}

// Parse rejections quote only structural facts (ports, shapes); the offending
// route line, which normally carries credentials, must never surface.
func TestParseRouteSpecErrorNeverContainsCredentials(t *testing.T) {
	for _, raw := range []string{
		"socks5://route-user:route-pass@provider.example:0",
		"socks5://route-user:route-pass@provider.example:70000",
		"route-user:route-pass@provider.example",
		"provider.example:1080:route-user:route-pass:extra",
		"socks5://route-user:route-pass@provider.example:1080/path",
	} {
		_, err := parseRouteSpec(autoProxyFileConfig{Proxy: raw, Kind: "v4"})
		if err == nil {
			t.Fatalf("parseRouteSpec(%q) unexpectedly accepted", raw)
		}
		for _, secret := range []string{"route-user", "route-pass"} {
			if strings.Contains(err.Error(), secret) {
				t.Fatalf("error for %q leaked %q: %v", raw, secret, err)
			}
		}
	}
}
