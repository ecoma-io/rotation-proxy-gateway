package config

import (
	"strings"
	"testing"
)

// The configuration docs (docs/configuration.md) define exactly three
// accepted proxy forms; route lines carry no scheme because the endpoint
// protocol is always SOCKS5. These tests pin
// that surface directly against parseRouteSpec, the single entry the runtime
// loader uses for every proxies.auto item.
func TestParseRouteSpecAcceptsDocumentedForms(t *testing.T) {
	for _, tc := range []struct {
		name     string
		raw      string
		wantUser string
		wantPass string
		wantHost string
	}{
		{"bare host:port without credentials", "provider.example:1080", "", "", "provider.example:1080"},
		{"bare host:port:user:pass", "provider.example:1080:route-user:route-pass", "route-user", "route-pass", "provider.example:1080"},
		{"bare user:pass@host:port", "route-user:route-pass@provider.example:1080", "route-user", "route-pass", "provider.example:1080"},
		{"bracketed ipv6 without credentials", "[2001:db8::1]:1080", "", "", "[2001:db8::1]:1080"},
		{"bracketed ipv6 bare form", "[2001:db8::1]:1080:route-user:route-pass", "route-user", "route-pass", "[2001:db8::1]:1080"},
		{"bracketed ipv6 at-credentials form", "route-user:route-pass@[2001:db8::1]:1080", "route-user", "route-pass", "[2001:db8::1]:1080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec, err := parseRouteSpec(autoProxyFileConfig{Proxy: tc.raw, Kind: "v4"})
			if err != nil {
				t.Fatalf("parseRouteSpec(%q) error = %v", tc.raw, err)
			}
			if spec.Kind != EgressV4 {
				t.Fatalf("kind = %q, want v4", spec.Kind)
			}
			if spec.URL.Scheme != "socks5" {
				t.Fatalf("implicit scheme = %q, want socks5", spec.URL.Scheme)
			}
			if spec.URL.Host != tc.wantHost {
				t.Fatalf("host = %q, want %q", spec.URL.Host, tc.wantHost)
			}
			if tc.wantUser == "" && spec.URL.User != nil {
				t.Fatalf("credentials = %q, want none", spec.URL.User.String())
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

// The endpoint protocol is not configurable, so no scheme spelling is
// accepted — not even socks5:// or its socks5h client-convention alias. The
// socks5/socks5h distinction belongs to inbound clients (it is the CONNECT
// frame's address type), never to the route line.
func TestParseRouteSpecRejectsEveryScheme(t *testing.T) {
	for _, tc := range []struct{ name, raw string }{
		{"socks5 scheme", "socks5://provider.example:1080"},
		{"socks5 scheme with credentials", "socks5://route-user:route-pass@provider.example:1080"},
		{"socks5h scheme", "socks5h://provider.example:1080"},
		{"uppercase SOCKS5 scheme", "SOCKS5://provider.example:1080"},
		{"uppercase SOCKS5H scheme", "SOCKS5H://provider.example:1080"},
		{"http scheme", "http://provider.example:1080"},
		{"https scheme", "https://provider.example:1080"},
		{"socks4 scheme", "socks4://provider.example:1080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRouteSpec(autoProxyFileConfig{Proxy: tc.raw, Kind: "v4"})
			if err == nil || !strings.Contains(err.Error(), "carry no scheme") {
				t.Fatalf("parseRouteSpec(%q) error = %v, want the carries-no-scheme rejection", tc.raw, err)
			}
			for _, secret := range []string{"route-user", "route-pass"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error for %q leaked %q: %v", tc.raw, secret, err)
				}
			}
		})
	}
}

func TestParseRouteSpecRejectsUndocumentedForms(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"missing port", "provider.example", "invalid proxy format"},
		{"empty host", ":1080", "invalid proxy format"},
		{"at-form missing port", "route-user:route-pass@provider.example", "port is required"},
		{"at-form empty host", "route-user:route-pass@:1080", "host is required"},
		{"at-form username without password", "route-user@provider.example:1080", "credentials must be user:pass@host:port"},
		{"at-form empty password", "route-user:@provider.example:1080", "credentials must be user:pass@host:port"},
		{"at-form empty username and password", ":@provider.example:1080", "credentials must be user:pass@host:port"},
		{"bare form missing password", "provider.example:1080:route-user", "invalid proxy format"},
		{"bare form password with colon", "provider.example:1080:route-user:pa:ss", "invalid proxy format"},
		{"unterminated ipv6 bracket", "[2001:db8::1:1080:route-user:route-pass", "invalid proxy format"},
		{"host with a space", "exa mple.com:1080", "invalid proxy format"},
		{"host with a space and credentials", "exa mple.com:1080:route-user:route-pass", "invalid proxy format"},
		{"host with a fragment separator", "exa#mple.com:1080", "invalid proxy format"},
		{"host with a query separator", "exa?mple.com:1080", "invalid proxy format"},
		{"host with a path separator", "exa/mple.com:1080", "invalid proxy format"},
		{"host with a percent sign", "exa%mple.com:1080", "invalid proxy format"},
		{"port zero", "provider.example:0", "invalid proxy port"},
		{"port above range", "provider.example:70000", "invalid proxy port"},
		{"port not numeric", "provider.example:socks", "invalid proxy port"},
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
		"provider.example:0:route-user:route-pass",
		"provider.example:1080:route-user:route-pass:extra",
		// A mistyped bare line whose port position holds the password
		// ("host:password"): the port rejection must name only the port rule.
		"provider.example:route-pass",
		"route-user:route-pass@provider.example:0",
		"route-user:route-pass@provider.example:70000",
		"route-user:route-pass@provider.example:1080/path",
		// Credential shapes outside the documented user:pass pair.
		"route-user@provider.example:1080",
		"route-user:@provider.example:1080",
		":@provider.example:1080",
		"exa mple.com:1080:route-user:route-pass",
		"socks5://route-user:route-pass@provider.example:1080",
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
