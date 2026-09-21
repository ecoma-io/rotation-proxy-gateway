package config

import (
	"net/url"
	"testing"
)

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

// CanonicalRouteID is the duplicate-detection key and the reload-state
// identity, so two routes carrying distinct credentials must never collapse
// to one identity. The decoded userinfo concatenation used previously made
// "u:v" as a no-password username and username "u" + password "v" produce the
// same string, wrongly rejecting one of the two as a duplicate and, across a
// reload, attaching one route's pool state to the other.
func TestCanonicalRouteIDDistinguishesCredentials(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"colon username without password vs user-password pair",
			"socks5://u%3Av@h.example:1080",
			"socks5://u:v@h.example:1080"},
		{"two-colon username vs user with colon password",
			"socks5://a%3Ab%3Ac@h.example:1080",
			"socks5://a:b%3Ac@h.example:1080"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			idA := CanonicalRouteID(mustParseURL(t, tc.a))
			idB := CanonicalRouteID(mustParseURL(t, tc.b))
			if idA == idB {
				t.Fatalf("distinct credentials share identity %q:\n  %s\n  %s", idA, tc.a, tc.b)
			}
		})
	}
}

// Equivalent spellings must still collapse: scheme and host case normalize
// (IPv6 included) while credential case is preserved as a real difference.
func TestCanonicalRouteIDNormalization(t *testing.T) {
	// Config now only ever produces socks5 URLs, so scheme case can no longer
	// vary from the outside; host and port normalization are the live surface.
	same := [][2]string{
		{"socks5://user:pass@Provider.example:1080", "socks5://user:pass@provider.EXAMPLE:1080"},
		{"socks5://user:pass@[2001:DB8::1]:1080", "socks5://user:pass@[2001:db8::1]:1080"},
		{"socks5://user:pass@provider.example:1080", "socks5://user:pass@provider.example:01080"},
	}
	for _, pair := range same {
		a := CanonicalRouteID(mustParseURL(t, pair[0]))
		b := CanonicalRouteID(mustParseURL(t, pair[1]))
		if a != b {
			t.Fatalf("equivalent routes differ:\n  %s -> %s\n  %s -> %s", pair[0], a, pair[1], b)
		}
	}
	different := [][2]string{
		{"socks5://user:pass@h.example:1080", "socks5://user:pass@h.example:1081"},
		{"socks5://user:pass@h.example:1080", "socks5://user:Pass@h.example:1080"},
		{"socks5://user:pass@h.example:1080", "socks5://user@h.example:1080"},
	}
	for _, pair := range different {
		a := CanonicalRouteID(mustParseURL(t, pair[0]))
		b := CanonicalRouteID(mustParseURL(t, pair[1]))
		if a == b {
			t.Fatalf("distinct routes share identity %q:\n  %s\n  %s", a, pair[0], pair[1])
		}
	}
}
