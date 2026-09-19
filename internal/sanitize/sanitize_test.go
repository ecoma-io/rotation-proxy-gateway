package sanitize

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// All credentials here are fake TEST fixtures.
func TestRedactsUserinfoWithSpecialChars(t *testing.T) {
	in := "dial socks5://TESTUSER:TESTP/ss?w@rd@proxy.test:1080: refused"
	got := Sanitize(in)
	for _, secret := range []string{"TESTUSER", "TESTP"} {
		if strings.Contains(got, secret) {
			t.Fatalf("Sanitize leaked %q in %q", secret, got)
		}
	}
	if !strings.Contains(got, "socks5://[redacted]@proxy.test:1080") {
		t.Fatalf("Sanitize lost host identity: %q", got)
	}
}

func TestRedactsMultipleURLs(t *testing.T) {
	in := "from socks5://TESTU1:TESTP1@a.test:1080 to socks5://TESTU2:TESTP2@b.test:1080"
	got := Sanitize(in)
	for _, s := range []string{"TESTU1", "TESTP1", "TESTU2", "TESTP2"} {
		if strings.Contains(got, s) {
			t.Fatalf("Sanitize leaked %q in %q", s, got)
		}
	}
	if !strings.Contains(got, "a.test:1080") || !strings.Contains(got, "b.test:1080") {
		t.Fatalf("Sanitize lost hosts: %q", got)
	}
}

// The bare user:pass@host spelling accepted in configuration must redact too,
// while ordinary user@host mentions (an email address) pass through untouched.
func TestRedactsBareUserinfo(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"plain bare form", "user:pass@host.test:1080", "[redacted]@host.test:1080"},
		{"inside an error", "invalid proxy user:pass@10.0.0.1:1080 (TEST)", "invalid proxy [redacted]@10.0.0.1:1080 (TEST)"},
		{"bracketed ipv6 host", "bob:pw@[2001:db8::1]:1080", "[redacted]@[2001:db8::1]:1080"},
		{"alongside a scheme URL", "from socks5://TESTU:TESTP@a.test:1 to TESTU2:TESTP2@b.test:2", "from socks5://[redacted]@a.test:1 to [redacted]@b.test:2"},
		{"two bare tokens", "a:b@c.test:1 d:e@f.test:2", "[redacted]@c.test:1 [redacted]@f.test:2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
	for _, keep := range []string{
		"alice@example.com",
		"admin@host.test:9090",         // the port colon sits after the '@'
		"route a:b:c:d has no at-sign", // colon-separated shape without userinfo
	} {
		if got := Sanitize(keep); got != keep {
			t.Fatalf("Sanitize(%q) = %q, want unchanged", keep, got)
		}
	}
}

func TestNeutralizesANSIAndControls(t *testing.T) {
	in := "fail\x1b[31mred\x1b[0m\nsecond\tline\rend\x07"
	got := Sanitize(in)
	if strings.Contains(got, "\x1b") {
		t.Fatalf("Sanitize kept ESC: %q", got)
	}
	if strings.ContainsAny(got, "\n\r\t\x07") {
		t.Fatalf("Sanitize kept controls: %q", got)
	}
	if !strings.Contains(got, "red") || !strings.Contains(got, "second line") {
		t.Fatalf("Sanitize dropped readable text: %q", got)
	}
}

// Every ANSI escape form stripANSI understands must vanish, including the
// truncated and lone-ESC tails an attacker can craft.
func TestStripsAllANSIForms(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
		want string
	}{
		{"CSI with params", "a\x1b[31;1mb", "ab"},
		{"OSC terminated by BEL", "a\x1b]0;title\x07b", "ab"},
		{"OSC terminated by ST", "a\x1b]8;;http://x\x1b\\b", "ab"},
		{"two-byte designator", "a\x1b(Bb", "ab"},
		{"single-char sequence", "a\x1bMb", "ab"},
		{"lone ESC at end", "trailing\x1b", "trailing"},
		{"unterminated CSI", "unterminated\x1b[31", "unterminated"},
		{"unterminated OSC", "unterminated\x1b]0;title", "unterminated"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Sanitize(tc.in); got != tc.want {
				t.Fatalf("Sanitize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBoundsOutput(t *testing.T) {
	in := strings.Repeat("z", MaxLength+100)
	got := Sanitize(in)
	if n := utf8.RuneCountInString(got); n != MaxLength+1 {
		t.Fatalf("rune length = %d, want %d", n, MaxLength+1)
	}
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("bounded output must end with ellipsis: %q", got[len(got)-10:])
	}
}

func TestErrorStringNil(t *testing.T) {
	if got := ErrorString(nil); got != "" {
		t.Fatalf("ErrorString(nil) = %q, want empty", got)
	}
}
