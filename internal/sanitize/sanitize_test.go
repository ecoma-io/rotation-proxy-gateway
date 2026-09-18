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
