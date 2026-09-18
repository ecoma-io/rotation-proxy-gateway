package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeProxies(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestHardeningRejectsURLWithoutExplicitPort(t *testing.T) {
	lines := []string{
		"socks5://proxy.example",
		"socks5://proxy.example:",
		"socks5://TEST-user:TEST-password@proxy.example",
		"socks5://[2001:db8::1]",
		"socks5://TEST-user:TEST-password@[2001:db8::1]",
		"TEST-user:TEST-password@proxy.example",
		"TEST-user:TEST-password@[2001:db8::1]",
	}
	for _, line := range lines {
		path := writeProxies(t, line+"\n")
		if _, err := ParseProxies(path); err == nil {
			t.Errorf("ParseProxies(%q) succeeded, want missing-port rejection", line)
		} else if strings.Contains(err.Error(), "TEST-password") {
			t.Errorf("ParseProxies(%q) error leaked credentials: %q", line, err)
		}
	}
}

func TestHardeningAcceptsExplicitPortsIncludingIPv6(t *testing.T) {
	content := "socks5://proxy.example:1080\n" +
		"socks5://TEST-user:TEST-password@[2001:db8::1]:1080\n" +
		"TEST-user:TEST-password@[2001:db8::2]:1080\n" +
		"[2001:db8::3]:1080:TEST-user:TEST-password\n"
	path := writeProxies(t, content)
	entries, err := ParseProxies(path)
	if err != nil {
		t.Fatalf("ParseProxies() error = %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("got %d entries, want 4", len(entries))
	}
}

func TestHardeningRejectsPathQueryFragment(t *testing.T) {
	lines := []string{
		"socks5://proxy.example:1080/path",
		"socks5://proxy.example:1080?q=1",
		"socks5://proxy.example:1080#frag",
		"socks5://TEST-user:TEST-password@proxy.example:1080/path?q=1#frag",
		"socks5://[2001:db8::1]:1080/path",
		"TEST-user:TEST-password@proxy.example:1080/path",
	}
	for _, line := range lines {
		path := writeProxies(t, line+"\n")
		if _, err := ParseProxies(path); err == nil {
			t.Errorf("ParseProxies(%q) succeeded, want path/query/fragment rejection", line)
		} else if strings.Contains(err.Error(), "TEST-password") {
			t.Errorf("ParseProxies(%q) error leaked credentials: %q", line, err)
		}
	}
}

func TestHardeningRejectsDuplicateCanonicalRoutes(t *testing.T) {
	// Exact duplicate.
	path := writeProxies(t, "socks5://a.example:1080\nsocks5://a.example:1080\n")
	if _, err := ParseProxies(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("exact duplicate err = %v, want duplicate error", err)
	}
	// URL + bare equivalent with same credentials.
	path = writeProxies(t, "socks5://TEST-user:TEST-password@b.example:1080\nTEST-user:TEST-password@b.example:1080\n")
	if _, err := ParseProxies(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("equivalent-form duplicate err = %v, want duplicate error", err)
	} else if strings.Contains(err.Error(), "TEST-password") {
		t.Fatalf("duplicate error leaked credentials: %q", err)
	}
	// Distinct credentials on same host:port remain distinct.
	path = writeProxies(t, "socks5://TEST-user:TEST-password@c.example:1080\nsocks5://TEST-user:TEST-other@c.example:1080\n")
	if _, err := ParseProxies(path); err != nil {
		t.Fatalf("distinct credentials rejected: %v", err)
	}
	// Same credentials differing only by host case are duplicates, not distinct routes.
	path = writeProxies(t, "socks5://TEST-user:TEST-password@d.example:1080\nsocks5://TEST-user:TEST-password@D.EXAMPLE:1080\n")
	if _, err := ParseProxies(path); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("case-variant duplicate err = %v, want duplicate error", err)
	} else if strings.Contains(err.Error(), "TEST-password") {
		t.Fatalf("duplicate error leaked credentials: %q", err)
	}
}

func TestHardeningLogLevelExact(t *testing.T) {
	for _, lvl := range []string{"debug", "info", "warn", "error"} {
		t.Setenv("LOG_LEVEL", lvl)
		cfg, err := Load()
		if err != nil {
			t.Errorf("Load() with LOG_LEVEL=%q error = %v", lvl, err)
			continue
		}
		if cfg.LogLevel != lvl {
			t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, lvl)
		}
	}
	for _, lvl := range []string{"DEBUG", "Info", "verbose", "all", "info ", " info"} {
		t.Run("reject "+lvl, func(t *testing.T) {
			t.Setenv("LOG_LEVEL", lvl)
			if _, err := Load(); err == nil {
				t.Fatalf("Load() with LOG_LEVEL=%q succeeded, want rejection", lvl)
			} else if !strings.Contains(err.Error(), "LOG_LEVEL") {
				t.Fatalf("error %q does not mention LOG_LEVEL", err)
			}
		})
	}
}

func TestHardeningNewErrorsNeverLeakCredentials(t *testing.T) {
	const secret = "TEST-password-leak-check"
	contents := []string{
		"socks5://TEST-user:" + secret + "@proxy.example\n",
		"socks5://TEST-user:" + secret + "@proxy.example:1080/secret-path\n",
		"socks5://TEST-user:" + secret + "@proxy.example:1080\nsocks5://TEST-user:" + secret + "@proxy.example:1080\n",
	}
	for i, content := range contents {
		path := writeProxies(t, content)
		_, err := ParseProxies(path)
		if err == nil {
			t.Fatalf("case %d succeeded, want error", i)
		}
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("case %d error leaked credentials: %q", i, err)
		}
	}
}
