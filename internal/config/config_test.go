package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDefaults(t *testing.T) {
	for _, k := range []string{"LISTEN_ADDR", "ADMIN_ADDR", "PROXIES_FILE", "LOG_LEVEL",
		"MAX_RETRIES", "COOLDOWN_BASE", "COOLDOWN_MAX", "CONNECT_TIMEOUT", "MAX_BODY_BUFFER", "TARGET_TLS_INSECURE"} {
		t.Setenv(k, "") // treated as unset
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if cfg.AdminAddr != DefaultAdminAddr {
		t.Errorf("AdminAddr = %q, want %q", cfg.AdminAddr, DefaultAdminAddr)
	}
	if cfg.ProxiesFile != DefaultProxiesFile {
		t.Errorf("ProxiesFile = %q, want %q", cfg.ProxiesFile, DefaultProxiesFile)
	}
	if cfg.MaxRetries != DefaultMaxRetries {
		t.Errorf("MaxRetries = %d, want %d", cfg.MaxRetries, DefaultMaxRetries)
	}
	if cfg.CooldownBase != DefaultCooldownBase || cfg.CooldownMax != DefaultCooldownMax {
		t.Errorf("cooldown = %s..%s, want %s..%s", cfg.CooldownBase, cfg.CooldownMax, DefaultCooldownBase, DefaultCooldownMax)
	}
	if cfg.ConnectTimeout != DefaultConnectTimeout {
		t.Errorf("ConnectTimeout = %s, want %s", cfg.ConnectTimeout, DefaultConnectTimeout)
	}
	if cfg.MaxBodyBuffer != DefaultMaxBodyBuffer {
		t.Errorf("MaxBodyBuffer = %d, want %d", cfg.MaxBodyBuffer, DefaultMaxBodyBuffer)
	}
	if cfg.TargetTLSInsecure {
		t.Error("TargetTLSInsecure = true, want false")
	}
}

func TestEnvOverrides(t *testing.T) {
	t.Setenv("LISTEN_ADDR", ":9999")
	t.Setenv("MAX_RETRIES", "5")
	t.Setenv("COOLDOWN_BASE", "1s")
	t.Setenv("COOLDOWN_MAX", "2m")
	t.Setenv("CONNECT_TIMEOUT", "3s")
	t.Setenv("MAX_BODY_BUFFER", "1024")
	t.Setenv("TARGET_TLS_INSECURE", "true")
	t.Setenv("LOG_LEVEL", "debug")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ListenAddr != ":9999" || cfg.AdminAddr != DefaultAdminAddr ||
		cfg.MaxRetries != 5 || cfg.CooldownBase != time.Second || cfg.CooldownMax != 2*time.Minute ||
		cfg.ConnectTimeout != 3*time.Second || cfg.MaxBodyBuffer != 1024 ||
		!cfg.TargetTLSInsecure || cfg.LogLevel != "debug" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestInvalidValues(t *testing.T) {
	cases := []struct {
		name, key, val, wantInErr string
	}{
		{"zero retries", "MAX_RETRIES", "0", "MAX_RETRIES"},
		{"bad retries", "MAX_RETRIES", "many", "MAX_RETRIES"},
		{"bad duration", "COOLDOWN_BASE", "soon", "COOLDOWN_BASE"},
		{"bad bool", "TARGET_TLS_INSECURE", "maybe", "TARGET_TLS_INSECURE"},
		{"admin equals listen", "ADMIN_ADDR", ":7777", "LISTEN_ADDR"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(tc.key, tc.val)
			t.Setenv("LISTEN_ADDR", ":7777")
			if tc.key == "LISTEN_ADDR" {
				return // not a case here
			}
			_, err := Load()
			if err == nil {
				t.Fatalf("Load() succeeded, want error mentioning %q", tc.wantInErr)
			}
			if !strings.Contains(err.Error(), tc.wantInErr) {
				t.Fatalf("error %q does not mention %q", err, tc.wantInErr)
			}
		})
	}
}

func TestDotEnvDoesNotOverrideEnvironment(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("MAX_RETRIES", "7") // real env wins over .env
	envFile := "LISTEN_ADDR=:4321\nMAX_RETRIES=9\n# comment\n\nBADLINE\n"
	if err := os.WriteFile(".env", []byte(envFile), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.ListenAddr != ":4321" {
		t.Errorf("ListenAddr = %q, want :4321 from .env", cfg.ListenAddr)
	}
	if cfg.MaxRetries != 7 {
		t.Errorf("MaxRetries = %d, want 7 (environment beats .env)", cfg.MaxRetries)
	}
}

func TestParseProxiesRejectsNonSOCKS(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	content := "# comment line\n" +
		"http://a.example:8080\n" +
		"socks5://user:pass@b.example:1080\n" +
		"https://c.example:8443\n" +
		"ftp://bad.example:21\n" +
		"://not-a-url\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseProxies(path)
	if err == nil {
		t.Fatal("ParseProxies() succeeded, want error for non-SOCKS lines")
	}
	for _, want := range []string{"line 2", "line 4", "line 5", "line 6"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries on error, want 0", len(entries))
	}
}

func TestParseProxiesValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	content := "# only comments\n\nsocks5://a.example:1080\nsocks5://u:p@b.example:1080\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseProxies(path)
	if err != nil {
		t.Fatalf("ParseProxies() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	if got := entries[1].User.Username(); got != "u" {
		t.Errorf("entry[1] user = %q, want u", got)
	}
}

func TestParseProxiesBareSOCKSFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	content := "# bare SOCKS5 forms\n203.0.113.7:1080:alice:s3cret\ncarol:s4cret@203.0.113.9:1080\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	entries, err := ParseProxies(path)
	if err != nil {
		t.Fatalf("ParseProxies() error = %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("got %d entries, want 2", len(entries))
	}
	for i, want := range []struct{ host, user, pass string }{
		{"203.0.113.7:1080", "alice", "s3cret"},
		{"203.0.113.9:1080", "carol", "s4cret"},
	} {
		if entries[i].Scheme != "socks5" {
			t.Errorf("entry[%d] scheme = %q, want socks5", i, entries[i].Scheme)
		}
		if entries[i].Host != want.host {
			t.Errorf("entry[%d] host = %q, want %q", i, entries[i].Host, want.host)
		}
		if u := entries[i].User.Username(); u != want.user {
			t.Errorf("entry[%d] user = %q, want %q", i, u, want.user)
		}
		if p, _ := entries[i].User.Password(); p != want.pass {
			t.Errorf("entry[%d] pass = %q, want %q", i, p, want.pass)
		}
	}
}

func TestParseProxiesBareBadLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	content := "203.0.113.7:1080:onlythree\n203.0.113.7:notaport:u:p\nhttp://bad.example:8080\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProxies(path); err == nil {
		t.Fatal("ParseProxies() succeeded, want error for malformed/non-SOCKS lines")
	} else {
		for _, want := range []string{"line 1", "line 2", "line 3"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q missing %s marker", err, want)
			}
		}
	}
}

func TestParseProxiesEmpty(t *testing.T) {
	path := filepath.Join(t.TempDir(), "proxies.txt")
	if err := os.WriteFile(path, []byte("# nothing here\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ParseProxies(path); err == nil || !strings.Contains(err.Error(), "no proxies") {
		t.Fatalf("err = %v, want no-proxies error", err)
	}
}
