package config

import (
	"strings"
	"testing"
)

func TestParseAccountAcceptsDocumentedShapes(t *testing.T) {
	for _, tc := range []struct {
		name         string
		raw          string
		wantUsername string
		wantPassword string
	}{
		{"plain", "alice:secret", "alice", "secret"},
		// The split is at the first colon, so colons are legal password bytes.
		{"password with colons", "alice:pa:ss:wo:rd", "alice", "pa:ss:wo:rd"},
		// RFC 1929 permits a zero-length password; validation is on shape, not
		// strength.
		{"empty password", "alice:", "alice", ""},
		{"max username", strings.Repeat("u", 255) + ":secret", strings.Repeat("u", 255), "secret"},
		{"max password", "alice:" + strings.Repeat("p", 255), "alice", strings.Repeat("p", 255)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			account, err := parseAccount(tc.raw)
			if err != nil {
				t.Fatalf("parseAccount(%q): %v", tc.raw, err)
			}
			if string(account.Username) != tc.wantUsername || string(account.Password) != tc.wantPassword {
				t.Fatalf("account = %q / %q, want %q / %q",
					account.Username, account.Password, tc.wantUsername, tc.wantPassword)
			}
		})
	}
}

func TestParseAccountRejectsInvalidShapesWithoutLeakingValue(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
		want string
	}{
		{"no colon", "justausername", "username:password"},
		{"empty username", ":secret", "1-255 bytes"},
		{"username over 255", strings.Repeat("u", 256) + ":secret", "1-255 bytes"},
		{"password over 255", "alice:" + strings.Repeat("p", 256), "0-255 bytes"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseAccount(tc.raw)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
			// The rejected value is a credential: boot errors must not quote
			// it, the same discipline as route-line parsing.
			if strings.Contains(err.Error(), tc.raw) {
				t.Fatalf("error leaked the account value: %v", err)
			}
		})
	}
}

func TestLoadBootstrapAccount(t *testing.T) {
	t.Run("unset keeps no-auth default", func(t *testing.T) {
		cfg, err := LoadBootstrap()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Account != nil {
			t.Fatalf("account = %+v, want nil", cfg.Account)
		}
	})
	t.Run("empty is the same as unset", func(t *testing.T) {
		t.Setenv("RPGW_ACCOUNT", "")
		cfg, err := LoadBootstrap()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Account != nil {
			t.Fatalf("account = %+v, want nil", cfg.Account)
		}
	})
	t.Run("valid value parses", func(t *testing.T) {
		t.Setenv("RPGW_ACCOUNT", "alice:secret")
		cfg, err := LoadBootstrap()
		if err != nil {
			t.Fatal(err)
		}
		if cfg.Account == nil || string(cfg.Account.Username) != "alice" || string(cfg.Account.Password) != "secret" {
			t.Fatalf("account = %+v, want alice/secret", cfg.Account)
		}
	})
	t.Run("malformed value fails startup", func(t *testing.T) {
		t.Setenv("RPGW_ACCOUNT", "leaked-secret-value-without-colon")
		_, err := LoadBootstrap()
		if err == nil || !strings.Contains(err.Error(), "RPGW_ACCOUNT") {
			t.Fatalf("error = %v, want RPGW_ACCOUNT rejection", err)
		}
		// The rejected credential must not be quoted in the boot error.
		if strings.Contains(err.Error(), "leaked-secret-value") {
			t.Fatalf("error leaked the account value: %v", err)
		}
	})
}
