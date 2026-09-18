package socksdial

import (
	"strings"
	"testing"
)

func TestSocksConnectRequestFraming(t *testing.T) {
	cases := []struct {
		name string
		host string
		want []byte
	}{
		{"ipv4", "127.0.0.1", []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}},
		{"ipv6", "::1", append([]byte{0x05, 0x01, 0x00, 0x04}, append(make([]byte, 15), 1, 0, 80)...)},
		{"domain", "example.com", append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}, append([]byte("example.com"), 0, 80)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := socksConnectRequest(tc.host, 80)
			if err != nil {
				t.Fatalf("socksConnectRequest: %v", err)
			}
			if string(got) != string(tc.want) {
				t.Fatalf("request = %v, want %v", got, tc.want)
			}
		})
	}
	t.Run("oversized hostname", func(t *testing.T) {
		if _, err := socksConnectRequest(strings.Repeat("a", 256), 80); err == nil {
			t.Fatal("expected error for 256-byte hostname")
		}
		if _, err := socksConnectRequest("", 80); err == nil {
			t.Fatal("expected error for empty hostname")
		}
	})
}
