package socksdial

import (
	"strings"
	"testing"
)

// The CONNECT encoder carries the caller's address type verbatim: these
// vectors pin the exact wire bytes for all three ATYPs and pin that the type
// is never re-derived from the host string.
func TestSocksConnectRequestFraming(t *testing.T) {
	cases := []struct {
		name   string
		target Target
		want   []byte
	}{
		{"ipv4", Target{Host: "127.0.0.1", Port: 80, Type: AddrIPv4}, []byte{0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, 0, 80}},
		{"ipv6", Target{Host: "::1", Port: 80, Type: AddrIPv6}, append([]byte{0x05, 0x01, 0x00, 0x04}, append(make([]byte, 15), 1, 0, 80)...)},
		{"domain", Target{Host: "example.com", Port: 80, Type: AddrDomain}, append([]byte{0x05, 0x01, 0x00, 0x03, byte(len("example.com"))}, append([]byte("example.com"), 0, 80)...)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := socksConnectRequest(tc.target)
			if err != nil {
				t.Fatalf("socksConnectRequest: %v", err)
			}
			if string(got) != string(tc.want) {
				t.Fatalf("request = %v, want %v", got, tc.want)
			}
		})
	}

	t.Run("oversized hostname", func(t *testing.T) {
		_, err := socksConnectRequest(Target{Host: strings.Repeat("a", 256), Port: 80, Type: AddrDomain})
		if err == nil {
			t.Fatal("expected error for 256-byte hostname")
		}
	})
	t.Run("empty hostname", func(t *testing.T) {
		if _, err := socksConnectRequest(Target{Host: "", Port: 80, Type: AddrDomain}); err == nil {
			t.Fatal("expected error for empty hostname")
		}
	})
	t.Run("zero port", func(t *testing.T) {
		if _, err := socksConnectRequest(Target{Host: "example.com", Port: 0, Type: AddrDomain}); err == nil {
			t.Fatal("expected error for zero port")
		}
	})
	t.Run("unsupported address type", func(t *testing.T) {
		if _, err := socksConnectRequest(Target{Host: "example.com", Port: 80, Type: 0x02}); err == nil {
			t.Fatal("expected error for unsupported address type")
		}
	})

	// The declared type wins; a host that cannot encode as it is a local
	// setup failure, never a silent switch to another address family.
	t.Run("domain host with ipv4 type fails locally", func(t *testing.T) {
		if _, err := socksConnectRequest(Target{Host: "example.com", Port: 80, Type: AddrIPv4}); err == nil {
			t.Fatal("expected error for a hostname declared as IPv4")
		}
	})
	t.Run("domain host with ipv6 type fails locally", func(t *testing.T) {
		if _, err := socksConnectRequest(Target{Host: "example.com", Port: 80, Type: AddrIPv6}); err == nil {
			t.Fatal("expected error for a hostname declared as IPv6")
		}
	})
	t.Run("ipv4 host declared as ipv6 encodes in sixteen bytes", func(t *testing.T) {
		got, err := socksConnectRequest(Target{Host: "1.2.3.4", Port: 80, Type: AddrIPv6})
		if err != nil {
			t.Fatalf("socksConnectRequest: %v", err)
		}
		want := append([]byte{0x05, 0x01, 0x00, 0x04}, make([]byte, 10)...)
		want = append(want, 0xff, 0xff, 1, 2, 3, 4, 0, 80)
		if string(got) != string(want) {
			t.Fatalf("request = %v, want %v", got, want)
		}
	})
}

// TargetFromAddr exists for gateway-originated dials; its classification must
// agree with the wire constants and reject shapes no CONNECT can carry.
func TestTargetFromAddrClassification(t *testing.T) {
	cases := []struct {
		name    string
		addr    string
		want    Target
		wantErr bool
	}{
		{"ipv4", "1.2.3.4:443", Target{Host: "1.2.3.4", Port: 443, Type: AddrIPv4}, false},
		{"ipv6", "[2001:db8::1]:443", Target{Host: "2001:db8::1", Port: 443, Type: AddrIPv6}, false},
		{"domain", "example.test:443", Target{Host: "example.test", Port: 443, Type: AddrDomain}, false},
		{"missing port", "example.test", Target{}, true},
		{"bad port", "example.test:notaport", Target{}, true},
		{"zero port", "example.test:0", Target{}, true},
		{"out of range port", "example.test:70000", Target{}, true},
		{"empty", "", Target{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := TargetFromAddr(tc.addr)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("TargetFromAddr(%q) = %+v, want error", tc.addr, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("TargetFromAddr(%q): %v", tc.addr, err)
			}
			if got != tc.want {
				t.Fatalf("TargetFromAddr(%q) = %+v, want %+v", tc.addr, got, tc.want)
			}
			if gotType := got.Type; gotType != AddrIPv4 && gotType != AddrIPv6 && gotType != AddrDomain {
				t.Fatalf("type %d is not a wire address type", gotType)
			}
		})
	}
}

// Addr is the pool-state and log identity: host:port, IPv6 bracketed.
func TestTargetAddr(t *testing.T) {
	cases := []struct {
		target Target
		want   string
	}{
		{Target{Host: "1.2.3.4", Port: 443, Type: AddrIPv4}, "1.2.3.4:443"},
		{Target{Host: "example.test", Port: 443, Type: AddrDomain}, "example.test:443"},
		{Target{Host: "2001:db8::1", Port: 443, Type: AddrIPv6}, "[2001:db8::1]:443"},
	}
	for _, tc := range cases {
		if got := tc.target.Addr(); got != tc.want {
			t.Fatalf("Addr() = %q, want %q", got, tc.want)
		}
	}
}
