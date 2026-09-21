package config

import (
	"strconv"
	"strings"
	"testing"
)

// balancePrologue carries one route per family so the balance block is
// meaningful; the block itself is appended per case.
const balancePrologue = `
log-level: info
max-retries: 3
cooldown:
  base: 2s
  max: 1m
dial-timeout: 7s
proxies:
  auto:
    - proxy: v4.example:1080
      kind: v4
    - proxy: v6.example:1080
      kind: v6
`

func TestLoadRuntimeBalanceShares(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want KindBalance
	}{
		{"absent block stays disabled", "", KindBalance{}},
		{"both shares", "balance:\n  v4: 7\n  v6: 3\n", KindBalance{V4: 7, V6: 3}},
		{"v4 only, v6 standby", "balance:\n  v4: 5\n", KindBalance{V4: 5}},
		{"v6 only, v4 standby", "balance:\n  v6: 2\n", KindBalance{V6: 2}},
		{"equal shares", "balance:\n  v4: 1\n  v6: 1\n", KindBalance{V4: 1, V6: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg, err := LoadRuntime(writeRuntimeConfig(t, balancePrologue+tc.yaml))
			if err != nil {
				t.Fatalf("LoadRuntime() error = %v", err)
			}
			if cfg.Balance != tc.want {
				t.Fatalf("balance = %+v, want %+v", cfg.Balance, tc.want)
			}
		})
	}
}

func TestLoadRuntimeAcceptsBalanceShareBounds(t *testing.T) {
	for _, share := range []int{1, MaxBalanceShare} {
		content := balancePrologue + "balance:\n  v4: " + strconv.Itoa(share) + "\n  v6: " + strconv.Itoa(share) + "\n"
		cfg, err := LoadRuntime(writeRuntimeConfig(t, content))
		if err != nil {
			t.Fatalf("share %d: LoadRuntime() error = %v", share, err)
		}
		if cfg.Balance.V4 != share || cfg.Balance.V6 != share {
			t.Fatalf("share %d parsed as %+v", share, cfg.Balance)
		}
	}
}

func TestLoadRuntimeRejectsInvalidBalanceShares(t *testing.T) {
	cases := map[string]string{
		"zero":       "balance:\n  v4: 0\n",
		"negative":   "balance:\n  v6: -3\n",
		"fractional": "balance:\n  v4: 2.5\n",
		"string":     "balance:\n  v6: \"7\"\n",
		"word":       "balance:\n  v4: most\n",
		"over max":   "balance:\n  v6: 1001\n",
	}
	for name, yaml := range cases {
		_, err := LoadRuntime(writeRuntimeConfig(t, balancePrologue+yaml))
		if err == nil {
			t.Fatalf("%s: LoadRuntime() accepted invalid balance block %q", name, yaml)
		}
		if !strings.Contains(err.Error(), "balance") {
			t.Fatalf("%s: error %v does not name the balance key", name, err)
		}
	}
}
