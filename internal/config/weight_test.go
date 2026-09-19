package config

import (
	"strconv"
	"strings"
	"testing"
)

const weightPrologue = `
log-level: info
max-retries: 3
cooldown:
  base: 2s
  max: 1m
dial-timeout: 7s
proxies:
`

func TestLoadRuntimeRouteWeights(t *testing.T) {
	content := weightPrologue + `
  auto:
    - proxy: socks5://v4.example:1080
      kind: v4
    - proxy: socks5://v4b.example:1080
      kind: v4
      weight: 7
  manual:
    - proxy: socks5://m.example:1080
      kind: v6
      weight: 3
      rotate-interval: 90s
      api:
        url: https://provider.example/rotate
`
	cfg, err := LoadRuntime(writeRuntimeConfig(t, content))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if len(cfg.Routes) != 2 || len(cfg.ManualRoutes) != 1 {
		t.Fatalf("routes = %+v manual = %+v", cfg.Routes, cfg.ManualRoutes)
	}
	if got := cfg.Routes[0].Weight; got != DefaultRouteWeight {
		t.Fatalf("absent weight = %d, want default %d", got, DefaultRouteWeight)
	}
	if got := cfg.Routes[1].Weight; got != 7 {
		t.Fatalf("auto weight = %d, want 7", got)
	}
	if got := cfg.ManualRoutes[0].Weight; got != 3 {
		t.Fatalf("manual weight = %d, want 3", got)
	}
}

func TestLoadRuntimeAcceptsWeightBounds(t *testing.T) {
	for _, w := range []int{1, DefaultRouteWeight, MaxRouteWeight} {
		content := weightPrologue + `
  auto:
    - proxy: socks5://v4.example:1080
      kind: v4
      weight: ` + strconv.Itoa(w) + `
`
		cfg, err := LoadRuntime(writeRuntimeConfig(t, content))
		if err != nil {
			t.Fatalf("weight %d: LoadRuntime() error = %v", w, err)
		}
		if cfg.Routes[0].Weight != w {
			t.Fatalf("weight %d parsed as %d", w, cfg.Routes[0].Weight)
		}
	}
}

func TestLoadRuntimeRejectsInvalidRouteWeights(t *testing.T) {
	cases := map[string]string{
		"zero":       "weight: 0",
		"negative":   "weight: -2",
		"fractional": "weight: 2.5",
		"string":     `weight: "3"`,
		"word":       "weight: heavy",
		"over max":   "weight: 1001",
	}
	for name, line := range cases {
		content := weightPrologue + `
  auto:
    - proxy: socks5://v4.example:1080
      kind: v4
      ` + line + `
`
		_, err := LoadRuntime(writeRuntimeConfig(t, content))
		if err == nil {
			t.Fatalf("%s: LoadRuntime() accepted invalid %s", name, line)
		}
		if !strings.Contains(err.Error(), "weight") {
			t.Fatalf("%s: error %v does not name weight", name, err)
		}
	}
}
