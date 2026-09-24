package config

import (
	"strings"
	"testing"

	"rotation-proxy-gateway/internal/socksdial"
)

// routingBaseConfig names every route; the routing-block tests splice their
// own `routing:` block under it.
const routingBaseConfig = `
log-level: info
max-retries: 3
cooldown:
  base: 2s
  max: 1m
dial-timeout: 5s
proxies:
  auto:
    - id: openai-a
      proxy: alice:secret@v4.example:1080
      kind: v4
    - id: openai-b
      proxy: bob:secret@v4b.example:1080
      kind: v4
    - id: kilo-a
      proxy: carol:secret@v6.example:1080
      kind: v6
`

func routingConfig(block string) string {
	return routingBaseConfig + block
}

func domainRouteTarget(host string) socksdial.Target {
	return socksdial.Target{Host: host, Port: 443, Type: socksdial.AddrDomain}
}

// TestLoadRuntimeWithoutRoutingKeepsUnrestricted pins the backward-compat
// spine: no `routing` block means no router and the pool serves every route
// for every target exactly as before the layer existed; configured ids still
// parse through onto their routes.
func TestLoadRuntimeWithoutRoutingKeepsUnrestricted(t *testing.T) {
	cfg, err := LoadRuntime(writeRuntimeConfig(t, routingBaseConfig))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if cfg.Routing != nil {
		t.Fatalf("Routing = %+v, want nil without a routing block", cfg.Routing)
	}
	ids := make([]string, 0, len(cfg.AllRoutes()))
	for _, route := range cfg.AllRoutes() {
		ids = append(ids, route.ID)
	}
	if strings.Join(ids, ",") != "openai-a,openai-b,kilo-a" {
		t.Fatalf("route ids = %v, want openai-a,openai-b,kilo-a", ids)
	}
}

// A configured id is validated and must be unique even without a routing
// block: uniqueness today is what keeps adding rules tomorrow deterministic.
func TestLoadRuntimeValidatesRouteIDsWithoutRouting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		idLine  string
		wantErr string
	}{
		{"invalid charset", "id: openai a", "must contain only letters, digits, hyphens, and underscores"},
		{"empty id", "id: \"\"", "must not be empty"},
		{"oversized id", "id: " + strings.Repeat("a", 129), "must be at most 128 characters"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := strings.Replace(routingBaseConfig, "    - id: openai-a", "    - "+tc.idLine, 1)
			_, err := LoadRuntime(writeRuntimeConfig(t, yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("LoadRuntime() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadRuntimeCompilesRouting(t *testing.T) {
	cfg, err := LoadRuntime(writeRuntimeConfig(t, routingConfig(`
routing:
  rules:
    - match:
        domains:
          - api.openai.com
          - "*.openai.com"
      routes:
        - openai-a
        - openai-b
  default-routes:
    - kilo-a
`)))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if cfg.Routing == nil {
		t.Fatal("Routing = nil, want a compiled router")
	}
	ids := make([]string, 0, len(cfg.AllRoutes()))
	for _, route := range cfg.AllRoutes() {
		ids = append(ids, route.ID)
	}
	if strings.Join(ids, ",") != "openai-a,openai-b,kilo-a" {
		t.Fatalf("route ids = %v", ids)
	}

	openai := cfg.Routing.Match(domainRouteTarget("API.OpenAI.com."))
	if openai == nil || !openai.Allows("openai-a") || !openai.Allows("openai-b") || openai.Allows("kilo-a") {
		t.Fatalf("api.openai.com candidates = %+v, want {openai-a openai-b}", openai)
	}
	wild := cfg.Routing.Match(domainRouteTarget("api2.openai.com"))
	if wild == nil || wild.Size() != 2 || !wild.Allows("openai-b") {
		t.Fatalf("wildcard candidates = %+v", wild)
	}
	def := cfg.Routing.Match(domainRouteTarget("other.example.com"))
	if def == nil || def.Size() != 1 || !def.Allows("kilo-a") {
		t.Fatalf("unmatched candidates = %+v, want the default set {kilo-a}", def)
	}
	ip := cfg.Routing.Match(socksdial.Target{Host: "23.3.14.2", Port: 443, Type: socksdial.AddrIPv4})
	if ip == nil || ip.Size() != 1 || !ip.Allows("kilo-a") {
		t.Fatalf("IP-target candidates = %+v, want the default set", ip)
	}
}

func TestLoadRuntimeCompilesRoutingWithManualRoute(t *testing.T) {
	// kilo-b is distinct from the base config's auto kilo-a: ids share one
	// namespace across auto and manual routes.
	manual := `
  manual:
    - id: kilo-b
      proxy: carol:manual-secret@manual.example:1080
      kind: v6
      rotate-interval: 90s
      api:
        url: https://provider.example/rotate
`
	cfg, err := LoadRuntime(writeRuntimeConfig(t, routingBaseConfig+manual+`
routing:
  rules:
    - match:
        domains: ["*.kilo.ai"]
      routes: [kilo-b]
  default-routes: [openai-a]
`))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	set := cfg.Routing.Match(domainRouteTarget("api.kilo.ai"))
	if set == nil || set.Size() != 1 || !set.Allows("kilo-b") {
		t.Fatalf("api.kilo.ai candidates = %+v, want {kilo-b}", set)
	}
}

func TestLoadRuntimeRejectsRouting(t *testing.T) {
	for _, tc := range []struct {
		name    string
		block   string
		wantErr string
	}{
		{
			name: "rule references unknown route id",
			block: `
routing:
  rules:
    - match:
        domains: [api.openai.com]
      routes: [openai-a, kilo-b]
  default-routes: [kilo-a]`,
			wantErr: "references route id \"kilo-b\"",
		},
		{
			name: "default-routes references unknown route id",
			block: `
routing:
  rules:
    - match:
        domains: [api.openai.com]
      routes: [openai-a]
  default-routes: [missing-a]`,
			wantErr: "default-routes references route id \"missing-a\"",
		},
		{
			name: "empty rules list with no defaults is the kill switch, but a rule with an empty routes list is not",
			block: `
routing:
  rules:
    - match:
        domains: [api.openai.com]
      routes: []`,
			wantErr: "selects no routes",
		},
		{
			name: "rule with an empty domains list",
			block: `
routing:
  rules:
    - match:
        domains: []
      routes: [openai-a]`,
			wantErr: "matches no domains",
		},
		{
			name: "rule without a match block",
			block: `
routing:
  rules:
    - routes: [openai-a]`,
			wantErr: "matches no domains",
		},
		{
			name: "explicit empty default-routes",
			block: `
routing:
  rules:
    - match:
        domains: [api.openai.com]
      routes: [openai-a]
  default-routes: []`,
			wantErr: "default-routes must not be empty",
		},
		{
			name: "star inside the pattern",
			block: `
routing:
  rules:
    - match:
        domains: ["*.*.openai.com"]
      routes: [openai-a]`,
			wantErr: "invalid domain pattern",
		},
		{
			name: "invalid hostname pattern",
			block: `
routing:
  rules:
    - match:
        domains: [api..openai.com]
      routes: [openai-a]`,
			wantErr: "invalid domain pattern",
		},
		{
			name:    "duplicate route id across auto and manual",
			block:   "",
			wantErr: "already used by another route",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			yaml := routingConfig(tc.block)
			if tc.name == "duplicate route id across auto and manual" {
				yaml = strings.Replace(yaml, "id: kilo-a", "id: openai-a", 1) + `
routing:
  rules:
    - match:
        domains: [api.openai.com]
      routes: [openai-a]`
			}
			_, err := LoadRuntime(writeRuntimeConfig(t, yaml))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("LoadRuntime() error = %v, want %q", err, tc.wantErr)
			}
		})
	}
}

// A routing block demands full naming: a route without an id could never
// appear in a rule or the default set, so admitting it would silently narrow
// the pool behind the operator's back.
func TestLoadRuntimeRoutingRequiresEveryRouteID(t *testing.T) {
	yaml := `
log-level: info
max-retries: 3
cooldown:
  base: 2s
  max: 1m
dial-timeout: 5s
proxies:
  auto:
    - id: openai-a
      proxy: alice:secret@v4.example:1080
      kind: v4
    - proxy: bob:secret@v4b.example:1080
      kind: v4
routing:
  rules:
    - match:
        domains: [api.openai.com]
      routes: [openai-a]
`
	_, err := LoadRuntime(writeRuntimeConfig(t, yaml))
	if err == nil || !strings.Contains(err.Error(), "proxies.auto[1]: routing requires every serving route to carry an id") {
		t.Fatalf("LoadRuntime() error = %v, want the unnamed-route rejection", err)
	}
}

// Strict decoding reaches into the routing block: unknown keys fail loudly
// instead of being ignored.
func TestLoadRuntimeRejectsUnknownRoutingFields(t *testing.T) {
	for _, tc := range []struct{ name, block string }{
		{"unknown key on routing", "\nrouting:\n  default: [openai-a]\n"},
		{"unknown key on rule", "\nrouting:\n  rules:\n    - match:\n        domains: [api.openai.com]\n      weight: 3\n      routes: [openai-a]\n"},
		{"unknown key on match", "\nrouting:\n  rules:\n    - match:\n        domains: [api.openai.com]\n        ips: [1.2.3.4]\n      routes: [openai-a]\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadRuntime(writeRuntimeConfig(t, routingConfig(tc.block)))
			if err == nil {
				t.Fatalf("LoadRuntime() accepted %s", tc.name)
			}
		})
	}
}

// A null `routing:` key means the block was not written; the config stays
// unrestricted rather than becoming the empty kill switch.
func TestLoadRuntimeNullRoutingBlockIsAbsent(t *testing.T) {
	cfg, err := LoadRuntime(writeRuntimeConfig(t, routingConfig("routing:\n")))
	if err != nil {
		t.Fatalf("LoadRuntime() error = %v", err)
	}
	if cfg.Routing != nil {
		t.Fatalf("Routing = %+v, want nil for a null routing key", cfg.Routing)
	}
}
