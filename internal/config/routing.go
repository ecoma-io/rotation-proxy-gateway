package config

import (
	"errors"
	"fmt"

	"rotation-proxy-gateway/internal/routing"
)

// routingFileConfig is the optional `routing` runtime block. A nil pointer
// means the block is absent and the gateway keeps the historical behavior:
// every listener selects from the whole shared pool. A present block — even
// an empty one — switches the pool to routed selection, so unmatched targets
// resolve to the default set or to no route at all, never back to the whole
// pool.
type routingFileConfig struct {
	Rules         []routingRuleFileConfig `mapstructure:"rules"`
	DefaultRoutes []string                `mapstructure:"default-routes"`
}

type routingRuleFileConfig struct {
	Match  routingMatchFileConfig `mapstructure:"match"`
	Routes []string               `mapstructure:"routes"`
}

type routingMatchFileConfig struct {
	Domains []string `mapstructure:"domains"`
}

// maxRouteIDLength bounds the operator-facing route id. It is generous — ids
// are short logical names — but finite so a pasted blob cannot become an
// unbounded log and /status field.
const maxRouteIDLength = 128

// validateRouteID checks the grammar of one operator-facing route id:
// 1-128 characters of letters, digits, hyphens, and underscores. The id is a
// routing label that appears in configuration, errors, logs, and /status, so
// the grammar doubles as the log-safety guarantee — no whitespace, no
// control characters, nothing that reads as another field.
func validateRouteID(id string) error {
	if id == "" {
		return errors.New("route id must not be empty")
	}
	if len(id) > maxRouteIDLength {
		return fmt.Errorf("route id must be at most %d characters", maxRouteIDLength)
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-' || r == '_':
		default:
			return fmt.Errorf("route id %q must contain only letters, digits, hyphens, and underscores", id)
		}
	}
	return nil
}

// parseRoutingSettings checks route-id uniqueness and compiles the routing
// policy. routes carries the full serving list with per-entry labels
// ("proxies.auto[2]") so one pass can report exactly which entry is wrong.
// Every id arrived validated by applyRouteID; only the cross-origin
// uniqueness check belongs here.
//
// A nil raw keeps RuntimeConfig.Routing nil — the unrestricted policy — but
// the uniqueness check still runs: a configured id must be unique whenever it
// appears, because uniqueness is what makes routing rules deterministic the
// day they are added.
//
// With a routing block present the contract tightens: every serving route
// must carry an id (an unnamed route could never appear in a rule or in the
// default set, so letting it serve would silently narrow the pool behind the
// operator's back), every referenced id must exist, and the pattern grammar
// is routing.Compile's. Any failure rejects the whole configuration; the
// reload path keeps the last-known-good generation serving.
func parseRoutingSettings(raw *routingFileConfig, routes []labeledRoute) (*routing.Router, error) {
	ids := make(map[string]struct{}, len(routes))
	for _, labeled := range routes {
		if labeled.spec.ID == "" {
			continue
		}
		if _, dup := ids[labeled.spec.ID]; dup {
			return nil, fmt.Errorf("%s: route id %q is already used by another route", labeled.where, labeled.spec.ID)
		}
		ids[labeled.spec.ID] = struct{}{}
	}
	if raw == nil {
		return nil, nil
	}
	for _, labeled := range routes {
		if labeled.spec.ID == "" {
			return nil, fmt.Errorf("%s: routing requires every serving route to carry an id", labeled.where)
		}
	}
	spec := routing.Spec{
		Rules: make([]routing.RuleSpec, 0, len(raw.Rules)),
	}
	for i, rule := range raw.Rules {
		if len(rule.Match.Domains) == 0 {
			return nil, fmt.Errorf("routing.rules[%d] matches no domains: a rule must list at least one domain pattern", i)
		}
		if len(rule.Routes) == 0 {
			return nil, fmt.Errorf("routing.rules[%d] selects no routes: a rule must list at least one route id", i)
		}
		for _, id := range rule.Routes {
			if _, ok := ids[id]; !ok {
				return nil, fmt.Errorf("routing.rules[%d] references route id %q, which no configured route carries", i, id)
			}
		}
		spec.Rules = append(spec.Rules, routing.RuleSpec{Domains: rule.Match.Domains, Routes: rule.Routes})
	}
	// default-routes is absent when unset. An explicit empty list is the
	// operator spelling "unmatched targets serve from nothing" — legal intent,
	// but spelled as an empty candidate list it is rejected alongside every
	// other empty candidate set: omit the key for the same, documented result.
	if raw.DefaultRoutes != nil {
		if len(raw.DefaultRoutes) == 0 {
			return nil, errors.New("routing.default-routes must not be empty: omit the key when unmatched targets should have no default route")
		}
		for _, id := range raw.DefaultRoutes {
			if _, ok := ids[id]; !ok {
				return nil, fmt.Errorf("routing.default-routes references route id %q, which no configured route carries", id)
			}
		}
		spec.DefaultRoutes = raw.DefaultRoutes
	}
	return routing.Compile(spec)
}
