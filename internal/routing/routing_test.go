package routing

import (
	"fmt"
	"testing"

	"rotation-proxy-gateway/internal/socksdial"
)

func domainTarget(host string) socksdial.Target {
	return socksdial.Target{Host: host, Port: 443, Type: socksdial.AddrDomain}
}

func ipTargets() []socksdial.Target {
	return []socksdial.Target{
		{Host: "23.3.14.2", Port: 443, Type: socksdial.AddrIPv4},
		{Host: "2001:db8::1", Port: 443, Type: socksdial.AddrIPv6},
	}
}

// mustCompile is the test helper for a router the config loader would have
// validated already.
func mustCompile(t *testing.T, spec Spec) *Router {
	t.Helper()
	r, err := Compile(spec)
	if err != nil {
		t.Fatalf("Compile(%+v) error = %v", spec, err)
	}
	return r
}

// matchID resolves target and returns the single route id of the candidate
// set, failing when the match is unrestricted (nil), empty, or carries any
// other membership.
func matchID(t *testing.T, r *Router, target socksdial.Target, want string) {
	t.Helper()
	set := r.Match(target)
	if set == nil {
		t.Fatalf("Match(%+v) = unrestricted, want candidate set containing %q", target, want)
	}
	if !set.Allows(want) || set.Size() != 1 {
		t.Fatalf("Match(%+v) allowed = %v (size %d), want exactly {%q}", target, set.Allows(want), set.Size(), want)
	}
}

func TestMatchExactDomain(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{{Domains: []string{"api.openai.com"}, Routes: []string{"openai-a"}}}})
	matchID(t, r, domainTarget("api.openai.com"), "openai-a")
}

func TestMatchWildcard(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a"}}}})
	matchID(t, r, domainTarget("api.openai.com"), "openai-a")
	matchID(t, r, domainTarget("a.b.openai.com"), "openai-a")
}

// The wildcard is a label boundary, not a string suffix: the bare registered
// domain and any lookalike ending in the same letters must not match.
func TestMatchWildcardLabelBoundary(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a"}}}})
	for _, host := range []string{"openai.com", "evilopenai.com", "openai.com.", "fooevilopenai.com"} {
		set := r.Match(domainTarget(host))
		if set == nil || set.Allows("openai-a") {
			t.Fatalf("Match(%q) allowed openai-a, want the wildcard to stop at the label boundary", host)
		}
	}
}

// The extra label a wildcard demands must be non-empty: a client-spelled
// empty label ("a..openai.com", "..openai.com") is a malformed name, so it
// falls through to the default set like any other non-match instead of
// slipping through the dotted suffix.
func TestMatchWildcardRejectsEmptyExtraLabel(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{{Domains: []string{"*.openai.com"}, Routes: []string{"openai-a"}}}})
	for _, host := range []string{"a..openai.com", "..openai.com", "evil..openai.com", ".openai.com"} {
		set := r.Match(domainTarget(host))
		if set == nil || set.Allows("openai-a") {
			t.Fatalf("Match(%q) allowed openai-a, want the empty extra label to fall through", host)
		}
	}
}

func TestMatchCaseNormalization(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{
		{Domains: []string{"API.OpenAI.com"}, Routes: []string{"exact"}},
		{Domains: []string{"*.KILO.AI"}, Routes: []string{"wild"}},
	}})
	matchID(t, r, domainTarget("api.openai.com"), "exact")
	matchID(t, r, domainTarget("API.OPENAI.COM"), "exact")
	matchID(t, r, domainTarget("Api.Kilo.AI"), "wild")
}

func TestMatchTrailingDotNormalization(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{{Domains: []string{"api.openai.com"}, Routes: []string{"openai-a"}}}})
	matchID(t, r, domainTarget("api.openai.com."), "openai-a")
}

func TestMatchFirstRuleWins(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{
		{Domains: []string{"api.openai.com", "*.openai.com"}, Routes: []string{"first"}},
		{Domains: []string{"*.openai.com"}, Routes: []string{"second"}},
	}})
	matchID(t, r, domainTarget("api.openai.com"), "first")
	matchID(t, r, domainTarget("other.openai.com"), "first")
}

// A wildcard listed before an exact pattern must still win: precedence is
// rule order, never "exact beats wildcard".
func TestMatchWildcardRulePrecedesExactRule(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{
		{Domains: []string{"*.openai.com"}, Routes: []string{"wild-first"}},
		{Domains: []string{"api.openai.com"}, Routes: []string{"exact-second"}},
	}})
	matchID(t, r, domainTarget("api.openai.com"), "wild-first")
}

func TestMatchDefaults(t *testing.T) {
	r := mustCompile(t, Spec{
		Rules:         []RuleSpec{{Domains: []string{"api.openai.com"}, Routes: []string{"openai-a"}}},
		DefaultRoutes: []string{"openai-a", "kilo-a"},
	})
	set := r.Match(domainTarget("unlisted.example.com"))
	if set == nil || !set.Allows("openai-a") || !set.Allows("kilo-a") || set.Size() != 2 {
		t.Fatalf("unmatched target did not resolve to the default set: %+v", set)
	}
}

// An IP target carries no hostname, so it can never match a rule and always
// resolves to the default set — the gateway never reverse-resolves.
func TestMatchIPTargetNeverMatchesRules(t *testing.T) {
	r := mustCompile(t, Spec{
		Rules: []RuleSpec{
			{Domains: []string{"api.openai.com", "*.openai.com"}, Routes: []string{"openai-a"}},
		},
		DefaultRoutes: []string{"kilo-a"},
	})
	for _, target := range ipTargets() {
		matchID(t, r, target, "kilo-a")
	}
}

// Unmatched target with no default routes: the empty set is the explicit
// "no candidate" outcome the serving path renders as the ordinary no-route
// SOCKS failure — never a silent fall-through to every route.
func TestMatchUnmatchedWithoutDefaultsIsEmptySet(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{{Domains: []string{"api.openai.com"}, Routes: []string{"openai-a"}}}})
	set := r.Match(domainTarget("unlisted.example.com"))
	if set == nil || set.Size() != 0 || set.Allows("openai-a") {
		t.Fatalf("unmatched target without defaults = %+v, want an empty (fail-closed) set", set)
	}
}

// Absent routing block: the nil router is the unrestricted policy, and its
// match result is a nil set — the caller's signal to keep the historical
// global-pool behavior.
func TestNilRouterIsUnrestricted(t *testing.T) {
	var r *Router
	if set := r.Match(domainTarget("api.openai.com")); set != nil {
		t.Fatalf("nil router matched = %+v, want nil (unrestricted)", set)
	}
	if set := r.Match(ipTargets()[0]); set != nil {
		t.Fatalf("nil router matched IP target = %+v, want nil (unrestricted)", set)
	}
}

// Allows on a nil set must fail closed: a caller that skips the unrestricted
// check can only ever narrow, never leak routes into a scope they do not
// belong to.
func TestNilSetAllowsFailsClosed(t *testing.T) {
	var s *Set
	if s.Allows("openai-a") || s.Size() != 0 {
		t.Fatal("nil set answered Allows=true or Size!=0; must fail closed")
	}
}

func TestSetDropsDuplicateRouteIDs(t *testing.T) {
	set := newSet([]string{"a", "b", "a"})
	if set.Size() != 2 || !set.Allows("a") || !set.Allows("b") {
		t.Fatalf("set = size %d, want deduplicated {a b}", set.Size())
	}
}

func TestCompileNormalizesTrailingDotPatterns(t *testing.T) {
	r := mustCompile(t, Spec{Rules: []RuleSpec{{Domains: []string{"api.openai.com.", "*.kilo.ai."}, Routes: []string{"a"}}}})
	matchID(t, r, domainTarget("api.openai.com"), "a")
	matchID(t, r, domainTarget("x.kilo.ai"), "a")
}

func TestCompileRejects(t *testing.T) {
	valid := func(spec Spec) Spec { return spec }
	for _, tc := range []struct {
		name string
		spec Spec
	}{
		{"rule without domains", valid(Spec{Rules: []RuleSpec{{Routes: []string{"a"}}}})},
		{"rule without routes", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a.test"}}}})},
		{"bare star", valid(Spec{Rules: []RuleSpec{{Domains: []string{"*"}, Routes: []string{"a"}}}})},
		{"bare star-dot", valid(Spec{Rules: []RuleSpec{{Domains: []string{"*."}, Routes: []string{"a"}}}})},
		{"mid-pattern star", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a.*.example.com"}, Routes: []string{"a"}}}})},
		{"suffix star", valid(Spec{Rules: []RuleSpec{{Domains: []string{"example.com/*"}, Routes: []string{"a"}}}})},
		{"lookalike suffix star", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a*.example.com"}, Routes: []string{"a"}}}})},
		{"empty label", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a..com"}, Routes: []string{"a"}}}})},
		{"leading dot", valid(Spec{Rules: []RuleSpec{{Domains: []string{".example.com"}, Routes: []string{"a"}}}})},
		{"label too long", valid(Spec{Rules: []RuleSpec{{Domains: []string{string(make([]byte, 64)) + ".com"}, Routes: []string{"a"}}}})},
		{"underscores are not hostname bytes", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a_b.example.com"}, Routes: []string{"a"}}}})},
		{"padded pattern", valid(Spec{Rules: []RuleSpec{{Domains: []string{" a.example.com"}, Routes: []string{"a"}}}})},
		{"duplicate domain in rule", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a.test", "a.test"}, Routes: []string{"a"}}}})},
		{"duplicate domain after normalization", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a.test", "A.TEST."}, Routes: []string{"a"}}}})},
		{"duplicate route in rule", valid(Spec{Rules: []RuleSpec{{Domains: []string{"a.test"}, Routes: []string{"a", "a"}}}})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Compile(tc.spec); err == nil {
				t.Fatalf("Compile(%+v) accepted an invalid spec", tc.spec)
			}
		})
	}
}

// A zero spec compiles to the explicit kill switch: every target — domain or
// IP — resolves to the empty default set. That is the configured intent, not
// a fallback to the whole pool.
func TestCompileEmptySpecIsTotalRestriction(t *testing.T) {
	r := mustCompile(t, Spec{})
	for _, target := range append([]socksdial.Target{domainTarget("api.openai.com")}, ipTargets()...) {
		set := r.Match(target)
		if set == nil || set.Size() != 0 {
			t.Fatalf("Match(%+v) = %+v, want the empty default set", target, set)
		}
	}
}

func BenchmarkRouterMatch(b *testing.B) {
	rules := make([]RuleSpec, 0, 50)
	for i := range 25 {
		rules = append(rules,
			RuleSpec{Domains: []string{fmt.Sprintf("api%d.example.com", i)}, Routes: []string{fmt.Sprintf("r%d", i)}},
			RuleSpec{Domains: []string{fmt.Sprintf("*.p%d.example.com", i)}, Routes: []string{fmt.Sprintf("w%d", i)}},
		)
	}
	r, err := Compile(Spec{Rules: rules, DefaultRoutes: []string{"default"}})
	if err != nil {
		b.Fatalf("Compile: %v", err)
	}
	cases := []struct {
		name   string
		target socksdial.Target
	}{
		{"exact-hit", domainTarget("api10.example.com")},
		{"wildcard-hit", domainTarget("deep.sub.p7.example.com")},
		{"miss-to-default", domainTarget("unlisted.example.org")},
		{"ip-target", ipTargets()[0]},
	}
	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if set := r.Match(tc.target); set == nil {
					b.Fatal("restricted router returned an unrestricted match")
				}
			}
		})
	}
}
