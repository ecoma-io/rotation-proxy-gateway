// Package routing compiles the optional routing policy and resolves one
// inbound CONNECT target to its candidate route set. It sits strictly before
// pool selection: a match narrows which routes the shared health-aware pool
// may consider for a target, and never selects one itself — availability,
// cooldown, auth block, rotation state, round-robin, and per-request exclusion
// all stay in the pool.
//
// The router is compiled once with the runtime configuration and published as
// part of the immutable runtime generation, so a routing change and the pool
// it scopes reach serving as one atomic unit. Matching is string-only and
// domain-scoped by construction: an IP target carries no hostname, so it can
// never match a rule and always falls to the default set. Nothing here reads
// or writes route health, resolves names, or looks at tunnel bytes.
package routing

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"rotation-proxy-gateway/internal/socksdial"
)

// Spec is the routing policy as configured, before compilation. Domains and
// route IDs are operator-facing strings; Compile validates the grammar and
// produces the immutable Router.
type Spec struct {
	Rules         []RuleSpec
	DefaultRoutes []string
}

// RuleSpec is one first-match-wins rule: a target whose hostname matches any
// listed pattern resolves to the rule's route set.
type RuleSpec struct {
	Domains []string
	Routes  []string
}

// Router is the immutable compiled routing policy. The zero usable value is
// produced only by Compile; a nil *Router is the unrestricted policy — every
// target resolves to no candidate set at all, which is exactly the historical
// no-routing-block behavior. Match is safe for concurrent use.
type Router struct {
	rules    []compiledRule
	defaults *Set
}

// compiledRule is one rule with its patterns normalized and its candidate set
// built once. exact holds whole hostnames; wilds holds ".suffix" forms matched
// with one HasSuffix — safe as a bare suffix test because every compared name
// has already passed the shared hostname grammar, so the leading dot can only
// land on a real label boundary.
type compiledRule struct {
	exact  map[string]struct{}
	wilds  []string
	routes *Set
}

// Configure renders the compiled policy back into the specification it was
// built from. It exists for one caller: writing a durable configuration
// document, where the value that gets stored must be the policy as configured
// rather than its compiled form.
//
// The distinction matters in two directions. An exact pattern and its
// wildcard form round-trip through their original spelling, because the
// compiler records a wildcard as a dotted suffix and un-compiling ".example.com"
// could only guess between "*.example.com" and a literal ".example.com" — so
// the wildcard marker is restored and the trailing-DNS-dot normalization is
// not. Candidate sets round-trip as sorted lists, since the compiled form
// deliberately drops duplicate and order information that a document has no
// need to preserve.
//
// The result is a specification, not a router: Compile must still run before it
// can serve, so nothing here bypasses validation.
func (r *Router) Configure() Spec {
	if r == nil {
		return Spec{}
	}
	spec := Spec{}
	if len(r.rules) > 0 {
		spec.Rules = make([]RuleSpec, 0, len(r.rules))
		for i := range r.rules {
			rule := &r.rules[i]
			rules := make([]RuleSpec, 1)
			rules[0].Routes = rule.routes.sorted()
			for host := range rule.exact {
				rules[0].Domains = append(rules[0].Domains, host)
			}
			for _, suffix := range rule.wilds {
				rules[0].Domains = append(rules[0].Domains, "*"+suffix)
			}
			sort.Strings(rules[0].Domains)
			spec.Rules = append(spec.Rules, rules[0])
		}
	}
	if r.defaults != nil {
		spec.DefaultRoutes = r.defaults.sorted()
	}
	return spec
}

// sorted renders a candidate set as a stable list. The compiled form holds a
// set, so iteration order is arbitrary; sorting is what makes a document
// round-trip byte-identically for the same policy.
func (s *Set) sorted() []string {
	if s == nil {
		return nil
	}
	out := make([]string, 0, len(s.ids))
	for id := range s.ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// Set is an immutable candidate route set — the outcome of one Match. A nil
// *Set means unrestricted: the caller must treat it as "no routing filter"
// and use its listener filter alone, which is what keeps the no-routing path
// allocation-free. A non-nil empty Set is a hard restriction: no route is a
// candidate, which is how an unmatched target without default routes fails.
type Set struct {
	ids map[string]struct{}
}

// newSet builds the immutable set, dropping duplicate IDs so the compiled
// policy cannot depend on list spelling.
func newSet(ids []string) *Set {
	uniqued := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		uniqued[id] = struct{}{}
	}
	return &Set{ids: uniqued}
}

// Allows reports whether id is in the set. Match returns nil for the
// unrestricted case and callers must check for it before consulting a set;
// a nil receiver answers false so a missed check fails closed (an unroutable
// request) instead of open (a route leaving its routing scope).
func (s *Set) Allows(id string) bool {
	if s == nil {
		return false
	}
	_, ok := s.ids[id]
	return ok
}

// Size reports the number of distinct candidate routes. Zero means every
// target matched by this set is unroutable.
func (s *Set) Size() int {
	if s == nil {
		return 0
	}
	return len(s.ids)
}

// Compile validates the spec's grammar and builds the immutable router. It is
// the only constructor: configuration load runs it so a malformed pattern or
// an impossible rule is rejected before it can serve, and the reload path
// keeps the last-known-good generation by refusing to publish on error.
//
// The grammar is deliberately tiny. A pattern is either a hostname or
// "*." followed by a hostname — nothing else matches, so `a*.example.com`,
// `*.*.example.com`, and bare `*` are all rejected. Hostnames follow the
// listener-address grammar: 1-253 characters, dot-separated labels of 1-63
// letters, digits, and hyphens, no leading or trailing hyphen or dot. A
// trailing DNS dot is accepted and normalized away, matching how targets are
// normalized before lookup. A rule must list at least one pattern and at
// least one route; a pattern or route listed twice in one rule is a
// configuration smell and is rejected rather than silently deduplicated.
func Compile(spec Spec) (*Router, error) {
	r := &Router{rules: make([]compiledRule, 0, len(spec.Rules))}
	for i, rule := range spec.Rules {
		if len(rule.Domains) == 0 {
			return nil, fmt.Errorf("routing.rules[%d] matches no domains: a rule must list at least one domain pattern", i)
		}
		if len(rule.Routes) == 0 {
			return nil, fmt.Errorf("routing.rules[%d] selects no routes: a rule must list at least one route id", i)
		}
		seenRoutes := make(map[string]struct{}, len(rule.Routes))
		for _, id := range rule.Routes {
			if _, dup := seenRoutes[id]; dup {
				return nil, fmt.Errorf("routing.rules[%d] lists route id %q twice", i, id)
			}
			seenRoutes[id] = struct{}{}
		}
		compiled := compiledRule{
			exact:  make(map[string]struct{}, len(rule.Domains)),
			wilds:  make([]string, 0, len(rule.Domains)),
			routes: newSet(rule.Routes),
		}
		for _, pattern := range rule.Domains {
			exact, wild, err := compilePattern(pattern)
			if err != nil {
				return nil, fmt.Errorf("routing.rules[%d]: %w", i, err)
			}
			switch {
			case wild != "":
				for _, existing := range compiled.wilds {
					if existing == wild {
						return nil, fmt.Errorf("routing.rules[%d] lists domain %q twice", i, pattern)
					}
				}
				compiled.wilds = append(compiled.wilds, wild)
			default:
				if _, dup := compiled.exact[exact]; dup {
					return nil, fmt.Errorf("routing.rules[%d] lists domain %q twice", i, pattern)
				}
				compiled.exact[exact] = struct{}{}
			}
		}
		r.rules = append(r.rules, compiled)
	}
	r.defaults = newSet(spec.DefaultRoutes)
	return r, nil
}

// compilePattern normalizes one domain pattern into either an exact hostname
// (wild "") or a wildcard suffix of the form ".suffix" (wild non-empty). The
// wildcard marker is checked after normalization, so a pattern's trailing
// DNS dot is stripped first: "*.example.com." compiles like
// "*.example.com", and a bare "*" or "*." fails hostname validation as the
// label "*" — the only wildcard form is "*.example.com".
func compilePattern(pattern string) (exact, wild string, err error) {
	if strings.TrimSpace(pattern) != pattern || pattern == "" {
		return "", "", errors.New("domain pattern must not be empty or padded with whitespace")
	}
	normalized := normalizeHost(pattern)
	wildcard := strings.HasPrefix(normalized, "*.")
	host := normalized
	if wildcard {
		host = normalized[len("*."):]
	}
	if err := validateHostname(host); err != nil {
		return "", "", fmt.Errorf("invalid domain pattern %q: %w", pattern, err)
	}
	if wildcard {
		return "", "." + host, nil
	}
	return host, "", nil
}

// validateHostname checks the listener-address hostname grammar: 1-253
// characters split into 1-63 character labels of letters, digits, and
// hyphens, with no empty label and no leading or trailing hyphen or dot.
// Punycode spellings pass as ordinary labels; the gateway never resolves
// names, so internationalized targets are matched byte-for-byte after the
// same normalization the patterns get.
func validateHostname(host string) error {
	if host == "" || len(host) > 253 {
		return errors.New("hostname must be 1-253 characters")
	}
	if strings.HasPrefix(host, ".") || strings.HasSuffix(host, ".") {
		return errors.New("hostname must not begin or end with a dot")
	}
	// Walk the labels in place: Match runs this on every domain target, so the
	// validation scan itself must stay allocation-free. A slicing window needs
	// no Split, and the empty-label case falls out of the two-dot gap naturally.
	for start := 0; start < len(host); {
		label := host[start:]
		if end := strings.IndexByte(label, '.'); end >= 0 {
			label = label[:end]
			start += end + 1
		} else {
			start = len(host)
		}
		if label == "" || len(label) > 63 {
			return fmt.Errorf("label %q must be 1-63 characters", label)
		}
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return fmt.Errorf("label %q must not begin or end with a hyphen", label)
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return fmt.Errorf("label %q contains a character outside letters, digits, and hyphens", label)
			}
		}
	}
	return nil
}

// matchHost validates and normalizes a target hostname. Matching and pattern
// compilation share this one grammar: an invalid target falls through to the
// default set rather than matching a byte suffix across an empty label.
func matchHost(host string) (string, bool) {
	host = normalizeHost(host)
	if validateHostname(host) != nil {
		return "", false
	}
	return host, true
}

// normalizeHost renders a hostname in the one form matching compares:
// lower-case with one trailing DNS dot removed. Matching is label-based on
// this normalized form only — it never rewrites the wire target, whose
// original bytes and address type travel to the outbound CONNECT untouched.
func normalizeHost(host string) string {
	host = strings.TrimSuffix(host, ".")
	return strings.ToLower(host)
}

// Match resolves one inbound CONNECT target to its candidate route set. A nil
// result means unrestricted: no routing policy applies to this target and the
// serving path must fall through to its listener filter alone. A non-nil
// result — including an empty one — is the complete candidate scope for the
// target; pool selection then picks among exactly those routes.
//
// Only an ATYP=DOMAIN target carries a hostname, so only it can match a rule;
// IPv4 and IPv6 targets always resolve to the default set. Reverse resolution
// is deliberately absent: inferring a hostname from an address literal would
// make routing depend on DNS rather than on what the client actually sent.
func (r *Router) Match(target socksdial.Target) *Set {
	if r == nil {
		return nil
	}
	if target.Type != socksdial.AddrDomain {
		return r.defaults
	}
	host, valid := matchHost(target.Host)
	// Target hostnames pass the same authoritative grammar patterns were
	// compiled under. A malformed name — an empty label anywhere in it, an
	// invalid byte, a label past RFC length bounds — can never satisfy a
	// rule, exact or wildcard, and falls through to the default set like any
	// other non-match.
	if !valid {
		return r.defaults
	}
	for i := range r.rules {
		rule := &r.rules[i]
		if _, ok := rule.exact[host]; ok {
			return rule.routes
		}
		for _, suffix := range rule.wilds {
			// Validation above guarantees the target is a sequence of
			// non-empty labels. A dotted suffix can therefore only match at a
			// label boundary: "*.example.com" accepts "api.example.com" and
			// "a.b.example.com", but not the bare "example.com" (which does
			// not end with the dotted suffix) or "evilexample.com" (whose
			// suffix match would eat part of a label).
			if strings.HasSuffix(host, suffix) {
				return rule.routes
			}
		}
	}
	return r.defaults
}
