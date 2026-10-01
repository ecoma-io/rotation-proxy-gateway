package controlapi

import (
	"net/http"
	"net/netip"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"
)

// handleProxies reports the configured route inventory: what the durable
// revision declares.
//
// It reads the active revision rather than the serving generation, deliberately.
// "Which routes does the cluster have" and "which routes is this replica
// serving" are different questions with different failure modes — a replica
// mid-convergence must not answer for the cluster — and an operator asking the
// first question while a rollout is in flight needs the answer that does not
// change under them.
//
// Health is absent by design. That is /routes, and the separation is what lets
// this be a declaration rather than an opinion.
func (a *api) handleProxies(w http.ResponseWriter, r *http.Request) {
	active, err := a.opts.ConfigStore.Active(r.Context())
	if err != nil {
		a.failStore(w, "config_unavailable", err)
		return
	}
	cfg, err := configstore.Decode(configstore.Document{Version: active.DocVersion, JSON: active.Document})
	if err != nil {
		// The active revision is not one this build can serve. That is a real
		// operational state — a peer wrote a document shape this instance does
		// not implement — and it is reported rather than answered with an empty
		// inventory, which would read as "the cluster has no routes".
		a.fail(w, http.StatusServiceUnavailable, "revision_unservable",
			"the active durable revision is not a configuration this build can serve")
		return
	}
	a.writeJSON(w, http.StatusOK, struct {
		// Revision is the durable revision this inventory was read from, so a
		// client can name exactly what it is looking at and tell two reads apart.
		Revision int64       `json:"revision"`
		Proxies  []proxyView `json:"proxies"`
	}{Revision: int64(active.Revision), Proxies: proxiesOf(cfg)})
}

// handleRoutes reports the serving generation's pool snapshot: the route
// inventory plus this instance's live health for it.
//
// The rotation state a manual route carries here is the pool's own view of it —
// the same object /status embeds — rather than a second rendering built for this
// API. One source means the two surfaces cannot disagree about which state a
// route is in, and it is the rotation state that matters (stale, cooling,
// auth-blocked) that is already reviewed for exactly this audience.
func (a *api) handleRoutes(w http.ResponseWriter, _ *http.Request) {
	gen := a.generation()
	routes := snapshotRoutes(gen)
	for i := range routes {
		if routes[i].Rotation != nil {
			routes[i].Rotation = rotationWithCanonicalIP(routes[i].Rotation)
		}
	}
	a.writeJSON(w, http.StatusOK, struct {
		// ConfigRevision is the revision this instance is serving, which is what
		// makes a health snapshot interpretable: the same healthy route means
		// something different before and after a reload that replaced it.
		ConfigRevision int64         `json:"configRevision"`
		Routes         []pool.Status `json:"routes"`
	}{ConfigRevision: gen.ConfigRevision, Routes: routes})
}

// handleRoutingRules reports the compiled routing policy: the rules as
// configured and the default candidate set.
//
// The policy is read from the serving generation rather than the durable
// revision, and the difference is not an inconsistency. Rules reference route
// ids, and an id means nothing until this instance has published the generation
// that binds it to a concrete route — so an API that answered from the durable
// revision would report rules naming routes this instance has not loaded. What
// it would lose is the guarantee the reader actually needs: that these are the
// rules this replica is applying to the traffic it is serving right now.
func (a *api) handleRoutingRules(w http.ResponseWriter, _ *http.Request) {
	cfg := a.generation().Config
	if cfg.Routing == nil {
		// An absent routing block is the unrestricted policy. It is reported as
		// configured:false rather than as an empty rule list, because those are
		// different configurations: an empty block is the fail-closed kill switch
		// that answers 503 for every unmatched target.
		a.writeJSON(w, http.StatusOK, struct {
			Configured bool `json:"configured"`
		}{Configured: false})
		return
	}
	spec := cfg.Routing.Configure()
	a.writeJSON(w, http.StatusOK, routingView{
		Configured:     true,
		ConfigRevision: a.generation().ConfigRevision,
		Rules:          rulesOf(spec.Rules),
		DefaultRoutes:  defaultsOf(spec.DefaultRoutes),
	})
}

// handleRotations reports rotation state for manual routes, the engine's
// process-lifetime aggregates, and the rotation settings safe to read back.
//
// Three deliberate omissions, each for the same reason. The rotate-API URL,
// headers, and body are never emitted, so a provider's credentials cannot reach
// a response even by accident. ip-check-url is omitted from the other end, for
// the same reason: a provider can carry an API token in that URL's query string,
// and nothing about the operator's view of rotation state needs it. And the
// rotation concurrency is reported as the single cap ResolveMaxConcurrent
// produces rather than as both raw knobs, because that cap is what the engine
// uses and a client comparing two instances should compare what is in effect,
// not the settings that happened to produce it.
//
// The route state itself comes from the pool's own rotation bookkeeping, which
// is where the answer to "is this route's egress IP current" is maintained.
func (a *api) handleRotations(w http.ResponseWriter, _ *http.Request) {
	gen := a.generation()
	cfg := gen.Config

	type routeRotation struct {
		Route string `json:"route"`
		// ID is the operator-facing routing label, so a rotation can be traced
		// to the rule or default set that names it.
		ID   string            `json:"id,omitempty"`
		Kind config.EgressKind `json:"kind"`
		// State is nil for a manual route that has not rotated yet. It is not an
		// empty object, so "never rotated" and "rotated with no IP recorded" stay
		// distinguishable — a distinction an operator debugging a rotation
		// actually needs.
		State *pool.RotationStatus `json:"state,omitempty"`
	}

	// Manual routes keyed by full route identity, so each joins its own rotation
	// state. Kind alone is not an identity here: validation rejects a duplicate
	// canonical route URL, not a duplicate kind, so an auto v6 route and a manual
	// v6 route coexist happily. Keyed by kind, the auto route would be reported as
	// a rotation candidate carrying the manual route's id.
	manual := make(map[string]config.ManualRouteSpec, len(cfg.ManualRoutes))
	for _, route := range cfg.ManualRoutes {
		manual[routeIdentity(route.RouteSpec)] = route
	}

	routes := []routeRotation{}
	for _, status := range snapshotRoutes(gen) {
		// status.Proxy is host:port, and spec.URL.Host is too, so the two halves of
		// this key cannot disagree on spelling.
		route, ok := manual[identityKey(status.Proxy, status.Kind, config.RouteOriginManual)]
		if !ok {
			continue
		}
		state := status.Rotation
		if state != nil {
			state = rotationWithCanonicalIP(state)
		}
		routes = append(routes, routeRotation{
			Route: status.Proxy,
			ID:    route.ID,
			Kind:  route.Kind,
			State: state,
		})
	}

	a.writeJSON(w, http.StatusOK, struct {
		// Rotations and IPRevisits are absent, not zero, when no engine backs this
		// process: an absent key means "not wired", and a zero would claim the
		// engine ran and rotated nothing.
		Rotations  *uint64         `json:"rotations"`
		IPRevisits *uint64         `json:"ipRevisits"`
		Routes     []routeRotation `json:"routes"`
		Settings   []setting       `json:"settings"`
	}{
		Rotations:  optionalCount(a.opts.Rotations),
		IPRevisits: optionalCount(a.opts.IPRevisits),
		Routes:     routes,
		Settings: []setting{
			boolSetting("rotate-on-start", cfg.Rotation.RotateOnStart),
			stringSetting("drain-timeout", cfg.Rotation.DrainTimeout.String()),
			stringSetting("ip-check-timeout", cfg.Rotation.IPCheckTimeout.String()),
			stringSetting("ip-check-interval", cfg.Rotation.IPCheckInterval.String()),
			stringSetting("retry-backoff-max", cfg.Rotation.RetryBackoffMax.String()),
			intSetting("max-concurrent", cfg.Rotation.ResolveMaxConcurrent(len(cfg.ManualRoutes))),
		},
	})
}

// identityKey joins a configured manual route to its pool status entry by the
// three facts that make a route itself: its endpoint, egress kind, and origin.
//
// Origin is the load-bearing part. The pool status carries it, so an auto route
// that happens to share a manual route's kind and endpoint can never be mistaken
// for a rotation candidate — which is exactly what a kind-only join did, and what
// a kind+endpoint join still would. The endpoint is host:port on both sides, so
// the key holds no credential.
func identityKey(hostPort string, kind config.EgressKind, origin config.RouteOrigin) string {
	return hostPort + "|" + string(kind) + "|" + string(origin)
}

// routeIdentity is identityKey for a configured spec, deriving the endpoint from
// the route URL the same way the pool snapshot does.
func routeIdentity(spec config.RouteSpec) string {
	return identityKey(spec.URL.Host, spec.Kind, spec.Origin)
}

// rotationWithCanonicalIP re-canonicalizes a route's reported egress IP through
// netip's Unmap, so a value that reached the pool snapshot in its IPv4-mapped
// IPv6 spelling is reported as the address it denotes.
//
// The pool stores it canonically already; doing it again here means the
// guarantee holds at the point the value leaves the process rather than only
// where it entered. A value that does not parse is dropped rather than passed
// through: an unparseable string in an "IP" field is worse than an absent one,
// because a client cannot tell it apart from a real address it failed to parse.
func rotationWithCanonicalIP(state *pool.RotationStatus) *pool.RotationStatus {
	if state.LastIP == "" {
		return state
	}
	addr, err := netip.ParseAddr(state.LastIP)
	if err != nil {
		out := *state
		out.LastIP = ""
		return &out
	}
	out := *state
	out.LastIP = addr.Unmap().String()
	return &out
}
