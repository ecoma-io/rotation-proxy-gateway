// Package controlapi serves the gateway's authenticated control API: the
// operator-facing HTTP surface that reads and writes the durable configuration
// and reports what this instance is actually serving.
//
// Four rules shape every handler here.
//
// # No secret ever leaves the process
//
// A configuration document carries route credentials and rotate-API headers and
// bodies. No endpoint here returns one, and none returns any fragment of one: a
// route is reported as host:port, a rotate API is reported as "configured", and
// a configuration view is assembled field by field from the validated
// RuntimeConfig rather than echoed from the stored bytes. Every string that
// originates outside the process — an operator's author or note, a validation
// error, a database message — goes through internal/sanitize, which bounds it,
// strips control and ANSI sequences, and redacts userinfo.
//
// # Nothing is invented
//
// Each resource reports only what a real source can answer, and says so
// explicitly when it cannot. /analytics has no durable source in this build and
// answers 501 rather than a plausible-looking empty series; a rotation aggregate
// with no engine behind it is omitted rather than reported as zero; a warm pool
// that is off reports nothing rather than zeros that look like an idle pool. A
// number that does not exist is never replaced by a zero.
//
// # No database query on the serving path
//
// Everything in this package runs on the admin listener, which is not the
// serving path, and nothing here is reachable from a proxied request.
//
// # The token is a boundary, not a formatting detail
//
// Authentication is delegated to the authenticator this package is handed, and
// every handler runs behind it. A nil authenticator answers 401 to everything:
// the fail-closed direction, so a control surface mounted without a token
// refuses rather than serves.
package controlapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/proxyserver"
	"rotation-proxy-gateway/internal/sanitize"

	"github.com/rs/zerolog"
)

// The resource paths, relative to the mount point. Exported so the mount and the
// test enumerating its surface agree on one list.
//
// The two route views are deliberately distinct. /proxies is what is
// *configured* — the durable revision's route list — and /routes is how those
// routes are *doing* right now on this instance, which is the pool snapshot and
// its health. Neither answers the other's question, and collapsing them would
// mean answering a durable question with instance-local state.
const (
	PathProxies      = "/proxies"
	PathRoutes       = "/routes"
	PathRoutingRules = "/routing-rules"
	PathRotations    = "/rotations"
	PathConfig       = "/config"
	PathAnalytics    = "/analytics"
)

// Paths is every resource this API serves, in one list.
var Paths = []string{
	PathProxies,
	PathRoutes,
	PathRoutingRules,
	PathRotations,
	PathConfig,
	PathAnalytics,
}

// controlHeaderPrefix is the gateway's own control-header namespace, which guard
// consumes so nothing here can forward a client's control header onward.
const controlHeaderPrefix = "x-ecoma-"

// headerRequestID is the correlation header this API reads and echoes. It is the
// same header the proxy listeners accept, under the same rules.
const headerRequestID = "X-Ecoma-Request-Id"

// Authenticator decides whether a control request may proceed. It is an
// interface rather than the concrete type so this package does not own the
// token's digest, comparison, or presentation rules — proxyserver does, under
// the same process-wide key every other credential in the process uses.
//
// A nil Authenticator refuses everything. That is the fail-closed direction, not
// an oversight: the process additionally refuses to start with a control API
// mounted and no token, and this is the second lock on the same door.
type Authenticator interface {
	Authorized(r *http.Request) bool
}

// Options configures the control mux.
type Options struct {
	// Auth guards every handler. Nil refuses every request.
	Auth Authenticator
	// Generations is the serving generation store. Required: most reads here
	// answer about what this instance is serving, and there is no honest answer
	// without it.
	Generations *pool.Store
	// ConfigStore is the durable configuration store. Required — a control API
	// with no store behind it could not do the one thing it exists to do.
	ConfigStore configstore.Repository
	// Rotations and IPRevisits are the rotation engine's process-lifetime
	// aggregates. Nil omits them, matching how /status treats them.
	Rotations  func() uint64
	IPRevisits func() uint64
	// Log is the process logger. Control requests are logged at debug so a write
	// to the durable configuration leaves a trace without adding noise to a proxy
	// that logs per request.
	Log zerolog.Logger
}

// api is the built mux plus the dependencies its handlers share.
type api struct {
	opts Options
	log  zerolog.Logger
}

// maxRequestBytes bounds one control request body.
//
// It is the store's own document ceiling plus room for the JSON envelope, so an
// oversized document is refused by the bound rather than read into memory first,
// and a document inside the store's ceiling is never rejected here for a reason
// the store would not have given.
const maxRequestBytes = configstore.MaxDocumentBytes + 64<<10

// errBodyTooLarge distinguishes an over-bound body from a malformed one, so a
// handler answers 413 rather than blaming the client's JSON.
var errBodyTooLarge = errors.New("control request body exceeds the document ceiling")

// New builds the control API mux.
//
// It panics on a nil generation or config store rather than serving a control
// surface that cannot answer its own question — the same constructor contract
// control.NewReconciler follows. The "mounted with no token" case is handled at
// the call site instead: that is a configuration error to refuse a process over,
// not a construction error to trap.
//
// It does not panic on a nil Auth; see Authenticator.
func New(opts Options) *http.ServeMux {
	if opts.Generations == nil {
		panic("controlapi: New requires a non-nil generation store")
	}
	if opts.ConfigStore == nil {
		panic("controlapi: New requires a non-nil config store")
	}
	a := &api{opts: opts, log: opts.Log}
	mux := http.NewServeMux()
	mux.Handle("GET "+PathProxies, a.guard(a.handleProxies))
	mux.Handle("GET "+PathRoutes, a.guard(a.handleRoutes))
	mux.Handle("GET "+PathRoutingRules, a.guard(a.handleRoutingRules))
	mux.Handle("GET "+PathRotations, a.guard(a.handleRotations))
	mux.Handle("GET "+PathConfig, a.guard(a.handleGetConfig))
	mux.Handle("PUT "+PathConfig, a.guard(a.handlePutConfig))
	mux.Handle("GET "+PathAnalytics, a.guard(a.handleAnalytics))
	return mux
}

// guard authenticates and consumes the gateway's own header namespace before any
// handler runs.
//
// Stripping is unconditional and lives here rather than in each handler. Nothing
// in this package forwards a request anywhere, so today it is belt-and-braces;
// it is here because a control handler that later grew an outbound call would
// otherwise inherit a client's control namespace by default, and "no x-ecoma-*
// header is forwarded" is a property worth holding structurally rather than by
// remembering.
//
// The correlation id is resolved before the header is deleted, and echoed on the
// response. An id this process will not echo is not an error: the request's log
// line still carries a minted one, so correlation works and the caller is told
// nothing false about its own header.
func (a *api) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		correlation, _ := proxyserver.AcceptedRequestID(r.Header)
		r.Header = r.Header.Clone()
		for name := range r.Header {
			if strings.HasPrefix(strings.ToLower(name), controlHeaderPrefix) {
				r.Header.Del(name)
			}
		}
		if !a.authorized(r) {
			// No detail about which part of the credential was wrong: a challenge
			// that distinguishes "malformed" from "wrong" is an oracle for probing
			// a token. 401 with the bearer challenge, never 407 — see
			// ControlAuthenticator for why the two are not interchangeable.
			w.Header().Set("WWW-Authenticate", proxyserver.BearerChallenge)
			a.log.Debug().Str("path", r.URL.Path).Str("correlation_id", correlation).
				Msg("control request refused")
			a.fail(w, http.StatusUnauthorized, "unauthorized", "a valid bearer token is required")
			return
		}
		if correlation != "" {
			w.Header().Set(headerRequestID, correlation)
		}
		a.log.Debug().Str("method", r.Method).Str("path", r.URL.Path).
			Str("correlation_id", correlation).Msg("control request")
		next(w, r)
	}
}

// authorized asks the authenticator whether this request may proceed.
//
// The nil check is the point of the method rather than an incidental guard: the
// Authenticator is an interface, and calling a method on a nil interface value
// panics rather than returning false. Without this a control surface handed no
// authenticator would crash on its first request instead of refusing it, which is
// the opposite of the fail-closed direction this package documents.
func (a *api) authorized(r *http.Request) bool {
	return a.opts.Auth != nil && a.opts.Auth.Authorized(r)
}

// generation returns the configuration this instance is serving right now.
//
// Loading the generation once per handler is what keeps a response internally
// consistent: a reload landing mid-request cannot make /routes report a revision
// and a route list that came from different snapshots.
func (a *api) generation() *pool.Generation {
	return a.opts.Generations.Load()
}

// handleAnalytics answers 501. Analytics is being built in a parallel phase and
// this build has no durable source for it.
//
// The refusal is explicit and typed rather than an empty result on purpose. An
// endpoint that returned [] or {"series":[]} for a resource it never measured is
// indistinguishable from one that measured nothing and found nothing, and an
// operator reading a dashboard cannot tell which one they have. 501 says the
// capability is absent from this build; 503 would say it is present and
// temporarily unavailable, which would send an operator to inspect a dependency
// that does not exist.
func (a *api) handleAnalytics(w http.ResponseWriter, _ *http.Request) {
	a.writeJSON(w, http.StatusNotImplemented, map[string]any{
		"error":     "not_available",
		"resource":  PathAnalytics,
		"available": false,
		"message": "this build has no durable analytics source; the resource is " +
			"reported unavailable rather than answered with invented data",
	})
}

// writeJSON emits one uncacheable JSON response.
//
// Every control response is no-store. These bodies describe live operational
// state, and a cached copy would be readable by whoever the cache sits in front
// of — including, for a proxy, an intermediary that never saw the token that
// authorized the read.
func (a *api) writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if body == nil {
		return
	}
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// The status line is already out, so this can only be reported.
		a.log.Warn().Str("error", sanitize.ErrorString(err)).Msg("control response body truncated")
	}
}

// fail emits the one error envelope every control endpoint uses. The message is
// written by the caller and is always safe text; this function sanitizes it
// anyway, so a future handler that formats an error into it cannot leak.
func (a *api) fail(w http.ResponseWriter, status int, code, message string) {
	a.log.Debug().Int("status", status).Str("error", code).Msg("control request rejected")
	a.writeJSON(w, status, map[string]any{
		"error":   code,
		"message": sanitize.Sanitize(message),
	})
}

// failStore maps a store read failure onto a transport status.
//
// Every one of these is 503: the store is unreachable or unpopulated, not the
// request wrong. ErrNoActiveRevision gets its own message because it is the one
// failure an operator can fix by committing a configuration, and reporting it as
// "unavailable" would send them to inspect the database instead.
func (a *api) failStore(w http.ResponseWriter, code string, err error) {
	if errors.Is(err, configstore.ErrNoActiveRevision) {
		a.fail(w, http.StatusServiceUnavailable, code,
			"no configuration revision has been committed yet")
		return
	}
	a.fail(w, http.StatusServiceUnavailable, code,
		"the durable configuration store is not readable right now")
}

// readBounded reads at most maxRequestBytes from r, reporting an oversized body
// distinctly from every other read failure so the handler can answer 413 rather
// than treating a truncated configuration as a malformed one.
func readBounded(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxRequestBytes))
	if err == nil {
		return body, nil
	}
	var tooLarge *http.MaxBytesError
	if errors.As(err, &tooLarge) {
		return nil, errBodyTooLarge
	}
	// A client that hung up mid-body and an over-limit body are the same problem
	// to the handler — the bytes are unusable either way — so every other read
	// failure keeps its own identity for the log and is reported as a bad
	// request.
	return nil, err
}

// snapshotRoutes returns the pool snapshot as an empty slice rather than a nil
// one, so a client reads `"routes": []` for a route-less configuration instead
// of having to tell null from empty itself.
func snapshotRoutes(gen *pool.Generation) []pool.Status {
	routes := gen.Pool.Snapshot()
	if routes == nil {
		return []pool.Status{}
	}
	return routes
}

// proxyView is one configured route.
//
// Proxy is the endpoint's host:port. It is built with hostPort, never
// URL.String(), because URL.String() carries the userinfo the route authenticates
// with — and a read-only inventory is not a reason to publish it.
type proxyView struct {
	ID     string             `json:"id,omitempty"`
	Proxy  string             `json:"proxy"`
	Kind   config.EgressKind  `json:"kind"`
	Origin config.RouteOrigin `json:"origin"`
	// RotateInterval is a manual route's provider rotation cadence. A schedule,
	// not a credential.
	RotateInterval string `json:"rotateInterval,omitempty"`
	// RotateAPIConfigured reports that a provider rotate call exists for this
	// manual route. Its URL, method, headers, and body are never reported: they
	// carry provider credentials, and "one is configured" is the only fact an
	// operator needs from a read-only inventory. It is a bool rather than a count
	// so a route cannot be probed for how many secrets it holds.
	RotateAPIConfigured bool `json:"rotateAPIConfigured,omitempty"`
}

// proxiesOf renders a configuration's routes. Both halves come out of the same
// helper so /proxies and /config cannot drift on what a route looks like — a
// route that was safe in one view and reimplemented in the other is exactly how
// a credential ends up in a response.
func proxiesOf(cfg *config.RuntimeConfig) []proxyView {
	proxies := make([]proxyView, 0, len(cfg.Routes)+len(cfg.ManualRoutes))
	for _, route := range cfg.Routes {
		proxies = append(proxies, proxyView{
			ID:     route.ID,
			Proxy:  hostPort(route.URL),
			Kind:   route.Kind,
			Origin: route.Origin,
		})
	}
	for _, route := range cfg.ManualRoutes {
		proxies = append(proxies, proxyView{
			ID:                  route.ID,
			Proxy:               hostPort(route.URL),
			Kind:                route.Kind,
			Origin:              route.Origin,
			RotateInterval:      route.RotateInterval.String(),
			RotateAPIConfigured: route.API.URL != nil,
		})
	}
	return proxies
}

// hostPort renders a route URL as host:port with no userinfo.
//
// URL.Host excludes userinfo and URL.String() does not, so this helper is the
// whole reason a route can be reported at all: it is the difference between
// publishing a route and publishing a route's password.
func hostPort(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Host
}

// setting is one named configuration or rotation knob.
//
// A name/value pair rather than a nested object because the reported set is
// deliberately partial — see handleRotations — and a nested object would invite a
// client to read an absent field as a default.
type setting struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// boolSetting renders a bool knob as a value.
//
// Every knob in these views has the same value type so a client never has to
// branch on which knob it is reading; a nested object with mixed types would put
// that branch in front of it on every read.
func boolSetting(name string, value bool) setting {
	return setting{Name: name, Value: strconv.FormatBool(value)}
}

// stringSetting renders a string or duration knob.
func stringSetting(name, value string) setting {
	return setting{Name: name, Value: value}
}

// intSetting renders a count knob.
func intSetting(name string, value int) setting {
	return setting{Name: name, Value: strconv.Itoa(value)}
}

// optionalCount renders an aggregate that may not be wired.
//
// Nil is omitted so the key's absence keeps meaning "this build has no rotation
// engine", which a zero could not: a zero would claim the engine ran and rotated
// nothing.
func optionalCount(source func() uint64) *uint64 {
	if source == nil {
		return nil
	}
	value := source()
	return &value
}
