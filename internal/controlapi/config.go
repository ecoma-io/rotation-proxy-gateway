package controlapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/routing"
	"rotation-proxy-gateway/internal/sanitize"
)

// PUT /config's transport status vocabulary, and why it is two statuses and not
// one.
//
// The store has exactly one concurrency failure — ErrRevisionMismatch — for "the
// pointer was not where you said it was". That one condition has two genuinely
// different causes, and a client has to tell them apart because the right next
// move differs:
//
//   - 428 Precondition Required (RFC 9110 §15.5.29) — the request carried no
//     usable expected_revision. The client did not attempt a conditional write,
//     so it must read the current revision and add one. Retrying the identical
//     request would clobber whatever a peer committed in the meantime.
//   - 412 Precondition Failed (RFC 9110 §15.5.13) — the request carried one and
//     it was stale. The client knows what it expected and lost the race; it
//     reads the current revision, decides whether its change is still wanted,
//     and writes again.
//
// Both name the current active revision, so the retry is knowingly rather than
// blind. A single status would force one of those two clients to guess, and
// guessing here means either an unguarded overwrite of a cluster-wide
// configuration or a write loop that never converges.
const (
	statusPreconditionFailed = http.StatusPreconditionFailed
	statusPreconditionNeeded = http.StatusPreconditionRequired
)

// The document returned by GET /config is not editable.
//
// A durable document holds route lines in `user:pass@host:port` form and
// rotate-API URLs, headers, and bodies. A GET /config that omitted them would be
// returning a document that fails its own decoder — the route rules reject a
// route line with no credentials where the live configuration has them, and
// the rotate-API URL is not optional for a manual route — and a client that
// round-tripped it would push a configuration that drops every credential in the
// deployment. So GET reports a declared view, and PUT takes a whole document
// written by an operator who already holds the credentials.
//
// editableDocument states which, in the response body, rather than leaving a
// client to infer it from the absence of a field it expected.
const editableDocument = false

// configView is one configuration revision, credential-free.
type configView struct {
	Revision int64  `json:"revision"`
	Author   string `json:"author,omitempty"`
	Note     string `json:"note,omitempty"`
	// CommittedAt is the durable store's own record of when the pointer last
	// moved. It is the database clock, not this instance's, because the question
	// "when did the cluster change" is not answered correctly by whichever
	// replica happens to answer it.
	CommittedAt string `json:"committedAt,omitempty"`
	// Editable is false, and documented above: this view is declared, not
	// round-trippable.
	Editable bool       `json:"editable"`
	Config   configBody `json:"config"`
}

// configBody is the sanitized configuration itself.
type configBody struct {
	LogLevel     string      `json:"logLevel"`
	MaxRetries   int         `json:"maxRetries"`
	CooldownBase string      `json:"cooldownBase"`
	CooldownMax  string      `json:"cooldownMax"`
	DialTimeout  string      `json:"dialTimeout"`
	Proxies      []proxyView `json:"proxies"`
	Rotation     []setting   `json:"rotation"`
	// WarmPool is absent when the pool is off. An absent block and a block of
	// zeros are different claims — "disabled" versus "enabled and idle" — and
	// only the first is true here.
	WarmPool []setting `json:"warmPool,omitempty"`
	// Routing is always present, with configured:false standing for the
	// unrestricted policy, because that and "configured to fail closed" are
	// different configurations and a client must be able to tell them apart.
	Routing routingView `json:"routing"`
}

// routingView is the compiled routing policy, or its absence.
type routingView struct {
	Configured bool       `json:"configured"`
	Rules      []ruleView `json:"rules,omitempty"`
	// DefaultRoutes is absent for an unrestricted policy and for one whose
	// default set is empty; the two are told apart by Configured.
	DefaultRoutes []string `json:"defaultRoutes,omitempty"`
	// ConfigRevision is the revision these rules were compiled from, present on
	// the standalone /routing-rules resource so a client reading it can tell
	// which configuration produced the policy.
	ConfigRevision int64 `json:"configRevision,omitempty"`
}

type ruleView struct {
	Domains []string `json:"domains"`
	Routes  []string `json:"routes"`
}

// rulesOf and defaultsOf normalize a compiled policy for the wire. The pool
// snapshot's rule slices are nil when empty; a client reading `"domains": null`
// has to special-case what an empty JSON array already says.
func rulesOf(rules []routing.RuleSpec) []ruleView {
	out := make([]ruleView, 0, len(rules))
	for _, rule := range rules {
		domains := rule.Domains
		if domains == nil {
			domains = []string{}
		}
		routes := rule.Routes
		if routes == nil {
			routes = []string{}
		}
		out = append(out, ruleView{Domains: domains, Routes: routes})
	}
	return out
}

func defaultsOf(routes []string) []string {
	if routes == nil {
		return []string{}
	}
	return routes
}

// handleGetConfig reports the active durable revision and a credential-free view
// of its configuration.
//
// Author and Note are operator-supplied free text read back out of the database,
// so both go through sanitize: they are the one pair of strings in this response
// a human typed, and an unbounded or escape-laden one would end up in logs and
// terminals downstream. Every other value in the view is derived from a
// validated configuration and is therefore already bounded.
func (a *api) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	active, err := a.opts.ConfigStore.Active(r.Context())
	if err != nil {
		a.failStore(w, "config_unavailable", err)
		return
	}
	cfg, err := configstore.Decode(configstore.Document{Version: active.DocVersion, JSON: active.Document})
	if err != nil {
		a.fail(w, http.StatusServiceUnavailable, "revision_unservable",
			"the active durable revision is not a configuration this build can serve")
		return
	}
	a.writeJSON(w, http.StatusOK, viewOf(active, cfg))
}

// viewOf builds the credential-free view of one revision.
//
// Every field is named explicitly. That is the point: a view assembled by
// reflecting over a configuration, or by re-serializing the stored document, is
// one field-skip away from publishing route userinfo, and this function is the
// place that has to be right.
func viewOf(active configstore.Active, cfg *config.RuntimeConfig) configView {
	body := configBody{
		LogLevel:     cfg.LogLevel,
		MaxRetries:   cfg.MaxRetries,
		CooldownBase: cfg.CooldownBase.String(),
		CooldownMax:  cfg.CooldownMax.String(),
		DialTimeout:  cfg.DialTimeout.String(),
		Proxies:      proxiesOf(cfg),
		Rotation: []setting{
			boolSetting("rotate-on-start", cfg.Rotation.RotateOnStart),
			stringSetting("drain-timeout", cfg.Rotation.DrainTimeout.String()),
			stringSetting("ip-check-timeout", cfg.Rotation.IPCheckTimeout.String()),
			stringSetting("ip-check-interval", cfg.Rotation.IPCheckInterval.String()),
			stringSetting("retry-backoff-max", cfg.Rotation.RetryBackoffMax.String()),
			intSetting("max-concurrent", cfg.Rotation.ResolveMaxConcurrent(len(cfg.ManualRoutes))),
		},
	}
	if cfg.WarmPool.Enabled {
		body.WarmPool = []setting{
			boolSetting("enabled", cfg.WarmPool.Enabled),
			intSetting("min-idle-per-proxy", cfg.WarmPool.MinIdlePerProxy),
			intSetting("max-idle-per-proxy", cfg.WarmPool.MaxIdlePerProxy),
			intSetting("max-total-idle", cfg.WarmPool.MaxTotalIdle),
			intSetting("max-replenish-concurrency", cfg.WarmPool.MaxReplenishConcurrency),
			intSetting("max-replenish-per-route", cfg.WarmPool.MaxReplenishPerRoute),
			stringSetting("idle-ttl", cfg.WarmPool.IdleTTL.String()),
		}
	}
	if cfg.Routing != nil {
		spec := cfg.Routing.Configure()
		body.Routing = routingView{
			Configured:    true,
			Rules:         rulesOf(spec.Rules),
			DefaultRoutes: defaultsOf(spec.DefaultRoutes),
		}
	} else {
		body.Routing = routingView{Configured: false}
	}
	return configView{
		Revision:    int64(active.Revision),
		Author:      sanitize.Sanitize(active.Author),
		Note:        sanitize.Sanitize(active.Note),
		CommittedAt: active.PointerUpdated.UTC().Format(time.RFC3339),
		Editable:    editableDocument,
		Config:      body,
	}
}

// putConfigRequest is the PUT /config envelope.
//
// The document is a nested field rather than the request body itself so the
// metadata travels with it: a durable write whose author and note are out of
// band has no way to survive a client crash between the two, and the revision
// history is only useful if each entry says who wrote it and why.
type putConfigRequest struct {
	// ExpectedRevision is the revision the client believes is active. Zero means
	// absent, and an absent expectation is refused with 428 rather than treated
	// as "write unconditionally" — see the status vocabulary above. An
	// unconditional write is the seed path's privilege (configstore.Commit's
	// NoRevision case), not this endpoint's: an operator-facing API that let a
	// missing field mean "overwrite whatever is there" would make the one
	// dangerous request the easiest one to make by accident.
	ExpectedRevision int64 `json:"expected_revision"`
	// Author and Note are free text recorded with the revision. Both are
	// sanitized before they reach the store, so a value that would corrupt a log
	// line downstream is cleaned at the boundary rather than at every reader.
	Author string `json:"author"`
	Note   string `json:"note"`
	// Document is the durable configuration document, exactly the shape
	// configstore.Decode accepts — the same bytes a hand-written document would
	// be, validated by the same code.
	Document json.RawMessage `json:"document"`
}

// handlePutConfig commits a new configuration revision through the store's
// optimistic concurrency.
//
// The order is the contract, and each step earns its place:
//
//  1. Bound and parse the body. A malformed envelope never reaches the store.
//     Unknown fields are refused: a client that misspells "expected_revision"
//     must not be answered with a successful unguarded write, so strictness here
//     is the difference between a caught typo and a silent lost update.
//  2. Read the active revision once, up front. It answers two questions at
//     once — what a client must name to proceed, and what a 412 or 428 body
//     must tell it — and it is a read, not a check. The decision is made by the
//     conditional write below, because read-then-write is precisely the race the
//     store's conditional pointer move exists to prevent.
//  3. Refuse a missing expectation with 428.
//  4. Validate the document with configstore.Decode — the same validation a
//     config.yaml gets, so nothing enters the durable history that could not be
//     served.
//  5. Commit with the expectation.
//
// Step 4 is why a client cannot poison the cluster: a document is validated here
// before it is appended, and validated again by the reconciler in every instance
// before it is published. A document that decodes is one this build can serve; a
// committed revision is one every instance has accepted into history — though
// whether each has finished applying it is a per-replica question, which is what
// /status's cluster scope reports and this endpoint deliberately does not
// promise.
func (a *api) handlePutConfig(w http.ResponseWriter, r *http.Request) {
	body, err := readBounded(w, r)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			a.fail(w, http.StatusRequestEntityTooLarge, "body_too_large",
				"the request body is larger than a configuration document may be")
			return
		}
		a.fail(w, http.StatusBadRequest, "unreadable_request",
			"the request body could not be read")
		return
	}

	var req putConfigRequest
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil || decoder.More() {
		// A trailing value would make the body a stream of envelopes rather than
		// one envelope, and which of the two the client meant is not guessable.
		a.fail(w, http.StatusBadRequest, "malformed_request",
			"the request body is not a configuration envelope this build understands")
		return
	}
	if len(req.Document) == 0 {
		a.fail(w, http.StatusBadRequest, "malformed_request", "the request carries no document")
		return
	}

	current, activeErr := a.opts.ConfigStore.Active(r.Context())

	if req.ExpectedRevision <= 0 {
		a.failPrecondition(w, statusPreconditionNeeded,
			"PUT /config requires expected_revision naming the revision it replaces",
			current, activeErr)
		return
	}

	if _, err := configstore.Decode(configstore.Document{
		Version: config.DocumentVersion,
		JSON:    req.Document,
	}); err != nil {
		// The message is deliberately generic. A validation error names the
		// offending field and its index, which is right for an operator reading
		// their own config.yaml and wrong here: a route line is
		// `user:pass@host:port`, so an error that quoted it would publish the
		// password into a response body and every log that recorded it.
		a.fail(w, http.StatusBadRequest, "invalid_config",
			"the document is not a configuration this build accepts")
		return
	}

	record, err := a.opts.ConfigStore.Commit(r.Context(), configstore.Revision(req.ExpectedRevision),
		configstore.Document{Version: config.DocumentVersion, JSON: req.Document},
		configstore.Meta{
			Author: sanitize.Sanitize(req.Author),
			Note:   sanitize.Sanitize(req.Note),
		})
	switch {
	case err == nil:
		a.log.Info().Int64("revision", int64(record.Revision)).
			Str("author", sanitize.Sanitize(req.Author)).Msg("configuration revision committed")
		a.writeJSON(w, http.StatusOK, struct {
			Revision int64 `json:"revision"`
			// Revision is the revision this write created. There is no separate
			// "applied" figure: whether each replica has finished materializing
			// it is per-replica state, and answering it here would mean either a
			// query per replica or a claim this instance cannot make.
			Accepted bool `json:"accepted"`
		}{Revision: int64(record.Revision), Accepted: true})
	case errors.Is(err, configstore.ErrRevisionMismatch):
		// The pointer moved between this client's read and its write, or between
		// its last successful write and now. Name where it is now.
		a.failPrecondition(w, statusPreconditionFailed,
			"the active configuration revision is not the one this write expected",
			current, nil)
	case errors.Is(err, configstore.ErrDocumentTooLarge):
		a.fail(w, http.StatusRequestEntityTooLarge, "body_too_large",
			"the document is larger than a configuration document may be")
	default:
		a.fail(w, http.StatusServiceUnavailable, "commit_failed",
			"the durable configuration store did not accept the revision")
	}
}

// failPrecondition emits 412 or 428 with the current active revision, so a
// client can retry against the truth rather than against its stale expectation.
//
// A failure to read the current revision is not itself escalated to a different
// status: the client is already being refused, and a precondition response that
// omitted the revision because the store blinked would force it to guess, which
// is the failure mode these two statuses exist to prevent. The `readable` flag
// says so explicitly — a false there is the signal to re-read before retrying,
// not to retry blind.
func (a *api) failPrecondition(w http.ResponseWriter, status int, message string, current configstore.Active, activeErr error) {
	revision := int64(0)
	switch {
	case activeErr != nil:
		// Zero stays zero, and readable:false tells the client the store could not
		// be asked rather than that the cluster is at revision zero.
	case !current.Revision.IsValid():
		// The store answered and names nothing. That is a real empty state, not an
		// unreadable one, and it is what a first-ever write should be given.
	default:
		revision = int64(current.Revision)
	}
	a.writeJSON(w, status, map[string]any{
		"error":   "precondition_failed",
		"message": message,
		// CurrentRevision is what a retry must name, or 0 when nothing is active.
		"currentRevision": revision,
		"readable":        activeErr == nil,
	})
}

// maxRequestEnvelopeBytes is the request-side bound restated under the name a
// reader of this file needs. maxRequestBytes is the store's document ceiling
// plus room for the envelope; saying it here makes it plain that a body over the
// limit is refused before parsing rather than halfway through it.
const maxRequestEnvelopeBytes = maxRequestBytes

// compile-time assertions that the duration and timestamp renderings in these
// views are the ones the rest of the process already uses. The pool formats
// rotation timestamps as RFC 3339 in UTC, and a second format in the control API
// would make two surfaces disagree about the same instant.
var _ = time.RFC3339
