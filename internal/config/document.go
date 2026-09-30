package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"rotation-proxy-gateway/internal/routing"
)

// The durable configuration document.
//
// A document is the durable form of one RuntimeConfig: one immutable JSON
// object per revision, holding every runtime setting and route. It exists so
// a revision can be validated, stored, and materialized as a single unit
// rather than as a set of rows whose cross-field rules would have to be
// re-derived in SQL.
//
// It deliberately does not reimplement any validation. Every rule — route
// lines, port ranges, kind grammar, route ids, routing-block compilation,
// rotation settings, warm-pool bounds, listener address overlap — is the
// existing runtime.go / routing.go code, reached through exactly one funnel:
//
//	JSON → documentFileConfig → fileConfig → runtimeFromFile → RuntimeConfig
//
// The document is decoded strictly, so it inherits the file config's rejection
// of unknown keys rather than quietly dropping them. That inheritance is the
// reason a durable document and a config.yaml are interchangeable inputs, and
// it is what makes a retired key (global:, weight:, balance:) fail identically
// through both paths.
//
// Document version. Two version axes exist in this subsystem and they are
// independent: the schema-migration version versions the database tables, and
// the document version versions the shape below. Bumping this constant is a
// document change and requires no migration; adding a migration is a schema
// change and requires nothing here. DocumentVersion is checked before decoding
// begins, so a too-new document is refused rather than partially understood —
// a reader that skipped fields it did not recognize would validate less than
// the writer did.
const DocumentVersion = 1

// documentFileConfig is the durable document's own shape. Its fields are
// strings and `any` exactly as fileConfig's are, because it is marshalled into
// that struct: keeping the same value shapes means the existing anti-coercion
// checks (a whole number, never a silently truncated fraction) apply unchanged
// rather than being reimplemented for JSON.
//
// Durations are Go duration strings rather than nanosecond integers, so a
// document stays readable in psql and a hand-edit is reviewable.
type documentFileConfig struct {
	Version     int                `json:"version"`
	LogLevel    string             `json:"log-level"`
	MaxRetries  any                `json:"max-retries"`
	Cooldown    cooldownFileConfig `json:"cooldown"`
	DialTimeout string             `json:"dial-timeout"`
	Rotation    rotationFileConfig `json:"rotation"`
	Proxies     proxiesFileConfig  `json:"proxies"`
	WarmPool    warmPoolFileConfig `json:"warm-pool"`
	Routing     *routingFileConfig `json:"routing"`
}

// marshalDocument converts a validated RuntimeConfig into the durable
// document form. It is the inverse of RuntimeFromDocument and shares its
// rules, so a configuration that round-trips through here is byte-identical to
// one written by hand for the same settings.
//
// Route credentials and rotate-API headers appear in the produced bytes. That
// is the document's nature — it is the durable form of the configuration, and
// the configuration holds the credentials. Callers must treat the result as
// secret material: it is written to the store and never logged.
func marshalDocument(cfg *RuntimeConfig) ([]byte, error) {
	if cfg == nil {
		return nil, errors.New("a configuration document needs a non-nil RuntimeConfig")
	}
	raw := documentFileConfig{
		Version:     DocumentVersion,
		LogLevel:    cfg.LogLevel,
		MaxRetries:  cfg.MaxRetries,
		DialTimeout: cfg.DialTimeout.String(),
		Cooldown: cooldownFileConfig{
			Base: cfg.CooldownBase.String(),
			Max:  cfg.CooldownMax.String(),
		},
	}
	for _, route := range cfg.Routes {
		raw.Proxies.Auto = append(raw.Proxies.Auto, autoProxyFileConfig{
			ID:    optionalString(route.ID),
			Proxy: routeLineFromURL(route.URL),
			Kind:  string(route.Kind),
		})
	}
	for _, route := range cfg.ManualRoutes {
		raw.Proxies.Manual = append(raw.Proxies.Manual, manualProxyFileConfig{
			ID:             optionalString(route.ID),
			Proxy:          routeLineFromURL(route.URL),
			Kind:           string(route.Kind),
			RotateInterval: route.RotateInterval.String(),
			API: apiFileConfig{
				URL:     route.API.URL.String(),
				Method:  route.API.Method,
				Headers: route.API.Headers,
				Body:    route.API.Body,
				Timeout: route.API.Timeout.String(),
			},
		})
	}
	raw.Rotation = rotationFromSettings(cfg.Rotation)
	raw.WarmPool = warmPoolFromSettings(cfg.WarmPool)
	if cfg.Routing != nil {
		raw.Routing = routingFromRouter(cfg.Routing)
	}
	body, err := json.Marshal(raw)
	if err != nil {
		// json.Marshal cannot fail on this struct: every field is a scalar, a
		// slice of scalars, or a map of strings. Reported without the value,
		// which is a configuration document.
		return nil, fmt.Errorf("encode config document: %w", err)
	}
	return body, nil
}

// optionalString distinguishes an absent id from an explicitly empty one, the
// same distinction the file config draws: absent is legal (an unnamed route),
// while an explicit empty id is a configuration smell the runtime validator
// rejects.
func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

// routeLineFromURL renders a validated route URL back into the bare
// host:port[:user:pass] form the file config accepts. The bare form is used
// rather than a socks5:// URL because the endpoint protocol is not
// configurable — writing "socks5://" into the document would produce a
// document its own parser rejects.
//
// Userinfo is written in the user:pass@host:port form. It is secret, so this
// function is only ever called on the way into the document, never on a path
// that formats the result into an error or a log field.
func routeLineFromURL(u *url.URL) string {
	host := u.Hostname()
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if u.User == nil {
		return host + ":" + port
	}
	username := u.User.Username()
	password, _ := u.User.Password()
	return username + ":" + password + "@" + host + ":" + port
}

// rotationFromSettings renders rotation settings back into the file shape.
// Absent values are emitted as absent rather than as their defaults, so a
// document records what an operator chose and the defaults stay defaults —
// writing defaults into the document would freeze today's default as an
// explicit choice.
func rotationFromSettings(s RotationSettings) rotationFileConfig {
	raw := rotationFileConfig{}
	switch {
	case s.MaxConcurrentPercent != nil:
		raw.MaxConcurrent = strconv.Itoa(*s.MaxConcurrentPercent) + "%"
	case s.MaxConcurrentFixed != nil:
		raw.MaxConcurrent = *s.MaxConcurrentFixed
	}
	if s.RotateOnStart {
		enabled := true
		raw.RotateOnStart = &enabled
	}
	raw.DrainTimeout = nonDefaultDuration("rotation.drain-timeout", s.DrainTimeout, DefaultDrainTimeout)
	raw.IPCheckURL = nonDefaultString("rotation.ip-check-url", s.IPCheckURL, DefaultIPCheckURL)
	raw.IPCheckTimeout = nonDefaultDuration("rotation.ip-check-timeout", s.IPCheckTimeout, DefaultIPCheckTimeout)
	raw.IPCheckInterval = nonDefaultDuration("rotation.ip-check-interval", s.IPCheckInterval, DefaultIPCheckInterval)
	raw.RetryBackoffMax = nonDefaultDuration("rotation.retry-backoff-max", s.RetryBackoffMax, DefaultRetryBackoffMax)
	return raw
}

func nonDefaultString(name, value, fallback string) string {
	if value == fallback {
		return ""
	}
	return value
}

func nonDefaultDuration(name string, value, fallback time.Duration) string {
	if value == fallback {
		return ""
	}
	return value.String()
}

// warmPoolFromSettings renders warm-pool settings into the file shape. Only
// non-default bounds are emitted, so enabling the pool does not also freeze
// every default into the document.
func warmPoolFromSettings(w WarmPoolSettings) warmPoolFileConfig {
	raw := warmPoolFileConfig{}
	if w.Enabled {
		enabled := true
		raw.Enabled = &enabled
	}
	raw.MinIdlePerProxy = nonDefaultCount("warm-pool.min-idle-per-proxy", w.MinIdlePerProxy, DefaultWarmMinIdlePerProxy)
	raw.MaxIdlePerProxy = nonDefaultCount("warm-pool.max-idle-per-proxy", w.MaxIdlePerProxy, DefaultWarmMaxIdlePerProxy)
	raw.MaxTotalIdle = nonDefaultCount("warm-pool.max-total-idle", w.MaxTotalIdle, DefaultWarmMaxTotalIdle)
	raw.MaxReplenishConcurrency = nonDefaultCount("warm-pool.max-replenish-concurrency", w.MaxReplenishConcurrency, DefaultWarmMaxReplenishConcurrency)
	raw.MaxReplenishPerRoute = nonDefaultCount("warm-pool.max-replenish-per-route", w.MaxReplenishPerRoute, DefaultWarmMaxReplenishPerRoute)
	raw.IdleTTL = nonDefaultDuration("warm-pool.idle-ttl", w.IdleTTL, DefaultWarmIdleTTL)
	return raw
}

// nonDefaultCount emits a count only when it differs from its default. Absent
// is how the file shape spells "use the default", and `any` is what lets the
// runtime parser reject a fractional value.
func nonDefaultCount(name string, value, fallback int) any {
	if value == fallback {
		return nil
	}
	return value
}

// routingFromRouter renders the compiled routing policy back into the file
// shape. The compiled router holds normalized patterns and resolved candidate
// sets; this renders the configured policy the operator wrote, so a round trip
// does not freeze one particular normalization into the document.
//
// A nil Router — the unrestricted policy — renders as an absent block, which is
// exactly how the file config spells "no routing block".
func routingFromRouter(r *routing.Router) *routingFileConfig {
	// A nil router means no block, so the presence flag is what distinguishes
	// "unrestricted" from "configured to fail closed" (an empty block). The
	// compiler cannot report which one it was built from, so the distinction is
	// carried by a non-nil router alone: a compiled router always exists for a
	// configured block, and routingFromRouter is only ever called for one.
	spec := r.Configure()
	raw := &routingFileConfig{}
	for _, rule := range spec.Rules {
		raw.Rules = append(raw.Rules, routingRuleFileConfig{
			Match:  routingMatchFileConfig{Domains: rule.Domains},
			Routes: rule.Routes,
		})
	}
	// default-routes is emitted only when the operator configured one: an
	// absent key and an empty list mean different things (unmatched targets get
	// no candidate set versus an explicitly empty default set), and Compile
	// rejects the empty spelling, so writing one would produce a document that
	// does not decode.
	if len(spec.DefaultRoutes) > 0 {
		routes := spec.DefaultRoutes
		raw.DefaultRoutes = routes
	}
	return raw
}

// MarshalDocument converts a validated RuntimeConfig into a durable, versioned
// document. It is the write-side counterpart of RuntimeFromDocument.
func MarshalDocument(cfg *RuntimeConfig) ([]byte, error) { return marshalDocument(cfg) }

// DecodeDocument parses a durable configuration document into the validated
// RuntimeConfig the gateway serves from.
//
// It is total: on success the result satisfies every rule the file config
// enforces, so a document that decodes is one the gateway can serve, and one
// that does not is one that never reaches the serving path. Unknown keys are
// rejected exactly as the file config rejects them, which is what keeps a
// retired key (global:, weight:, balance:) failing through both paths.
//
// Errors never quote the document. Route lines carry credentials and
// rotate-API headers carry provider tokens, so a message names the offending
// field and the index to fix, and nothing else — the same rule the file
// config's parse errors follow.
func DecodeDocument(data []byte) (*RuntimeConfig, error) {
	if len(data) == 0 {
		return nil, errors.New("config document is empty")
	}
	return RuntimeFromDocument(data)
}

// RuntimeFromDocument converts raw durable document bytes into a validated
// RuntimeConfig. It is the single funnel every durable read goes through, and
// it delegates rather than reimplements: the document is decoded into the file
// shape and then handed to the same runtimeFromFile the YAML path uses, so
// route parsing, the routing-block compiler, rotation validation, warm-pool
// validation, and the cross-cutting config validation are one implementation,
// not two that can drift.
//
// The document version is checked before anything is decoded, so an unknown
// version — too new, or one this build never had — is refused rather than
// partially understood.
func RuntimeFromDocument(data []byte) (*RuntimeConfig, error) {
	var doc documentFileConfig
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(&doc); err != nil {
		// The decode error would quote the offending bytes, so it is reduced to
		// its own kind: a malformed document is not reported with its content.
		return nil, fmt.Errorf("decode config document: %s", jsonErrorKind(err))
	}
	// One trailing value would mean the document is a stream, not one object —
	// refused so a truncated-then-appended document can never parse as valid.
	if decoder.More() {
		return nil, errors.New("config document must be exactly one JSON object")
	}
	switch {
	case doc.Version < 1:
		return nil, fmt.Errorf("config document version must be at least 1, got %d", doc.Version)
	case doc.Version > DocumentVersion:
		// Refusing is the safe direction: this build cannot know which
		// validations a newer shape adds, so serving it would validate less
		// than the writer did.
		return nil, fmt.Errorf("config document version %d is newer than this build supports (%d): upgrade the gateway", doc.Version, DocumentVersion)
	}
	// An unknown key in the document is a rejected document, not an ignored
	// one — the same strictness the YAML path gets from UnmarshalExact, and the
	// reason a retired key cannot survive a move to durable storage.
	if unknown := unknownJSONKeys(data); len(unknown) > 0 {
		return nil, fmt.Errorf("config document has unknown fields: %s", describeUnknownKeys(unknown))
	}
	// JSON has one numeric type, so encoding/json hands every number over as
	// float64 — including a whole one. The runtime parsers downstream expect
	// the int that YAML decoding produces (parseMaxRetries, parseWarmCount,
	// parseMaxConcurrent), and refusing every document for that reason would
	// break the anti-coercion rules those checks exist to enforce. A float64
	// holding an exact whole number is therefore narrowed back to int here, and
	// anything fractional or out of range is left alone so the existing check —
	// not this one — is what rejects it.
	normalizeDocumentNumbers(&doc)
	cfg, err := runtimeFromFile(fileConfig{
		LogLevel:    doc.LogLevel,
		MaxRetries:  doc.MaxRetries,
		Cooldown:    doc.Cooldown,
		DialTimeout: doc.DialTimeout,
		Rotation:    doc.Rotation,
		Proxies:     doc.Proxies,
		WarmPool:    doc.WarmPool,
		Routing:     doc.Routing,
	})
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

// normalizeDocumentNumbers narrows the whole-valued float64 numbers
// encoding/json produces into the int values the runtime config's own parsers
// require. It touches every field whose parser demands a whole number: the
// max-retries budget, the warm-pool counts, and the rotation concurrency.
//
// The narrowing is deliberately narrow. A float64 that is not exactly a whole
// number in int range keeps its type, so the existing "must be a whole number"
// or "must be a count or a percent" error fires — a document cannot buy its way
// past those checks by being JSON.
func normalizeDocumentNumbers(doc *documentFileConfig) {
	if n, ok := wholeInt(doc.MaxRetries); ok {
		doc.MaxRetries = n
	}
	if n, ok := wholeInt(doc.WarmPool.MinIdlePerProxy); ok {
		doc.WarmPool.MinIdlePerProxy = n
	}
	if n, ok := wholeInt(doc.WarmPool.MaxIdlePerProxy); ok {
		doc.WarmPool.MaxIdlePerProxy = n
	}
	if n, ok := wholeInt(doc.WarmPool.MaxTotalIdle); ok {
		doc.WarmPool.MaxTotalIdle = n
	}
	if n, ok := wholeInt(doc.WarmPool.MaxReplenishConcurrency); ok {
		doc.WarmPool.MaxReplenishConcurrency = n
	}
	if n, ok := wholeInt(doc.WarmPool.MaxReplenishPerRoute); ok {
		doc.WarmPool.MaxReplenishPerRoute = n
	}
	if n, ok := wholeInt(doc.Rotation.MaxConcurrent); ok {
		doc.Rotation.MaxConcurrent = n
	}
}

// wholeInt narrows a decoded JSON number to an int only when it is an exact
// whole number inside int's range. Anything else returns false and leaves the
// value untouched for the existing validation to reject.
func wholeInt(raw any) (int, bool) {
	f, ok := raw.(float64)
	if !ok {
		return 0, false
	}
	if f != math.Trunc(f) {
		return 0, false
	}
	if f < math.MinInt || f > math.MaxInt {
		return 0, false
	}
	return int(f), true
}

// jsonErrorKind reduces a JSON decoding failure to a description that cannot
// quote document content. A malformed document is reported as a malformed
// document, and the operator reads the value they wrote.
func jsonErrorKind(err error) string {
	var syntax *json.SyntaxError
	if errors.As(err, &syntax) {
		return "malformed JSON at byte " + strconv.FormatUint(uint64(syntax.Offset), 10)
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) {
		// Field and Value are structural (a key name and a Go type name); the
		// offending value itself is not quoted.
		return fmt.Sprintf("field %q must be %s", typeErr.Field, typeErr.Type)
	}
	return "malformed JSON"
}
