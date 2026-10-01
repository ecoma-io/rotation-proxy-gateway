package controlapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/proxyserver"
	"rotation-proxy-gateway/internal/sanitize"

	"github.com/rs/zerolog"
)

// The control API's tests are about its three guarantees: the token is a
// boundary, no secret leaves the process, and nothing is ever invented.

// --- test doubles ----------------------------------------------------------

// fakeStore is an in-memory Repository.
//
// It mirrors internal/control's own fake rather than importing it, because that
// one is unexported and a test double shared across packages by export would be
// a production dependency on a test artifact. What matters is that it can be
// made to do the two things a real store does that the API must handle: refuse
// a write whose expectation is stale, and be unreadable.
type fakeStore struct {
	mu     sync.Mutex
	active *configstore.Active
	// committed accumulates every appended revision, so a test can assert a
	// rejected write left no trace — the property that makes a 412 safe.
	committed []configstore.Revision
	next      int64

	readErr   error
	commitErr error
}

func newFakeStore() *fakeStore { return &fakeStore{next: 1} }

// seedActive installs a revision without appending one.
//
// A seeded revision has no history behind it, so the next commit must not reuse
// its number: two records sharing a revision would make "the client expected 7
// and got 8" true by accident and a mismatch indistinguishable from a success.
func (s *fakeStore) seedActive(doc configstore.Document, revision configstore.Revision) {
	s.setActive(doc, revision)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.next = int64(revision) + 1
}

func (s *fakeStore) Active(context.Context) (configstore.Active, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.readErr != nil {
		return configstore.Active{}, s.readErr
	}
	if s.active == nil {
		return configstore.Active{}, configstore.ErrNoActiveRevision
	}
	return *s.active, nil
}

func (s *fakeStore) setActive(doc configstore.Document, revision configstore.Revision) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active = &configstore.Active{Record: configstore.Record{
		Revision:   revision,
		DocVersion: doc.Version,
		Document:   doc.JSON,
	}}
}

func (s *fakeStore) Get(_ context.Context, revision configstore.Revision) (configstore.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.active.Revision != revision {
		return configstore.Record{}, fmt.Errorf("%w: %d", configstore.ErrNoRevision, int64(revision))
	}
	return s.active.Record, nil
}

// Commit mirrors the store's contract exactly: a valid expectation makes the
// pointer move conditional, and a mismatch appends nothing. The API's 412/428
// mapping is only meaningful if the fake is this strict — a fake that accepted
// any expectation would let a broken mapping pass its test.
func (s *fakeStore) Commit(_ context.Context, expected configstore.Revision, doc configstore.Document, meta configstore.Meta) (configstore.Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.commitErr != nil {
		return configstore.Record{}, s.commitErr
	}
	if expected.IsValid() && (s.active == nil || s.active.Revision != expected) {
		return configstore.Record{}, configstore.ErrRevisionMismatch
	}
	revision := configstore.Revision(s.next)
	s.next++
	s.active = &configstore.Active{Record: configstore.Record{
		Revision:   revision,
		DocVersion: doc.Version,
		Document:   doc.JSON,
		Author:     meta.Author,
		Note:       meta.Note,
	}}
	s.committed = append(s.committed, revision)
	return s.active.Record, nil
}

func (s *fakeStore) Activate(_ context.Context, expected, target configstore.Revision) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active == nil || s.active.Revision != expected {
		return configstore.ErrRevisionMismatch
	}
	s.active.Revision = target
	return nil
}

func (s *fakeStore) Migrate(context.Context) error { return nil }

func (s *fakeStore) SchemaVersion(context.Context) (int, error) { return 1, nil }

func (s *fakeStore) Close() {}

func (s *fakeStore) committedRevisions() []configstore.Revision {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]configstore.Revision(nil), s.committed...)
}

// tokenAuth is an Authenticator standing in for the real one. The real
// authenticator's refusals are tested in internal/proxyserver; what matters here
// is that the API puts every resource behind whatever it is handed, including a
// nil.
type tokenAuth struct{ token string }

func (a tokenAuth) Authorized(r *http.Request) bool {
	if a.token == "" {
		return false
	}
	return r.Header.Get("Authorization") == "Bearer "+a.token
}

// --- fixtures --------------------------------------------------------------

const (
	testToken   = "control-token-for-tests"
	testAuthor  = "operator@example.com"
	routeSecret = "s3cr3t-route-password"
	rotateToken = "rotate-api-token-value"
	proxySecret = "inbound-account-password"
)

var testDocument = []byte(`{
  "version": 1,
  "log-level": "info",
  "max-retries": 2,
  "cooldown": {"base": "5s", "max": "5m"},
  "dial-timeout": "10s",
  "rotation": {
    "max-concurrent": "50%",
    "ip-check-url": "https://ip.example.com/check?token=` + rotateToken + `",
    "ip-check-timeout": "20s",
    "ip-check-interval": "5s",
    "drain-timeout": "20s",
    "retry-backoff-max": "30m",
    "rotate-on-start": true
  },
  "proxies": {
    "auto": [{"id": "auto-route", "proxy": "auto-user:` + routeSecret + `@auto.example.com:1080", "kind": "v4"}],
    "manual": [{
      "id": "manual-route",
      "proxy": "manual-user:` + routeSecret + `@manual.example.com:1080",
      "kind": "v6",
      "rotate-interval": "30m",
      "api": {
        "url": "https://api.example.com/rotate",
        "method": "POST",
        "headers": {"Authorization": "Bearer ` + rotateToken + `"},
        "body": "{\"session\":\"` + rotateToken + `\"}",
        "timeout": "15s"
      }
    }]
  },
  "warm-pool": {"enabled": true, "max-total-idle": 12},
  "routing": {
    "rules": [{"match": {"domains": ["api.example.com"]}, "routes": ["auto-route"]}],
    "default-routes": ["auto-route"]
  }
}`)

// servedConfig builds a running configuration carrying the same secrets, so the
// endpoints that read the serving generation are exercised against real
// credentials rather than an empty pool.
func servedConfig(t *testing.T) *config.RuntimeConfig {
	t.Helper()
	cfg, err := configstore.Decode(configstore.Document{Version: config.DocumentVersion, JSON: testDocument})
	if err != nil {
		t.Fatalf("test document does not decode: %v", err)
	}
	return cfg
}

type harness struct {
	mux   http.Handler
	store *fakeStore
	srv   *httptest.Server
}

func newHarness(t *testing.T, cfg *config.RuntimeConfig) *harness {
	t.Helper()
	store := newFakeStore()
	store.seedActive(configstore.Document{Version: config.DocumentVersion, JSON: testDocument}, 7)
	generations := pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax))
	mux := New(Options{
		Auth:        tokenAuth{token: testToken},
		Generations: generations,
		ConfigStore: store,
		Rotations:   func() uint64 { return 3 },
		IPRevisits:  func() uint64 { return 1 },
		Log:         zerolog.Nop(),
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &harness{mux: mux, store: store, srv: srv}
}

// get issues an authenticated control request.
func (h *harness) get(t *testing.T, path string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	return h.do(t, req)
}

func (h *harness) do(t *testing.T, req *http.Request) (*http.Response, []byte) {
	t.Helper()
	resp, err := h.srv.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func decodeJSON(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode %q: %v", truncate(body), err)
	}
	return out
}

func truncate(b []byte) string {
	if len(b) > 400 {
		return string(b[:400]) + "..."
	}
	return string(b)
}

// --- authentication -------------------------------------------------------

// Every resource is behind the token. The list is walked rather than a single
// endpoint sampled, so a resource added later cannot ship without a test that
// reaches it.
//
// Every spelling of a bad credential gets the same 401, the same challenge, and
// the same body: a response that distinguished "malformed" from "wrong" would be
// an oracle for probing a token one guess at a time.
func TestEveryResourceRequiresTheToken(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	for _, path := range Paths {
		for name, header := range map[string]string{
			"absent":     "",
			"malformed":  "Bearer",
			"non-bearer": "Basic " + testToken,
			"empty":      "Bearer ",
			"wrong":      "Bearer " + testToken + "x",
			"garbage":    "not a credential at all",
		} {
			req, err := http.NewRequest(http.MethodGet, h.srv.URL+path, nil)
			if err != nil {
				t.Fatal(err)
			}
			if header != "" {
				req.Header.Set("Authorization", header)
			}
			resp, body := h.do(t, req)
			if resp.StatusCode != http.StatusUnauthorized {
				t.Errorf("%s credential on GET %s = %d, want 401", name, path, resp.StatusCode)
				continue
			}
			if got := resp.Header.Get("WWW-Authenticate"); got != proxyserver.BearerChallenge {
				t.Errorf("%s credential on GET %s: WWW-Authenticate = %q, want %q", name, path, got, proxyserver.BearerChallenge)
			}
			if got := decodeJSON(t, body)["error"]; got != "unauthorized" {
				t.Errorf("%s credential on GET %s: error = %v, want unauthorized", name, path, got)
			}
			if got := decodeJSON(t, body)["message"]; got != "a valid bearer token is required" {
				t.Errorf("%s credential on GET %s: message = %v, want the same text for every refusal", name, path, got)
			}
		}
	}
}

// The token is not enough to reach a resource with the wrong method: PUT /config
// is the cluster's write path and GET is its read, and the mux — not a handler —
// is what tells them apart.
func TestControlMethodsAreScopedToTheirResources(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	req, err := http.NewRequest(http.MethodPost, h.srv.URL+PathConfig, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	resp, _ := h.do(t, req)
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST /config = %d, want 405", resp.StatusCode)
	}
}

// PUT /config is behind the token too. A write path reachable without one would
// make every other check here cosmetic.
func TestPutConfigRequiresTheToken(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	req, err := http.NewRequest(http.MethodPut, h.srv.URL+PathConfig,
		strings.NewReader(`{"expected_revision":7,"document":{}}`))
	if err != nil {
		t.Fatal(err)
	}
	resp, _ := h.do(t, req)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated PUT /config = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != proxyserver.BearerChallenge {
		t.Errorf("WWW-Authenticate = %q", got)
	}
	if got := h.store.committedRevisions(); len(got) != 0 {
		t.Errorf("a refused write committed %v", got)
	}
}

// A nil authenticator refuses everything rather than authenticating everything.
// This is the second lock on the fail-closed door, and the one that survives a
// future mount site that forgets the startup check.
func TestNilAuthenticatorRefusesEveryResource(t *testing.T) {
	store := newFakeStore()
	store.seedActive(configstore.Document{Version: config.DocumentVersion, JSON: testDocument}, 7)
	cfg := servedConfig(t)
	mux := New(Options{
		Generations: pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax)),
		ConfigStore: store,
		Log:         zerolog.Nop(),
	})
	for _, path := range Paths {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s with no authenticator = %d, want 401", path, rec.Code)
		}
	}
}

// A 401 must carry no-store like every other control response: a cached refusal
// is still a refusal an intermediary can serve on the process's behalf.
func TestUnauthorizedResponsesAreNotCacheable(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	for _, path := range Paths {
		resp, _ := h.get(t, path)
		if got := resp.Header.Get("Cache-Control"); got != "no-store" {
			t.Errorf("GET %s Cache-Control = %q, want no-store", path, got)
		}
	}
}

// The correlation id is echoed only when this process would accept it, and no
// control header is ever forwarded onward.
//
// The refused ids are driven straight into the mux through a recorder rather than
// over a live connection. That is not a shortcut: net/http's client refuses to
// *send* a header value carrying a newline or a control byte, so a client-borne
// request could never present `"quoted"` or an escape sequence at all. Testing
// them through the transport would assert only that the transport rejects them.
func TestCorrelationIDIsEchoedAndControlHeadersConsumed(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	for name, tc := range map[string]struct{ sent, echoed string }{
		"accepted id":  {"trace-abc_1.2:3", "trace-abc_1.2:3"},
		"unsafe id":    {"\"quoted\"", ""},
		"over-long id": {strings.Repeat("a", 200), ""},
		"escape in id": {"abc\x1b[31m", ""},
	} {
		// Built by hand: httptest.NewRequest stores the value verbatim, while
		// http.NewRequest would refuse to hand a live client something unsendable.
		req := &http.Request{
			Method: http.MethodGet,
			URL:    parsedURL(t, h.srv.URL+PathProxies),
			Header: http.Header{
				"Authorization":      []string{"Bearer " + testToken},
				"X-Ecoma-Request-Id": []string{tc.sent},
			},
		}
		rec := httptest.NewRecorder()
		h.mux.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", name, rec.Code)
		}
		if got := rec.Header().Get("X-Ecoma-Request-Id"); got != tc.echoed {
			t.Errorf("%s: echoed correlation id = %q, want %q", name, got, tc.echoed)
		}
	}

	// A control header is consumed, never echoed, whatever it says. Echoing one
	// back would tell a caller its value was honored by an endpoint that has no
	// such notion.
	//
	// The request id is excluded, and that is not an oversight: it is the one
	// x-ecoma-* header this API deliberately echoes, under the rules above. Its
	// grammar admits no "v6" — the echo grammar is [A-Za-z0-9-_.:] — so an
	// unaccepted value is dropped rather than reflected.
	for _, name := range []string{"X-Ecoma-Proxy-Family", "X-Ecoma-Unknown-Control", "X-Ecoma-Forwarded"} {
		req, err := http.NewRequest(http.MethodGet, h.srv.URL+PathProxies, nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set(name, "v6")
		resp, _ := h.do(t, req)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("%s: status = %d, want 200", name, resp.StatusCode)
		}
		if got := resp.Header.Get(name); got != "" {
			t.Errorf("%s: the control header was echoed back as %q", name, got)
		}
	}
}

func parsedURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// --- the secret sweep ------------------------------------------------------

// forbidden is every credential this deployment is built with. None of them may
// appear in any response, on any resource, on any status path.
var forbidden = []string{
	routeSecret,
	"auto-user",
	"manual-user",
	rotateToken,
	proxySecret,
	"api.example.com/rotate",
	"ip.example.com/check",
	"Bearer rotate",
	testToken,
}

// sweep drives every resource through every status path a client can reach and
// fails on any forbidden substring in the raw response bytes or in what the
// request carried onward.
//
// The raw-bytes check is the one that matters. A JSON view can be safe in the
// fields someone thought about and unsafe in the one they did not, so this
// looks at the bytes rather than at a decoded struct.
func TestNoEndpointEmitsCredentials(t *testing.T) {
	cfg := servedConfig(t)
	h := newHarness(t, cfg)

	// Bodies chosen to exercise the failure paths as well as the success paths:
	// an empty store, a stale expectation, an invalid document, an oversized
	// body, and a store that cannot be read. Every one of those reaches
	// failStore, fail, or failPrecondition, and every one of those formats text.
	h.store.mu.Lock()
	h.store.active = nil
	h.store.mu.Unlock()

	requests := []struct {
		method, path, body string
	}{
		{http.MethodGet, PathProxies, ""},
		{http.MethodGet, PathRoutes, ""},
		{http.MethodGet, PathRoutingRules, ""},
		{http.MethodGet, PathRotations, ""},
		{http.MethodGet, PathConfig, ""},
		{http.MethodGet, PathAnalytics, ""},
		{http.MethodGet, PathConfig + "/../../etc/passwd", ""},
		{http.MethodGet, "/nope", ""},
		{http.MethodPut, PathConfig, `{"expected_revision":0,"document":{}}`},
		{http.MethodPut, PathConfig, `{"expected_revision":7,"document":{"version":1,"proxies":{"auto":[{"proxy":"auto-user:` + routeSecret + `@x.example.com:1"}]}}}`},
		{http.MethodPut, PathConfig, "not json"},
		{http.MethodPut, PathConfig, strings.Repeat("x", maxRequestBytes+1)},
		{http.MethodPost, PathConfig, "{}"},
		{http.MethodDelete, PathProxies, ""},
	}

	for _, tc := range requests {
		var body io.Reader
		if tc.body != "" {
			body = strings.NewReader(tc.body)
		}
		req, err := http.NewRequest(tc.method, h.srv.URL+tc.path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+testToken)
		req.Header.Set("X-Ecoma-Request-Id", "sweep-1")
		resp, raw := h.do(t, req)
		assertNoSecrets(t, fmt.Sprintf("%s %s -> %d", tc.method, tc.path, resp.StatusCode), raw)
	}

	// And the same sweep with a populated store, so the success paths are
	// covered too — an error path that is careful and a success path that is not
	// is the usual way a credential leaks.
	h.store.seedActive(configstore.Document{Version: config.DocumentVersion, JSON: testDocument}, 7)
	for _, tc := range requests {
		var body io.Reader
		if tc.body != "" {
			body = strings.NewReader(tc.body)
		}
		req, err := http.NewRequest(tc.method, h.srv.URL+tc.path, body)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, raw := h.do(t, req)
		assertNoSecrets(t, "populated "+fmt.Sprintf("%s %s -> %d", tc.method, tc.path, resp.StatusCode), raw)
	}
}

func assertNoSecrets(t *testing.T, what string, body []byte) {
	t.Helper()
	for _, secret := range forbidden {
		if strings.Contains(string(body), secret) {
			t.Errorf("%s: response contains %q:\n%s", what, secret, truncate(body))
		}
	}
}

// The admin token is a credential too: a response that echoed it would hand it
// to anything that could reach the admin port.
func TestControlTokenNeverAppearsInAResponse(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	for _, path := range Paths {
		_, body := h.get(t, path)
		if strings.Contains(string(body), testToken) {
			t.Errorf("GET %s echoed the control token:\n%s", path, truncate(body))
		}
	}
}

// The rotate API's URL, headers, and body are reported as "configured" and
// nothing more. This asserts the specific absences by name, because "the sweep
// found nothing" does not tell a reader which field was checked.
//
// The credential sweep already covers the bytes; what this adds is that the
// manual route really does report the flag — an endpoint that dropped the field
// entirely would pass a pure absence check while telling an operator nothing about
// which routes can rotate.
func TestRotateAPIMaterialIsReducedToConfigured(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	_, body := h.get(t, PathProxies)
	got := decodeJSON(t, body)

	proxies, _ := got["proxies"].([]any)
	if len(proxies) != 2 {
		t.Fatalf("proxies = %v, want two routes", proxies)
	}
	configured := 0
	for _, raw := range proxies {
		proxy, _ := raw.(map[string]any)
		for _, key := range []string{"api", "apiURL", "headers", "body", "method"} {
			if _, present := proxy[key]; present {
				t.Errorf("%v exposed %q", proxy["id"], key)
			}
		}
		// The endpoint is host:port, never the userinfo form.
		if endpoint, _ := proxy["proxy"].(string); strings.Contains(endpoint, "@") {
			t.Errorf("route endpoint carries userinfo: %q", endpoint)
		}
		switch proxy["rotateAPIConfigured"] {
		case true:
			configured++
			if proxy["id"] != "manual-route" {
				t.Errorf("an auto route reported a rotate API: %v", proxy)
			}
		case nil, false:
		default:
			t.Errorf("rotateAPIConfigured = %v, want a bool", proxy["rotateAPIConfigured"])
		}
	}
	if configured != 1 {
		t.Errorf("%d routes reported a rotate API, want exactly the manual one", configured)
	}
}

// ip-check-url can carry a provider token in its query string, so it is not
// reported even though it is "just a URL".
func TestIPCheckURLIsNotReported(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	for _, path := range []string{PathRotations, PathConfig} {
		_, body := h.get(t, path)
		if strings.Contains(string(body), "ip.example.com") || strings.Contains(string(body), "check?token") {
			t.Errorf("GET %s reported the ip-check-url:\n%s", path, truncate(body))
		}
		settings := settingsFrom(t, body)
		for _, s := range settings {
			if s["name"] == "ip-check-url" {
				t.Errorf("GET %s reported an ip-check-url setting: %v", path, s)
			}
		}
	}
}

func settingsFrom(t *testing.T, body []byte) []map[string]any {
	t.Helper()
	var raw struct {
		Settings []map[string]any `json:"settings"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatalf("decode settings: %v", err)
	}
	return raw.Settings
}

// --- nothing invented -----------------------------------------------------

// /analytics answers 501 with an explicit unavailability, not an empty series.
// An empty result for a resource that was never measured is indistinguishable
// from one that measured nothing.
func TestAnalyticsReportsUnavailableRatherThanEmpty(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	resp, body := h.get(t, PathAnalytics)
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("GET /analytics = %d, want 501", resp.StatusCode)
	}
	got := decodeJSON(t, body)
	if got["available"] != false || got["error"] != "not_available" {
		t.Errorf("GET /analytics body = %v, want an explicit not_available", got)
	}
	if _, present := got["series"]; present {
		t.Error("GET /analytics returned a series for a resource it never measured")
	}
}

// A rotation aggregate with no engine behind it is omitted, not zero: a zero
// would claim the engine ran and rotated nothing.
func TestAbsentRotationAggregatesAreOmittedNotZero(t *testing.T) {
	store := newFakeStore()
	store.seedActive(configstore.Document{Version: config.DocumentVersion, JSON: testDocument}, 7)
	cfg := servedConfig(t)
	mux := New(Options{
		Auth:        tokenAuth{token: testToken},
		Generations: pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax)),
		ConfigStore: store,
		Log:         zerolog.Nop(),
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, PathRotations, nil))

	var raw struct {
		Rotations  *uint64 `json:"rotations"`
		IPRevisits *uint64 `json:"ipRevisits"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.Rotations != nil || raw.IPRevisits != nil {
		t.Errorf("rotations = %v, ipRevisits = %v, want both absent", raw.Rotations, raw.IPRevisits)
	}
	if strings.Contains(rec.Body.String(), `"rotations":0`) {
		t.Errorf("an unwired aggregate was reported as zero:\n%s", truncate(rec.Body.Bytes()))
	}
}

// An empty store is reported as unpopulated, not as a cluster with no routes.
func TestEmptyStoreIsNotAnEmptyInventory(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	h.store.mu.Lock()
	h.store.active = nil
	h.store.mu.Unlock()

	for _, path := range []string{PathProxies, PathConfig} {
		resp, body := h.get(t, path)
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("GET %s with an empty store = %d, want 503", path, resp.StatusCode)
		}
		if _, present := decodeJSON(t, body)["proxies"]; present {
			t.Errorf("GET %s reported a route inventory for an empty store:\n%s", path, truncate(body))
		}
	}
}

// An unreachable store is 503, distinct from a rejected request. "I could not
// read the cluster" and "the cluster has no routes" must not look the same.
func TestUnreachableStoreIs503(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	h.store.mu.Lock()
	h.store.readErr = fmt.Errorf("dial tcp 10.0.0.1:5432: connection refused")
	h.store.mu.Unlock()

	resp, body := h.get(t, PathProxies)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("GET /proxies with an unreadable store = %d, want 503", resp.StatusCode)
	}
	// The database's own message may name an address; the response must not.
	assertNoSecrets(t, "unreadable store", body)
	if strings.Contains(string(body), "5432") {
		t.Errorf("the response quoted the database address:\n%s", truncate(body))
	}
}

// An absent routing block is the unrestricted policy and is reported as
// configured:false, which is a different configuration from an empty block —
// the fail-closed kill switch.
func TestRoutingRulesDistinguishAbsentFromEmpty(t *testing.T) {
	cfg := servedConfig(t)
	cfg.Routing = nil
	store := newFakeStore()
	store.seedActive(configstore.Document{Version: config.DocumentVersion, JSON: testDocument}, 7)
	mux := New(Options{
		Auth:        tokenAuth{token: testToken},
		Generations: pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax)),
		ConfigStore: store,
		Log:         zerolog.Nop(),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, PathRoutingRules, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /routing-rules = %d, want 200", rec.Code)
	}
	if got := decodeJSON(t, rec.Body.Bytes())["configured"]; got != false {
		t.Errorf("configured = %v, want false for the unrestricted policy", got)
	}
	if _, present := decodeJSON(t, rec.Body.Bytes())["rules"]; present {
		t.Error("an absent routing block was reported as an empty rule list")
	}
}

// --- revision semantics ----------------------------------------------------

// The whole point of expected_revision: a write from a stale expectation is
// refused, appends nothing, and names the revision the client must now read.
func TestStaleExpectationIs412AndAppendsNothing(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	before := len(h.store.committedRevisions())

	resp, body := h.putConfig(t, 3, testDocument)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("PUT /config with a stale expectation = %d, want 412", resp.StatusCode)
	}
	got := decodeJSON(t, body)
	if got["currentRevision"] != float64(7) {
		t.Errorf("currentRevision = %v, want 7 so the client can retry knowingly", got["currentRevision"])
	}
	if got["readable"] != true {
		t.Errorf("readable = %v, want true", got["readable"])
	}
	if after := h.store.committedRevisions(); len(after) != before {
		t.Errorf("a refused write appended %v", after[before:])
	}
}

// A missing expectation is 428, not 412: the client did not attempt a
// conditional write at all, and retrying it unchanged would clobber whatever a
// peer committed. It is 428 rather than 400 because the request is
// well-formed — it is missing a precondition, which is its own condition.
func TestMissingExpectationIs428AndNamesTheCurrentRevision(t *testing.T) {
	for name, body := range map[string]string{
		"absent":   `{"document":` + string(mustJSON(t, testDocument)) + `}`,
		"zero":     `{"expected_revision":0,"document":` + string(mustJSON(t, testDocument)) + `}`,
		"negative": `{"expected_revision":-4,"document":` + string(mustJSON(t, testDocument)) + `}`,
	} {
		h := newHarness(t, servedConfig(t))
		resp, raw := h.do(t, newPutRequest(t, h, body))
		if resp.StatusCode != http.StatusPreconditionRequired {
			t.Errorf("%s: PUT /config = %d, want 428", name, resp.StatusCode)
		}
		got := decodeJSON(t, raw)
		if got["currentRevision"] != float64(7) {
			t.Errorf("%s: currentRevision = %v, want 7", name, got["currentRevision"])
		}
		if n := len(h.store.committedRevisions()); n != 0 {
			t.Errorf("%s: a refused write committed %d revisions", name, n)
		}
	}
}

// A precondition response reports the revision the client must now read, and says
// whether that revision is trustworthy.
//
// The two cases differ in a way an operator depends on: with a readable store the
// named revision is one they can fetch and retry against, while a store that
// could not be read must not present "0" as if the cluster were empty. It says
// readable:false instead, so a retry loop knows to wait rather than to rebase onto
// a revision that does not exist.
//
// One fake serves both cases, because the two responses differ in a way a
// production-path check alone would miss: the store refuses to be read, so the
// write is refused before any revision is named, and the "current" value the
// handler passes to failPrecondition is a zero-valued Active. A handler that
// passed it through unconditionally would report revision 0 as though the cluster
// had an active revision of zero — a client rebasing onto it would be writing
// against something that does not exist.
func TestPreconditionResponseNamesTheCurrentRevisionAndWhetherItIsReadable(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	resp, body := h.putConfig(t, 3, testDocument)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("status = %d, want 412", resp.StatusCode)
	}
	if got := decodeJSON(t, body); got["readable"] != true || got["currentRevision"] != float64(7) {
		t.Errorf("readable store: body = %v, want readable:true and the revision to rebase onto", got)
	}
	if n := len(h.store.committedRevisions()); n != 0 {
		t.Fatalf("the readable-store refusal already committed %d revisions", n)
	}

	// The store now refuses to be read. The write is refused before any revision
	// is named, so the "current" value the handler hands the precondition writer
	// is a zero-valued Active — and a handler that passed it through
	// unconditionally would report revision 0 as though the cluster had an active
	// revision of zero, which a client would then rebase onto.
	h.store.mu.Lock()
	h.store.readErr = fmt.Errorf("connection reset by peer")
	h.store.mu.Unlock()

	resp, body = h.putConfig(t, 4, testDocument)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("unreadable store: status = %d, want 412", resp.StatusCode)
	}
	if got := decodeJSON(t, body); got["readable"] != false || got["currentRevision"] != float64(0) {
		t.Errorf("unreadable store: body = %v, want readable:false and revision 0", got)
	}
	if n := len(h.store.committedRevisions()); n != 0 {
		t.Errorf("the refusal appended revisions: %v", h.store.committedRevisions())
	}
}

// A cluster with no committed revision yet is not an unreadable store, and a
// first write is told which of the two it hit.
//
// This is the case that separates the two precondition statuses from one: with
// nothing active there is no revision to replace, so naming one is a stale
// expectation (412) rather than a missing one (428) — a client must not be told
// "add an expectation" when it already named one that the cluster cannot match.
// What it must never be told is readable:false, which would send it to wait for a
// revision that will never arrive because nobody has committed one.
func TestEmptyStoreIsReadableWithNoActiveRevision(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	h.store.mu.Lock()
	h.store.active = nil
	h.store.mu.Unlock()

	resp, body := h.putConfig(t, 1, testDocument)
	if resp.StatusCode != http.StatusPreconditionFailed {
		t.Fatalf("PUT /config naming a revision against an empty cluster = %d, want 412", resp.StatusCode)
	}
	got := decodeJSON(t, body)
	if got["readable"] != true || got["currentRevision"] != float64(0) {
		t.Errorf("body = %v, want a readable store with no active revision", got)
	}
	if n := len(h.store.committedRevisions()); n != 0 {
		t.Errorf("the refusal committed %d revisions", n)
	}
}

// A matching expectation commits, and the response names the new revision.
func TestMatchingExpectationCommits(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	resp, body := h.putConfig(t, 7, testDocument)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("PUT /config = %d: %s", resp.StatusCode, truncate(body))
	}
	got := decodeJSON(t, body)
	if got["revision"] != float64(8) {
		t.Errorf("revision = %v, want 8", got["revision"])
	}
	if n := len(h.store.committedRevisions()); n != 1 {
		t.Errorf("committed %d revisions, want 1", n)
	}
}

// An invalid document is refused before it is committed, and its error names no
// part of it. A validation error quotes the offending value, and the offending
// value here is a route line carrying a password.
func TestInvalidDocumentIsRefusedWithoutQuotingIt(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	invalid := []byte(`{"version":1,"proxies":{"auto":[{"proxy":"bad-user:` + routeSecret + `@auto.example.com:1080","kind":"v9"}]}}`)

	resp, body := h.putConfig(t, 7, invalid)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT /config with an invalid document = %d, want 400", resp.StatusCode)
	}
	if got := decodeJSON(t, body)["error"]; got != "invalid_config" {
		t.Errorf("error = %v, want invalid_config", got)
	}
	assertNoSecrets(t, "invalid document", body)
	if n := len(h.store.committedRevisions()); n != 0 {
		t.Errorf("an invalid document was committed: %v", h.store.committedRevisions())
	}
}

// A misspelled expected_revision must not become a successful unguarded write.
// That is the whole reason the envelope is decoded strictly.
func TestUnknownEnvelopeFieldIsRefused(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	resp, body := h.do(t, newPutRequest(t, h,
		`{"expected_revison":7,"document":`+string(mustJSON(t, testDocument))+`}`))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("PUT /config with a misspelled field = %d, want 400", resp.StatusCode)
	}
	if n := len(h.store.committedRevisions()); n != 0 {
		t.Errorf("a misspelled field still committed %d revisions", n)
	}
	assertNoSecrets(t, "misspelled field", body)
}

// An over-bound body is 413 rather than a validation failure, so an operator
// sending a large document is told the size was the problem.
func TestOversizedBodyIs413(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	resp, _ := h.putConfig(t, 7, []byte(`{"padding":"`+strings.Repeat("p", maxRequestBytes)+`"}`))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("PUT /config with an oversized body = %d, want 413", resp.StatusCode)
	}
	if n := len(h.store.committedRevisions()); n != 0 {
		t.Errorf("an oversized body committed %d revisions", n)
	}
}

// --- reading the resources -------------------------------------------------

func TestProxiesReportsTheActiveRevision(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	_, body := h.get(t, PathProxies)
	got := decodeJSON(t, body)
	if got["revision"] != float64(7) {
		t.Errorf("revision = %v, want 7", got["revision"])
	}
	proxies, _ := got["proxies"].([]any)
	if len(proxies) != 2 {
		t.Fatalf("proxies = %d, want 2", len(proxies))
	}
	// Auto routes first, then manual — the order AllRoutes uses and the pool's.
	auto, _ := proxies[0].(map[string]any)
	manual, _ := proxies[1].(map[string]any)
	if auto["origin"] != string(config.RouteOriginAuto) || manual["origin"] != string(config.RouteOriginManual) {
		t.Errorf("origins = %v, %v", auto["origin"], manual["origin"])
	}
	if manual["rotateInterval"] != "30m0s" {
		t.Errorf("rotateInterval = %v, want the cadence", manual["rotateInterval"])
	}
}

func TestRoutesReportsTheServingGeneration(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	_, body := h.get(t, PathRoutes)
	got := decodeJSON(t, body)
	// A file-seeded instance serves revision 0; the durable revision is 7. The
	// two must not be conflated, and this is the assertion that says so.
	if got["configRevision"] != float64(0) {
		t.Errorf("configRevision = %v, want 0 (this instance is file-seeded)", got["configRevision"])
	}
	routes, _ := got["routes"].([]any)
	if len(routes) != 2 {
		t.Fatalf("routes = %d, want 2", len(routes))
	}
}

func TestRoutingRulesReportTheCompiledPolicy(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	_, body := h.get(t, PathRoutingRules)
	got := decodeJSON(t, body)
	if got["configured"] != true {
		t.Fatalf("configured = %v, want true", got["configured"])
	}
	rules, _ := got["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("rules = %v, want one", rules)
	}
	rule, _ := rules[0].(map[string]any)
	domains, _ := rule["domains"].([]any)
	if len(domains) != 1 || domains[0] != "api.example.com" {
		t.Errorf("domains = %v", domains)
	}
	defaults, _ := got["defaultRoutes"].([]any)
	if len(defaults) != 1 {
		t.Errorf("defaultRoutes = %v", defaults)
	}
}

func TestRotationsReportTheResolvedConcurrencyCap(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	_, body := h.get(t, PathRotations)
	got := decodeJSON(t, body)
	if got["rotations"] != float64(3) || got["ipRevisits"] != float64(1) {
		t.Errorf("aggregates = %v/%v, want 3/1", got["rotations"], got["ipRevisits"])
	}
	settings := settingsFrom(t, body)
	// One manual route at 50% rounds up to 1, and that is the number the engine
	// uses — not the raw "50%".
	if !hasSetting(settings, "max-concurrent", "1") {
		t.Errorf("max-concurrent not reported as the resolved cap: %v", settings)
	}
	if hasSetting(settings, "max-concurrent-percent", "50") {
		t.Errorf("the raw concurrency knob leaked: %v", settings)
	}
	routes, _ := got["routes"].([]any)
	if len(routes) != 1 {
		t.Fatalf("routes = %v, want the one manual route", routes)
	}
}

// /rotations reports manual routes, and an auto route of the same egress kind
// must not be swept in with them.
//
// Config validation rejects duplicate canonical route URLs, not duplicate kinds,
// so an auto v6 route and a manual v6 route coexist. A report that joined the two
// sides by kind would list the auto route as though it were a rotation
// candidate — and hand it the manual route's id, because the kind map holds one
// spec per kind. Origin is the property that actually distinguishes them.
func TestRotationsReportsOnlyManualRoutesWhenKindsCollide(t *testing.T) {
	doc := []byte(`{
	  "version": 1,
	  "log-level": "info",
	  "max-retries": 2,
	  "cooldown": {"base": "5s", "max": "5m"},
	  "dial-timeout": "10s",
	  "proxies": {
	    "auto": [{"id": "auto-v6", "proxy": "auto.example.com:1080", "kind": "v6"}],
	    "manual": [{
	      "id": "manual-v6",
	      "proxy": "manual.example.com:1080",
	      "kind": "v6",
	      "rotate-interval": "30m",
	      "api": {"url": "https://api.example.com/rotate", "method": "POST", "timeout": "15s"}
	    }]
	  }
	}`)
	cfg, err := configstore.Decode(configstore.Document{Version: config.DocumentVersion, JSON: doc})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	store := newFakeStore()
	store.seedActive(configstore.Document{Version: config.DocumentVersion, JSON: doc}, 7)
	mux := New(Options{
		Auth:        tokenAuth{token: testToken},
		Generations: pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax)),
		ConfigStore: store,
		Log:         zerolog.Nop(),
	})
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, PathRotations, nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s = %d, want 200", PathRotations, rec.Code)
	}
	var raw struct {
		Routes []struct {
			Route string `json:"route"`
			ID    string `json:"id"`
		} `json:"routes"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if len(raw.Routes) != 1 || raw.Routes[0].Route != "manual.example.com:1080" {
		t.Fatalf("rotations routes = %+v, want only the manual route", raw.Routes)
	}
	if raw.Routes[0].ID != "manual-v6" {
		t.Errorf("rotation route id = %q, want the manual route's id", raw.Routes[0].ID)
	}
}

func hasSetting(settings []map[string]any, name, value string) bool {
	for _, s := range settings {
		if s["name"] == name && s["value"] == value {
			return true
		}
	}
	return false
}

// GET /config's document is not editable, and says so. A round-tripped view
// would fail its own decoder, because the route lines would have lost their
// credentials — so a client that assumed otherwise would push a configuration
// that drops every secret in the deployment.
func TestGetConfigDeclaresItsDocumentNonEditable(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	_, body := h.get(t, PathConfig)
	got := decodeJSON(t, body)
	if got["editable"] != false {
		t.Errorf("editable = %v, want false", got["editable"])
	}
	if got["revision"] != float64(7) {
		t.Errorf("revision = %v, want 7", got["revision"])
	}
	cfg, _ := got["config"].(map[string]any)
	if cfg == nil {
		t.Fatalf("no config in the response:\n%s", truncate(body))
	}
	if cfg["logLevel"] != "info" || cfg["maxRetries"] != float64(2) {
		t.Errorf("config = %v", cfg)
	}
}

// Author and note are the one pair of strings a human typed, so they are bounded
// and stripped on the way out.
func TestGetConfigSanitizesAuthorAndNote(t *testing.T) {
	h := newHarness(t, servedConfig(t))
	h.store.mu.Lock()
	h.store.active.Author = "ops\x1b[31m@example.com"
	h.store.active.Note = strings.Repeat("n", sanitizeLimit())
	h.store.mu.Unlock()

	_, body := h.get(t, PathConfig)
	got := decodeJSON(t, body)
	author, _ := got["author"].(string)
	if strings.Contains(author, "\x1b") {
		t.Errorf("author carried an ANSI sequence: %q", author)
	}
	note, _ := got["note"].(string)
	if len(note) > sanitizeLimit() {
		t.Errorf("note length = %d, want it bounded to %d", len(note), sanitizeLimit())
	}
	assertNoSecrets(t, "sanitized author", body)
}

// A rotation state carried into a response has its egress IP canonicalized, so
// an IPv4-mapped IPv6 spelling cannot reach a client as a different address.
func TestRotationIPIsUnmappedInResponses(t *testing.T) {
	if got := unmapped("::ffff:203.0.113.7"); got != "203.0.113.7" {
		t.Errorf("unmapped = %q, want the IPv4 address", got)
	}
	if got := unmapped("2001:db8::1"); got != "2001:db8::1" {
		t.Errorf("unmapped = %q, want the IPv6 address unchanged", got)
	}
	// An unparseable value is dropped rather than passed through: an
	// unparseable string in an IP field is worse than an absent one.
	state := &pool.RotationStatus{State: "stale", LastIP: "not-an-ip", RotationCount: 2}
	if got := rotationWithCanonicalIP(state); got.LastIP != "" {
		t.Errorf("an unparseable IP survived as %q", got.LastIP)
	}
	if state.LastIP != "not-an-ip" {
		t.Error("rotationWithCanonicalIP mutated its input")
	}
}

func unmapped(value string) string {
	state := &pool.RotationStatus{LastIP: value}
	return rotationWithCanonicalIP(state).LastIP
}

// --- no state on the proxy path -------------------------------------------

// The serving path must not consult the control database. A store that fails
// every read still leaves the proxy listeners and /status fully working, which
// is what "no query on the request path" has to mean in practice.
func TestServingPathDoesNotDependOnTheStore(t *testing.T) {
	cfg := servedConfig(t)
	generations := pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax))
	store := &failingStore{}

	// A pool with routes that will never dial still serves: route selection,
	// generation loading, and /status all work with the store refusing every
	// read, because none of them ask it anything.
	if generations.Load().Config != cfg {
		t.Error("the generation store did not return the configuration it was built with")
	}
	if _, err := store.Active(context.Background()); err == nil {
		t.Error("the failing store answered a read")
	}

	// And the admin mux mounts with a control API and a dead store without the
	// unauthenticated endpoints caring.
	// Marked ready so /readyz is 200: its 503 is the readiness contract working,
	// not a dependency on the control database, and a test that left it
	// un-marked would prove nothing either way.
	lc := proxyserver.NewLifecycle()
	lc.MarkReady()
	mux := proxyserver.AdminMux(proxyserver.AdminOptions{
		Version:   "test",
		Started:   time.Now(),
		Store:     generations,
		Lifecycle: lc,
		Control:   New(Options{Auth: tokenAuth{token: testToken}, Generations: generations, ConfigStore: store, Log: zerolog.Nop()}),
	})
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/status with a dead store = %d, want 200", rec.Code)
	}
	for _, path := range []string{"/healthz", "/status"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Errorf("GET %s = %d, want 200 without a token", path, rec.Code)
		}
		if got := rec.Header().Get("WWW-Authenticate"); got != "" {
			t.Errorf("GET %s challenged for a token: %q", path, got)
		}
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("/status Cache-Control = %q, want no-store", got)
	}

	// /readyz is unauthenticated too. Marking the lifecycle ready above is what
	// makes it 200; the assertion is that mounting the control API did not put a
	// challenge in front of the readiness probe, and did not move the state the
	// probe reports.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, proxyserver.ReadyPath, nil))
	if rec.Code != http.StatusOK {
		t.Errorf("GET %s = %d, want 200 without a token", proxyserver.ReadyPath, rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("GET %s challenged for a token: %q", proxyserver.ReadyPath, got)
	}

	// And the control surface really is mounted, so "unauthenticated" above is not
	// an artifact of nothing being registered under /control at all.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, proxyserver.ControlAPIMountPrefix+PathProxies, nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("GET %s%s with no token = %d, want 401", proxyserver.ControlAPIMountPrefix, PathProxies, rec.Code)
	}
	if got := rec.Header().Get("WWW-Authenticate"); got != proxyserver.BearerChallenge {
		t.Errorf("the mounted control API challenged with %q, want the bearer challenge", got)
	}
}

// failingStore refuses every read and write. It exists to prove the claim above
// structurally rather than by inspection.
type failingStore struct{ fakeStore }

func (s *failingStore) Active(context.Context) (configstore.Active, error) {
	return configstore.Active{}, fmt.Errorf("the control database is unreachable")
}

func (s *failingStore) Get(context.Context, configstore.Revision) (configstore.Record, error) {
	return configstore.Record{}, fmt.Errorf("the control database is unreachable")
}

func (s *failingStore) Commit(context.Context, configstore.Revision, configstore.Document, configstore.Meta) (configstore.Record, error) {
	return configstore.Record{}, fmt.Errorf("the control database is unreachable")
}

func (s *failingStore) SchemaVersion(context.Context) (int, error) {
	return 0, fmt.Errorf("unreachable")
}

func (s *failingStore) Activate(context.Context, configstore.Revision, configstore.Revision) error {
	return fmt.Errorf("the control database is unreachable")
}

// --- helpers ---------------------------------------------------------------

func (h *harness) putConfig(t *testing.T, expected int64, doc []byte) (*http.Response, []byte) {
	t.Helper()
	envelope := fmt.Sprintf(`{"expected_revision":%d,"author":%q,"note":"test","document":%s}`,
		expected, testAuthor, mustJSON(t, doc))
	return h.do(t, newPutRequest(t, h, envelope))
}

func newPutRequest(t *testing.T, h *harness, body string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodPut, h.srv.URL+PathConfig, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+testToken)
	req.Header.Set("Content-Type", "application/json")
	return req
}

func mustJSON(t *testing.T, raw []byte) []byte {
	t.Helper()
	// The test document is already JSON; compact it so an envelope built by
	// string concatenation around it is valid.
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		t.Fatalf("compact test document: %v", err)
	}
	return buf.Bytes()
}

// sanitizeLimit is the sanitizer's own bound, imported rather than restated so a
// change to it does not silently turn these assertions into no-ops.
func sanitizeLimit() int { return sanitize.MaxLength }
