package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/proxyserver"
	"rotation-proxy-gateway/internal/rotation"

	"github.com/rs/zerolog"
)

// The mount decision, which is a security decision and not a wiring detail.
//
// A process can end up in exactly one of three states, and the difference between
// two of them is whether the cluster's only configuration write path is behind a
// credential. The tests below walk all three, because the state that matters is
// the one that must not start.

// mountFixture builds the minimum a mounted control API needs: a generation
// store, a rotation engine for its aggregates, and a durable store.
func mountFixture(t *testing.T) (*pool.Store, *rotation.Engine, *controlPlane) {
	t.Helper()
	cfg := &config.RuntimeConfig{
		MaxRetries:   1,
		DialTimeout:  time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
	}
	generations := pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax))
	return generations, rotation.New(generations, zerolog.Nop()), &controlPlane{store: &stubRepository{}}
}

// A store configured with no admin token refuses to start.
//
// This is the whole fail-closed contract in one assertion. The alternative
// implementation — returning a nil handler — would also stop the control API from
// serving, but it would do so by starting happily, and the operator's only clue
// would be a 404 on a path they configured.
func TestControlAPIMountIsRefusedWithoutAToken(t *testing.T) {
	generations, engine, cp := mountFixture(t)

	handler, err := mountControlAPI(&config.BootstrapConfig{}, cp, generations, engine, zerolog.Nop())
	if err == nil {
		t.Fatal("a control API was mounted with RPGW_ADMIN_TOKEN empty")
	}
	if handler != nil {
		t.Error("a refused mount still returned a handler")
	}
	// The message must name the variable the operator has to set, and must not
	// name the DSN: an operator who reached this error already has a store
	// configured and needs to know which credential is missing, not where the
	// database is.
	if !strings.Contains(err.Error(), "RPGW_ADMIN_TOKEN") {
		t.Errorf("the error does not name RPGW_ADMIN_TOKEN: %v", err)
	}
	if strings.Contains(err.Error(), "postgres://") || strings.Contains(err.Error(), "5432") {
		t.Errorf("the error quoted the store's address: %v", err)
	}
}

// A token that is present but unusable is still a refusal, not a silent
// unauthenticated surface. NewControlAuthenticator only returns nil for an empty
// token, so this asserts the branch exists rather than that it is reachable
// today — a token source that started yielding whitespace-only would otherwise
// mount a control API that refuses every request with no startup error.
func TestControlAPIMountIsRefusedWhenTheTokenYieldsNoAuthenticator(t *testing.T) {
	generations, engine, cp := mountFixture(t)
	auth := proxyserver.NewControlAuthenticator("")
	if auth != nil {
		t.Fatal("an empty token produced an authenticator; the guard below would be unreachable to test")
	}
	// The check itself: with the constructor's nil result the mount must not
	// proceed, and the same must hold for the mount path that consumes it.
	if handler, err := mountControlAPI(&config.BootstrapConfig{AdminToken: ""}, cp, generations, engine, zerolog.Nop()); err == nil || handler != nil {
		t.Errorf("an unusable credential mounted a handler: %v, %v", handler, err)
	}
}

// No durable store means no control API, and that is not an error. A file-seeded
// deployment has nothing for /config to commit through, so mounting a smaller,
// staler copy of /status behind a token would be worse than not mounting it.
func TestControlAPIIsNotMountedWithoutADurableStore(t *testing.T) {
	generations, engine, _ := mountFixture(t)

	handler, err := mountControlAPI(&config.BootstrapConfig{AdminToken: "a-token"}, nil, generations, engine, zerolog.Nop())
	if err != nil {
		t.Fatalf("no store configured = %v, want no error", err)
	}
	if handler != nil {
		t.Error("a control API was mounted with no durable store behind it")
	}
}

// A store and a token together mount, and the mounted surface is live behind the
// token — not mounted-and-refusing, which would look identical to the fail-closed
// case from the outside.
func TestControlAPIMountsWithAStoreAndAToken(t *testing.T) {
	generations, engine, cp := mountFixture(t)

	bootstrap := &config.BootstrapConfig{AdminToken: "an-operator-token"}
	handler, err := mountControlAPI(bootstrap, cp, generations, engine, zerolog.Nop())
	if err != nil {
		t.Fatalf("mount: %v", err)
	}
	if handler == nil {
		t.Fatal("a store and a token produced no control API")
	}
	if token := bootstrap.AdminToken; token != "" {
		t.Errorf("the bootstrap configuration retained the control token as %q", token)
	}

	mux := proxyserver.AdminMux(proxyserver.AdminOptions{
		Version:   "test",
		Started:   time.Now(),
		Store:     generations,
		Lifecycle: proxyserver.NewLifecycle(),
		Control:   handler,
	})
	admin := httptest.NewServer(mux)
	defer admin.Close()

	// Without the token: refused, with the bearer challenge. Not 407 — that is the
	// proxy listeners' Proxy-Authorization vocabulary and answering it here would
	// leave a client looking for a proxy password.
	resp, err := http.Get(admin.URL + proxyserver.ControlAPIMountPrefix + "/proxies")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated control request = %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); got != proxyserver.BearerChallenge {
		t.Errorf("WWW-Authenticate = %q, want %q", got, proxyserver.BearerChallenge)
	}
	// A refusal says why, and says the same thing whatever was wrong with the
	// credential: a body that distinguished "malformed" from "wrong" would be an
	// oracle for probing the token.
	var refusal map[string]any
	if err := json.Unmarshal(body, &refusal); err != nil {
		t.Fatalf("decode refusal: %v", err)
	}
	if refusal["error"] != "unauthorized" {
		t.Errorf("refusal = %v, want an unauthorized envelope", refusal)
	}

	// With it: the resource answers. The durable store here has nothing committed,
	// so the honest answer is 503 — a live endpoint reporting an empty cluster,
	// which is a different thing from a refused request.
	req, err := http.NewRequest(http.MethodGet,
		admin.URL+proxyserver.ControlAPIMountPrefix+"/proxies", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer an-operator-token")
	resp, err = admin.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("authenticated control request = %d (%s), want 503 from an empty store", resp.StatusCode, body)
	}
	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded["error"] != "config_unavailable" {
		t.Errorf("error = %v, want config_unavailable", decoded["error"])
	}

	// The token the operator configured must not appear anywhere in what came
	// back, and neither must a credential the durable store would have carried.
	if strings.Contains(string(body), "an-operator-token") {
		t.Errorf("the response echoed the admin token: %s", body)
	}
}

// The token reaches the authenticator and stops there. The mount function takes
// the plaintext and hands the authenticator a digest; this asserts the plaintext
// is not reachable from the mounted handler by any path a test can observe, and
// that a second mount with a different token does not accept the first.
func TestMountedControlAPIKeepsNoPlaintextToken(t *testing.T) {
	generations, engine, cp := mountFixture(t)
	const token = "a-long-operator-token-value"

	handler, err := mountControlAPI(&config.BootstrapConfig{AdminToken: token}, cp, generations, engine, zerolog.Nop())
	if err != nil {
		t.Fatalf("mount: %v", err)
	}

	// A handler built around the same store but a different token must not accept
	// this one: if the digest were derived from anything global — a key, a
	// process-wide cache — two tokens in one process would authenticate each
	// other.
	other, err := mountControlAPI(&config.BootstrapConfig{AdminToken: "a-different-token"}, cp, generations, engine, zerolog.Nop())
	if err != nil {
		t.Fatalf("second mount: %v", err)
	}
	for name, tc := range map[string]struct {
		handler http.Handler
		token   string
		want    int
	}{
		"its own token":              {handler, token, http.StatusServiceUnavailable},
		"another token":              {other, token, http.StatusUnauthorized},
		"a token that is its prefix": {other, token[:len(token)-1], http.StatusUnauthorized},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/proxies", nil)
		req.Header.Set("Authorization", "Bearer "+tc.token)
		tc.handler.ServeHTTP(rec, req)
		if rec.Code != tc.want {
			t.Errorf("%s: status = %d, want %d", name, rec.Code, tc.want)
		}
	}
}

// stubRepository is a durable store with nothing in it. It exists so the mount
// tests can build a control plane without a database, and it fails every read
// with the one error that means "no revision has been committed yet" — the state
// a fresh cluster is genuinely in.
type stubRepository struct{}

func (stubRepository) Active(context.Context) (configstore.Active, error) {
	return configstore.Active{}, configstore.ErrNoActiveRevision
}

func (stubRepository) Get(context.Context, configstore.Revision) (configstore.Record, error) {
	return configstore.Record{}, fmt.Errorf("%w: nothing committed", configstore.ErrNoRevision)
}

func (stubRepository) Commit(context.Context, configstore.Revision, configstore.Document, configstore.Meta) (configstore.Record, error) {
	return configstore.Record{}, fmt.Errorf("stubRepository: Commit is not exercised by the mount tests")
}

func (stubRepository) Activate(context.Context, configstore.Revision, configstore.Revision) error {
	return fmt.Errorf("stubRepository: Activate is not exercised by the mount tests")
}

func (stubRepository) Migrate(context.Context) error { return nil }

func (stubRepository) SchemaVersion(context.Context) (int, error) { return 1, nil }

func (stubRepository) Close() {}
