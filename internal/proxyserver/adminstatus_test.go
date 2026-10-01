package proxyserver

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/warmpool"
)

// The three-scope split on /status.
//
// Two things have to hold at once and they pull against each other. The scope
// objects are new, so a client needs them; the top-level keys are a published
// wire contract that six test files and the e2e suite decode positionally, so
// they must stay exactly where they are. The split is therefore additive, and the
// tests below assert both halves — the new grouping is present and labelled, and
// every pre-existing key is still present with the value it had.

// statusFixture builds an admin mux whose status document has non-zero values in
// every scope, so a test can tell a present field from an absent one and a
// mislabelled one from a correct one.
func statusFixture(t *testing.T, cluster ClusterStatus) *httptest.Server {
	t.Helper()
	u, err := url.Parse("socks5://user:secret@manual.test:1080")
	if err != nil {
		t.Fatal(err)
	}
	spec := config.RouteSpec{URL: u, Kind: config.EgressV6, Origin: config.RouteOriginManual}
	cfg := &config.RuntimeConfig{
		MaxRetries:   1,
		DialTimeout:  time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
	}
	pl := pool.NewRoutes([]config.RouteSpec{spec}, time.Second, time.Minute)
	srv := NewRuntime(pool.NewStore(cfg, pl), testLogger(), "9.9.9-test", "mixed", config.EgressV4, config.EgressV6)

	admin := httptest.NewServer(AdminMux(AdminOptions{
		Version: "9.9.9-test",
		Started: time.Now(),
		Store:   pool.NewStore(cfg, pl),
		Listeners: map[string]*Server{
			"mixed": srv,
		},
		Rotations:  func() uint64 { return 5 },
		IPRevisits: func() uint64 { return 2 },
		Warm:       func() warmpool.Status { return warmpool.Status{Enabled: true, IdleTotal: 3} },
		Lifecycle:  NewLifecycle(),
		Cluster:    cluster,
	}))
	t.Cleanup(admin.Close)
	return admin
}

func fetchStatus(t *testing.T, admin *httptest.Server) (*http.Response, map[string]any) {
	t.Helper()
	resp, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("decode status: %v", err)
	}
	return resp, out
}

// Every scope is present, names itself, and carries the fields that belong to it.
//
// The scope marker is what makes the grouping usable: a client that sees a
// "pool" key needs to know whether it is reading one replica's pool or a
// cluster-wide figure, and an object that does not name its own scope cannot be
// told apart from a resource that happens to have been grouped.
func TestStatusCarriesEveryScopeLabelled(t *testing.T) {
	cluster := ClusterStatus{ConfigRevision: 12, StoreConfigured: true, ActiveRevision: 11, Synced: false}
	_, got := fetchStatus(t, statusFixture(t, cluster))

	for _, scope := range []string{ScopeCluster, ScopeDistributed, ScopeInstance} {
		raw, present := got[scope]
		if !present {
			t.Fatalf("/status omits the %q scope: %v", scope, keysOf(got))
		}
		object, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("%q = %T, want an object", scope, raw)
		}
		if object["scope"] != scope {
			t.Errorf("%q does not name itself: scope = %v", scope, object["scope"])
		}
	}

	clusterScope := got[ScopeCluster].(map[string]any)
	for _, key := range []string{"configRevision", "storeConfigured", "activeRevision", "synced"} {
		if _, present := clusterScope[key]; !present {
			t.Errorf("the cluster scope omits %q: %v", key, clusterScope)
		}
	}
	if clusterScope["configRevision"] != float64(12) {
		t.Errorf("cluster.configRevision = %v, want 12", clusterScope["configRevision"])
	}
	if clusterScope["storeConfigured"] != true {
		t.Errorf("cluster.storeConfigured = %v, want true", clusterScope["storeConfigured"])
	}
	// activeRevision behind configRevision is the convergence window, and it must
	// survive into the response rather than being rounded to "in sync".
	if clusterScope["activeRevision"] != float64(11) {
		t.Errorf("cluster.activeRevision = %v, want the lagging 11", clusterScope["activeRevision"])
	}
	if clusterScope["synced"] != false {
		t.Errorf("cluster.synced = %v, want false when the instance is behind", clusterScope["synced"])
	}

	distributed := got[ScopeDistributed].(map[string]any)
	for _, key := range []string{"requests", "failovers", "rotations", "ipRevisits"} {
		if _, present := distributed[key]; !present {
			t.Errorf("the distributed scope omits %q: %v", key, distributed)
		}
	}
	if distributed["rotations"] != float64(5) || distributed["ipRevisits"] != float64(2) {
		t.Errorf("distributed = %v, want the engine's own aggregates", distributed)
	}

	instance := got[ScopeInstance].(map[string]any)
	for _, key := range []string{"version", "uptime", "pool", "warmPool"} {
		if _, present := instance[key]; !present {
			t.Errorf("the instance scope omits %q: %v", key, instance)
		}
	}
	if instance["version"] != "9.9.9-test" {
		t.Errorf("instance.version = %v, want the process version", instance["version"])
	}
}

// A field belongs to exactly one scope, and the grouping is not decorative.
//
// The three scopes exist so an operator can tell "this replica is behind" from
// "the fleet rotated five times". A field that appeared under two of them would
// leave a reader unable to act on either, so the test asserts the placement
// rather than only the presence.
func TestStatusScopesDoNotOverlap(t *testing.T) {
	cluster := ClusterStatus{ConfigRevision: 3, StoreConfigured: true, ActiveRevision: 3, Synced: true}
	_, got := fetchStatus(t, statusFixture(t, cluster))

	clusterScope := got[ScopeCluster].(map[string]any)
	distributed := got[ScopeDistributed].(map[string]any)
	instance := got[ScopeInstance].(map[string]any)

	// configRevision is durable and shared, so it is cluster-scoped and must not
	// be reported as an instance-local figure: a client reading it under
	// "instance" would conclude this replica is behind when the cluster is fine.
	if _, present := instance["configRevision"]; present {
		t.Error("configRevision is reported as instance-local")
	}
	if _, present := distributed["configRevision"]; present {
		t.Error("configRevision is reported as distributed")
	}
	// requests and failovers are per-replica slices of a fleet total, so they are
	// distributed and must not be presented as a cluster-wide agreed figure.
	for _, key := range []string{"requests", "failovers"} {
		if _, present := clusterScope[key]; present {
			t.Errorf("%q is reported as agreed cluster state", key)
		}
	}
	// Per-route health belongs to this process's pool alone.
	for _, key := range []string{"pool", "warmPool", "version", "uptime"} {
		if _, present := clusterScope[key]; present {
			t.Errorf("%q is reported as cluster state", key)
		}
		if _, present := distributed[key]; present {
			t.Errorf("%q is reported as distributed state", key)
		}
	}
}

// Every key /status published before the split is still published, with the value
// it had. This is the compatibility half of the contract: the scope objects were
// added alongside the flat document, not in place of it.
func TestStatusPreservesEveryPreExistingTopLevelKey(t *testing.T) {
	cluster := ClusterStatus{ConfigRevision: 9, StoreConfigured: true, ActiveRevision: 9, Synced: true}
	_, got := fetchStatus(t, statusFixture(t, cluster))

	for _, key := range []string{
		"version", "uptime", "requests", "failovers",
		"listeners", "pool", "configRevision", "rotations", "ipRevisits", "warmPool",
	} {
		if _, present := got[key]; !present {
			t.Errorf("/status omits the pre-existing top-level key %q: %v", key, keysOf(got))
		}
	}
	if got["version"] != "9.9.9-test" {
		t.Errorf("version = %v, want it unchanged at the top level", got["version"])
	}
	if got["rotations"] != float64(5) || got["ipRevisits"] != float64(2) {
		t.Errorf("the aggregates moved: rotations=%v ipRevisits=%v", got["rotations"], got["ipRevisits"])
	}

	// The flat counters and the distributed scope report the same figure. That is
	// the point of the split — labelling, not a second number — and a client that
	// reads either one sees the same process.
	distributed := got[ScopeDistributed].(map[string]any)
	for _, key := range []string{"requests", "failovers", "rotations", "ipRevisits"} {
		if got[key] != distributed[key] {
			t.Errorf("%q = %v at the top level but %v under the distributed scope", key, got[key], distributed[key])
		}
	}
}

// The dynamic cluster snapshot receives the one generation /status loaded, and
// its values are returned alongside that same snapshot. This is what lets the
// binary compare a cached reconciler observation to what it is serving without a
// second generation load or a database query on the unauthenticated endpoint.
func TestStatusBuildsClusterScopeFromTheServingSnapshot(t *testing.T) {
	cfg := &config.RuntimeConfig{
		MaxRetries:   1,
		DialTimeout:  time.Second,
		CooldownBase: time.Second,
		CooldownMax:  time.Minute,
	}
	generations := pool.NewStore(cfg, pool.NewRoutes(nil, cfg.CooldownBase, cfg.CooldownMax))
	generations.PublishRevision(cfg, 21)
	var received int64
	admin := httptest.NewServer(AdminMux(AdminOptions{
		Version: "test",
		Started: time.Now(),
		Store:   generations,
		ClusterSnapshot: func(servingRevision int64) ClusterStatus {
			received = servingRevision
			return ClusterStatus{
				ConfigRevision:  servingRevision,
				StoreConfigured: true,
				ActiveRevision:  22,
				Synced:          false,
			}
		},
	}))
	t.Cleanup(admin.Close)

	_, got := fetchStatus(t, admin)
	if received != 21 {
		t.Errorf("ClusterSnapshot received %d, want the one serving revision 21", received)
	}
	cluster := got[ScopeCluster].(map[string]any)
	if cluster["configRevision"] != float64(21) || cluster["activeRevision"] != float64(22) || cluster["synced"] != false {
		t.Errorf("cluster = %v, want the cached cluster pointer 22 beside serving revision 21", cluster)
	}
	if got["configRevision"] != float64(21) {
		t.Errorf("top-level configRevision = %v, want the same serving snapshot", got["configRevision"])
	}
}

// An unconfigured store is a supported deployment, and /status says so rather
// than implying a fault or inventing a revision.
func TestStatusReportsAnUnconfiguredStoreAsSuch(t *testing.T) {
	_, got := fetchStatus(t, statusFixture(t, ClusterStatus{ConfigRevision: 0}))
	clusterScope := got[ScopeCluster].(map[string]any)
	if clusterScope["storeConfigured"] != false {
		t.Errorf("cluster.storeConfigured = %v, want false", clusterScope["storeConfigured"])
	}
	if clusterScope["configRevision"] != float64(0) {
		t.Errorf("cluster.configRevision = %v, want 0 for a file-seeded instance", clusterScope["configRevision"])
	}
	// With no store there is nothing to be in sync with, and saying so honestly
	// is better than claiming a convergence that was never attempted.
	if clusterScope["synced"] != false {
		t.Errorf("cluster.synced = %v, want false with no store to converge on", clusterScope["synced"])
	}
}

// /status describes a moving target and is unauthenticated, so a cached copy
// would be a wrong answer served as a right one.
func TestStatusIsNotCacheable(t *testing.T) {
	cluster := ClusterStatus{ConfigRevision: 1, StoreConfigured: true, ActiveRevision: 1, Synced: true}
	resp, _ := fetchStatus(t, statusFixture(t, cluster))
	if got := resp.Header.Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}
}

// The control API is mounted under one prefix and takes nothing away from the
// unauthenticated endpoints beside it.
func TestControlAPIIsMountedUnderItsPrefixOnly(t *testing.T) {
	control := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "control surface")
	})
	lc := NewLifecycle()
	lc.MarkReady()
	mux := AdminMux(AdminOptions{
		Version:   "9.9.9-test",
		Started:   time.Now(),
		Lifecycle: lc,
		Control:   control,
	})
	mounted := httptest.NewServer(mux)
	defer mounted.Close()

	// The prefix reaches the control handler...
	for _, path := range []string{ControlAPIMountPrefix + "/", ControlAPIMountPrefix + "/proxies"} {
		resp, err := http.Get(mounted.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if string(body) != "control surface" {
			t.Errorf("GET %s reached %q, want the control handler", path, body)
		}
	}

	// ...and nothing outside it does, so a resource added to the admin mux later
	// cannot accidentally land inside the control surface.
	resp, err := http.Get(mounted.URL + "/proxies")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode == http.StatusOK && resp.Request.URL.Path == "/proxies" {
		t.Error("a path outside the control prefix reached the control handler")
	}
	for _, path := range []string{"/healthz", ReadyPath} {
		resp, err := http.Get(mounted.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("GET %s = %d, want it unauthenticated and live", path, resp.StatusCode)
		}
	}
}

func keysOf(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
