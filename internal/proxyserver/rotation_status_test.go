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
)

// /status carries the rotation engine's aggregates under fixed key names and
// the per-route successful-rotation counters inside each manual route's
// rotation object. The engine is stubbed here because this test owns the
// handler contract; the engine's own aggregates are covered in
// internal/rotation and the end-to-end shape in e2e.
func TestAdminStatusExposesRotationCounters(t *testing.T) {
	u, err := url.Parse("socks5://manual.test:1080")
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
	store := pool.NewStore(cfg, pl)
	route := pl.RoutePointers()[0]

	// Baseline A, commit B, commit A: two successful rotations, one of them
	// back onto an address the route had already verified.
	route.SetBaselineIP("203.0.113.1")
	if _, err := pl.CommitRotation(route, "203.0.113.2", time.Now()); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if _, err := pl.CommitRotation(route, "203.0.113.1", time.Now()); err != nil {
		t.Fatalf("commit: %v", err)
	}

	rotations, ipRevisits := uint64(2), uint64(1)
	admin := httptest.NewServer(AdminMux("test", time.Now(), store, nil,
		func() uint64 { return rotations }, func() uint64 { return ipRevisits }, nil))
	defer admin.Close()

	resp, err := http.Get(admin.URL + "/status")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"rotations", "ipRevisits"} {
		if _, ok := raw[key]; !ok {
			t.Fatalf("/status omits %q: %v", key, raw)
		}
	}

	var response struct {
		Rotations  uint64        `json:"rotations"`
		IPRevisits uint64        `json:"ipRevisits"`
		Pool       []pool.Status `json:"pool"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		t.Fatal(err)
	}
	if response.Rotations != 2 || response.IPRevisits != 1 {
		t.Fatalf("aggregates = %d/%d, want 2/1", response.Rotations, response.IPRevisits)
	}
	if len(response.Pool) != 1 || response.Pool[0].Rotation == nil {
		t.Fatalf("pool = %+v, want one manual route with a rotation view", response.Pool)
	}
	rot := response.Pool[0].Rotation
	if rot.RotationCount != 2 || rot.IPRevisitCount != 1 {
		t.Fatalf("route counters = %d/%d, want 2/1", rot.RotationCount, rot.IPRevisitCount)
	}
	if rot.LastIP != "203.0.113.1" || rot.State != "idle" {
		t.Fatalf("rotation view = %+v, want the existing fields unchanged", rot)
	}
}
