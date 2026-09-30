package proxyserver

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/pool"
)

// The lifecycle is the whole point of /readyz, so its two properties are pinned
// here rather than only through the endpoint: it moves forward and never
// backward, and it distinguishes "not ready yet" from "draining" from
// "stopped" — three states that all answer 503 but mean different things to a
// log reader.
func TestLifecycleMovesForwardOnly(t *testing.T) {
	lc := NewLifecycle()
	if lc.Ready() {
		t.Fatal("a fresh lifecycle is ready; the zero value must mean 'starting'")
	}
	lc.MarkReady()
	if !lc.Ready() || lc.load() != StateReady {
		t.Fatalf("state = %v, want ready", lc.load())
	}
	// A repeated call is a no-op that keeps the forward-only guarantee.
	if !lc.MarkReady() {
		t.Fatal("MarkReady() is not idempotent: a second call must report the state it left in place")
	}
	lc.BeginDraining()
	if lc.Ready() {
		t.Fatal("a draining process still reports ready")
	}
	// The dangerous direction: anything that could re-advertise a draining
	// process puts traffic back into sockets that are about to close.
	if lc.MarkReady() {
		t.Fatal("MarkReady() after BeginDraining() re-advertised a draining process")
	}
	if lc.load() != StateDraining {
		t.Fatalf("state = %v, want the refused transition to leave it draining", lc.load())
	}
	if !lc.BeginDraining() {
		t.Fatal("BeginDraining() is not idempotent: a second call must be a no-op that keeps the state")
	}
	lc.MarkStopped()
	if got := lc.load(); got != StateStopped {
		t.Fatalf("state = %v, want stopped", got)
	}
	// Terminal: a late drain notification must not un-drain a stopped process.
	lc.BeginDraining()
	if got := lc.load(); got != StateStopped {
		t.Fatalf("state = %v, want stopped: a late drain undid the terminal state", got)
	}
	if lc.MarkReady() {
		t.Fatal("MarkReady() after MarkStopped() re-advertised a stopped process")
	}
}

// A process stopped during startup never advertised readiness, but it has just
// as much reason to answer "not ready" as one stopped while serving.
func TestLifecycleDrainsFromStarting(t *testing.T) {
	lc := NewLifecycle()
	lc.BeginDraining()
	if got := lc.load(); got != StateDraining {
		t.Fatalf("state = %v, want draining", got)
	}
	if lc.Ready() {
		t.Fatal("a process that never advertised readiness reports ready after draining")
	}
}

// The endpoint's contract: 200 "ok\n" only while ready, 503 with the state
// token otherwise, uncacheable, and 405 for anything but GET.
func TestReadyzReportsLifecycleState(t *testing.T) {
	// Before the listeners are up the answer is 503, with the reason in the
	// body; while ready it is 200 "ok\n" and nothing else.
	store := pool.NewStore(defaultRuntime(), pool.NewRoutes(nil, time.Second, time.Minute))
	lc := NewLifecycle()
	admin := httptest.NewServer(AdminMux("test", time.Now(), store, nil, nil, nil, nil, lc))
	defer admin.Close()

	probe := func(method string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(method, admin.URL+ReadyPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		return resp, string(body)
	}

	// Before the listeners are up the answer is 503, with the reason in the
	// body; while ready it is 200 "ok\n" and nothing else.
	starting, startingBody := probe(http.MethodGet)
	if starting.StatusCode != http.StatusServiceUnavailable || startingBody != "starting\n" {
		t.Fatalf("starting: status=%d body=%q, want 503 %q", starting.StatusCode, startingBody, "starting\n")
	}
	lc.MarkReady()
	ready, readyBody := probe(http.MethodGet)
	if ready.StatusCode != http.StatusOK {
		t.Fatalf("ready: status = %d, want 200", ready.StatusCode)
	}
	if readyBody != ReadyBody {
		t.Fatalf("ready: body = %q, want %q", readyBody, ReadyBody)
	}
	if got := ready.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("ready: Cache-Control = %q, want no-store (a cached 200 replayed into a closing socket is the failure this endpoint prevents)", got)
	}

	lc.BeginDraining()
	draining, drainingBody := probe(http.MethodGet)
	if draining.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("draining: status = %d, want 503", draining.StatusCode)
	}
	if drainingBody != "draining\n" {
		t.Fatalf("draining: body = %q, want the state token %q", drainingBody, "draining\n")
	}
	if got := draining.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("draining: Cache-Control = %q, want no-store", got)
	}
	lc.MarkStopped()
	stopped, stoppedBody := probe(http.MethodGet)
	if stopped.StatusCode != http.StatusServiceUnavailable || stoppedBody != "stopped\n" {
		t.Fatalf("stopped: status=%d body=%q, want 503 %q", stopped.StatusCode, stoppedBody, "stopped\n")
	}
	lc.MarkReady() // refused: the endpoint must not ride on a stale transition
	if _, after := probe(http.MethodGet); after != "stopped\n" {
		t.Fatalf("after a refused MarkReady: body = %q, want the terminal token %q", after, "stopped\n")
	}

	rejected := probe2(t, admin.URL+ReadyPath)
	if rejected.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST: status = %d, want 405 (only GET is this endpoint)", rejected.StatusCode)
	}
	if got := rejected.Header.Get("Allow"); got != http.MethodGet {
		t.Fatalf("POST: Allow = %q, want GET", got)
	}
}

// probe2 issues one non-GET request and returns the response, for the 405 case.
func probe2(t *testing.T, url string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(""))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// Liveness is the deliberate mirror image: it must never report the drain, or
// an orchestrator reading it would kill a process that is stopping correctly.
func TestHealthzStaysUnconditionalThroughDrain(t *testing.T) {
	lc := NewLifecycle()
	admin := httptest.NewServer(AdminMux("test", time.Now(), pool.NewStore(defaultRuntime(), pool.NewRoutes(nil, time.Second, time.Minute)), nil, nil, nil, nil, lc))
	defer admin.Close()
	lc.MarkReady()
	for _, phase := range []string{"ready", "draining", "stopped"} {
		if phase == "draining" {
			lc.BeginDraining()
		}
		if phase == "stopped" {
			lc.MarkStopped()
		}
		resp, err := http.Get(admin.URL + "/healthz")
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: /healthz = %d, want 200 in every phase", phase, resp.StatusCode)
		}
		_ = resp.Body.Close()
	}
}

// The head start is drawn from the grace, not added to it, and a grace that
// cannot carry one takes none.
func TestPropagationIsCappedByHalfTheGrace(t *testing.T) {
	for _, tc := range []struct {
		grace time.Duration
		want  time.Duration
	}{
		{grace: 55 * time.Second, want: 5 * time.Second},
		{grace: 20 * time.Second, want: 5 * time.Second},
		{grace: 10 * time.Second, want: 5 * time.Second},
		{grace: 9 * time.Second, want: 4500 * time.Millisecond},
		{grace: 1 * time.Second, want: 500 * time.Millisecond},
		{grace: 9 * time.Millisecond, want: 4500 * time.Microsecond},
		{grace: time.Nanosecond, want: 0},
		{grace: 0, want: 0},
		{grace: -time.Second, want: 0},
	} {
		if got := Propagation(tc.grace); got != tc.want {
			t.Errorf("Propagation(%s) = %s, want %s", tc.grace, got, tc.want)
		}
	}
	// The invariant the cap exists for: the drain keeps the majority of the
	// budget, so a head start can never starve the work it delays.
	for _, grace := range []time.Duration{time.Second, 9 * time.Second, 55 * time.Second, 350 * time.Second} {
		if head := Propagation(grace); head > grace/2 {
			t.Errorf("Propagation(%s) = %s, want at most grace/2", grace, head)
		}
	}
}
