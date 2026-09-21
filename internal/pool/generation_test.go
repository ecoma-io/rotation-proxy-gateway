package pool

import (
	"sync"
	"testing"
	"time"

	"rotation-proxy-gateway/internal/config"
)

func mustGenerationConfig(t *testing.T, routes []config.RouteSpec, base, max time.Duration) *config.RuntimeConfig {
	t.Helper()
	return &config.RuntimeConfig{
		MaxRetries:   3,
		CooldownBase: base,
		CooldownMax:  max,
		DialTimeout:  2 * time.Second,
		LogLevel:     "info",
		Routes:       routes,
	}
}

func generationRoutes(t *testing.T, raws ...string) []config.RouteSpec {
	t.Helper()
	return mustRouteSpecs(t, raws...)
}

func TestGenerationStoreRejectsIncomplete(t *testing.T) {
	cfg := mustGenerationConfig(t, generationRoutes(t, "socks5://a.test:1080"), time.Second, time.Minute)
	pl := NewRoutes(cfg.Routes, cfg.CooldownBase, cfg.CooldownMax)
	for name, fn := range map[string]func(){
		"nil config": func() { NewStore(nil, pl) },
		"nil pool":   func() { NewStore(cfg, nil) },
		"nil gen":    func() { NewStore(cfg, pl).Store(nil) },
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Fatalf("%s did not panic", name)
				}
			}()
			fn()
		}()
	}
}

func TestGenerationStorePublishesSnapshots(t *testing.T) {
	cfg := mustGenerationConfig(t, generationRoutes(t, "socks5://a.test:1080"), time.Second, time.Minute)
	store := NewStore(cfg, NewRoutes(cfg.Routes, cfg.CooldownBase, cfg.CooldownMax))
	if got := store.Load(); got.Config != cfg {
		t.Fatal("store did not load initial generation")
	}
	next := mustGenerationConfig(t, generationRoutes(t, "socks5://a.test:1080"), 3*time.Second, 3*time.Second)
	store.Publish(next)
	if got := store.Load(); got.Config != next {
		t.Fatal("store did not publish new generation")
	}
	if got := store.Load().Pool.ReportFailure(store.Load().Pool.PickFor(nil, nil, "t:443"), nil); got != 3*time.Second {
		t.Fatalf("published pool cooldown = %s, want new base 3s", got)
	}
}

func TestGenerationPublishPreservesCanonicalState(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	cfg := mustGenerationConfig(t, generationRoutes(t, "socks5://a.test:1080", "socks5://b.test:1080"), 30*time.Second, time.Minute)
	pl := NewRoutes(cfg.Routes, cfg.CooldownBase, cfg.CooldownMax)
	pl.Now = c.NowFunc
	store := NewStore(cfg, pl)

	old := store.Load().Pool.PickFor(nil, nil, "t:443")
	store.Load().Pool.ReportSuccess(old, "t:443")
	next := mustGenerationConfig(t, generationRoutes(t, "socks5://b.test:1080", "socks5://a.test:1080"), 30*time.Second, time.Minute)
	gen := store.Publish(next)
	if len(gen.Pool.entries) != 2 || gen.Pool.entries[1] != old {
		t.Fatal("publish lost canonical route identity")
	}
	if snap := gen.Pool.Snapshot(); snap[1].Successes != 1 {
		t.Fatalf("publish lost health state: %+v", snap)
	}
}

func TestGenerationInFlightKeepsOriginalSnapshot(t *testing.T) {
	c := &clock{now: time.Unix(0, 0)}
	cfg := mustGenerationConfig(t, generationRoutes(t, "socks5://a.test:1080"), 30*time.Second, time.Minute)
	pl := NewRoutes(cfg.Routes, cfg.CooldownBase, cfg.CooldownMax)
	pl.Now = c.NowFunc
	store := NewStore(cfg, pl)

	inFlight := store.Load()
	next := mustGenerationConfig(t, generationRoutes(t, "socks5://b.test:1080"), time.Second, time.Minute)
	store.Publish(next)

	if got := inFlight.Config.MaxRetries; got != 3 {
		t.Fatalf("in-flight config changed: %+v", inFlight.Config)
	}
	if got := inFlight.Pool.PickFor(nil, nil, "t:443"); got == nil || got.URL.Host != "a.test:1080" {
		t.Fatalf("in-flight pool changed: %+v", got)
	}
	if got := store.Load().Pool.PickFor(nil, nil, "t:443"); got == nil || got.URL.Host != "b.test:1080" {
		t.Fatalf("published pool = %+v, want b.test:1080", got)
	}
	// Old-generation health reports land on the old pool only.
	inFlight.Pool.ReportSuccess(inFlight.Pool.PickFor(nil, nil, "t:443"), "t:443")
	if snap := store.Load().Pool.Snapshot()[0]; snap.Successes != 0 {
		t.Fatalf("in-flight report leaked into new generation: %+v", snap)
	}
}

func TestGenerationConcurrentLoadPublishRaceFree(t *testing.T) {
	cfg := mustGenerationConfig(t, generationRoutes(t, "socks5://a.test:1080"), time.Second, time.Minute)
	store := NewStore(cfg, NewRoutes(cfg.Routes, cfg.CooldownBase, cfg.CooldownMax))
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				gen := store.Load()
				_ = gen.Config
				_ = gen.Pool.PickFor(nil, nil, "t:443")
			}
		}()
		go func() {
			defer wg.Done()
			for j := 0; j < 25; j++ {
				next := mustGenerationConfig(t, generationRoutes(t, "socks5://a.test:1080"), time.Second, time.Minute)
				store.Publish(next)
			}
		}()
	}
	wg.Wait()
}
