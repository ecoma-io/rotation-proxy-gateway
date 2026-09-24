// Generation and Store publish one immutable runtime snapshot: the validated
// configuration, the pool built from it, and the compiled routing policy that
// scopes its picks. The Store lives in the pool package because pool already
// depends on config; the reverse dependency would be an import cycle.
package pool

import (
	"sync/atomic"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/routing"
)

// Generation is one immutable runtime snapshot. Handlers load it once at the
// start of an HTTP request or CONNECT operation so every route pick and all
// request settings use the same generation even if a reload publishes a new
// one in parallel. In-flight operations may safely keep using an older
// generation: Reconfigure shares unchanged Proxy state with the new pool.
type Generation struct {
	Config *config.RuntimeConfig
	Pool   *Pool
	// Router is the compiled routing policy from Config.Routing — nil when
	// the runtime YAML has no routing block. It rides on the generation so a
	// target's candidate set always comes from the same snapshot as the pool
	// it narrows: a reload that changes routes and rules together publishes
	// both as one unit, and in-flight sessions keep matching against their
	// original policy.
	Router *routing.Router
}

// NewGeneration combines validated configuration with its pool snapshot. It
// panics on nil inputs so a partially built generation can never serve.
func NewGeneration(cfg *config.RuntimeConfig, pl *Pool) *Generation {
	if cfg == nil {
		panic("pool: NewGeneration requires a non-nil RuntimeConfig")
	}
	if pl == nil {
		panic("pool: NewGeneration requires a non-nil Pool")
	}
	return &Generation{Config: cfg, Pool: pl, Router: cfg.Routing}
}

// Store atomically publishes Generations. All methods are safe for concurrent
// use; Load always returns a complete generation, never a mix of two.
type Store struct {
	value atomic.Pointer[Generation]
}

// NewStore publishes the initial generation. It panics on nil inputs.
func NewStore(cfg *config.RuntimeConfig, pl *Pool) *Store {
	s := &Store{}
	s.value.Store(NewGeneration(cfg, pl))
	return s
}

// Load returns the current generation.
func (s *Store) Load() *Generation {
	return s.value.Load()
}

// Store publishes a fully built generation. It panics unless the router is
// the one compiled from the generation's own config: config, pool, and
// routing policy must move as one snapshot, and a hand-assembled triple
// that pairs a router with someone else's config would serve candidate
// sets no pool in that generation was validated against.
func (s *Store) Store(gen *Generation) {
	if gen == nil || gen.Config == nil || gen.Pool == nil {
		panic("pool: Store requires a complete Generation")
	}
	if gen.Router != gen.Config.Routing {
		panic("pool: Store requires the generation's router to be its config's routing policy")
	}
	s.value.Store(gen)
}

// Publish builds the pool snapshot for validated configuration and publishes
// the combined generation atomically. Callers must fully parse and validate
// cfg before calling; on invalid input they keep serving the previous
// generation by not calling Publish at all. The new pool reuses unchanged
// Proxy health state from the current generation via Reconfigure.
func (s *Store) Publish(cfg *config.RuntimeConfig) *Generation {
	if cfg == nil {
		panic("pool: Publish requires a non-nil RuntimeConfig")
	}
	current := s.value.Load()
	gen := NewGeneration(cfg, current.Pool.Reconfigure(cfg.AllRoutes(), cfg.CooldownBase, cfg.CooldownMax))
	s.value.Store(gen)
	return gen
}
