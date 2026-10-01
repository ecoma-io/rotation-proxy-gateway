// Command rotation-proxy-gateway runs an HTTP forward proxy with v4, v6, and
// mixed egress listener views plus an always-on admin listener. Every client
// request is relayed through SOCKS5H routes from a shared health-aware pool:
// CONNECT opens a byte-transparent tunnel and an absolute-form request is
// forwarded to its origin in origin form. The gateway resolves no target name
// itself, so a hostname reaches the outbound route untouched.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/configstore"
	"rotation-proxy-gateway/internal/control"
	"rotation-proxy-gateway/internal/logging"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/proxyserver"
	"rotation-proxy-gateway/internal/rotation"
	"rotation-proxy-gateway/internal/sanitize"
	"rotation-proxy-gateway/internal/warmpool"

	"github.com/rs/zerolog"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

// fatalLog reports startup failures before any configuration is available.
// It is deliberately ungated (no global level is set yet) and writes to the
// same stdout stream as the runtime logger so all structured output stays on
// one stream for the json-file log driver.
var fatalLog = logging.New(os.Stdout)

// usageLine names every supported invocation. It is static text: it must
// never carry configuration values or credentials.
const usageLine = "usage: rotation-proxy-gateway [version|healthcheck]\n" +
	"no arguments starts the gateway; configuration comes from the RPGW_ environment and the runtime YAML\n"

func main() {
	os.Exit(runArgs(os.Args[1:]))
}

// runArgs dispatches the command line and returns the process exit code. An
// empty argument list starts the server; a recognized subcommand runs and
// exits; any other first argument is a usage error, so a typo or a stray flag
// can never fall through and boot a live gateway on the default addresses.
func runArgs(args []string) int {
	if len(args) == 0 {
		if err := run(); err != nil {
			fatalLog.Error().Str("err", sanitize.ErrorString(err)).Msg("fatal")
			return 1
		}
		return 0
	}
	switch args[0] {
	case "version":
		fmt.Println(version)
		return 0
	case "healthcheck":
		return healthcheck()
	default:
		fmt.Fprint(os.Stderr, usageLine)
		return 2
	}
}

// healthcheck probes the bootstrap-configured admin listener. It deliberately
// does not parse runtime YAML: a bad reload must not make a healthy, already
// running process fail Docker's health probe.
//
// It probes /readyz, not /healthz, and that choice is the point. A container
// health check asks "should this instance still receive traffic?", and the
// answer has to go false while the sockets are still up — which is exactly what
// /readyz does and what /healthz deliberately does not. Probing /healthz would
// keep reporting a draining process as fine until its listener finally closed,
// and Docker would then be told to kill a process that is stopping correctly,
// mid-drain, with live tunnels on it.
//
// The body is checked as well as the status: /readyz answers "ok\n" only while
// the process is ready, so a 200 from anything else listening on that port
// fails the probe. The body is never logged — a probe aimed at the wrong port
// can hit anything, and its answer is not ours to quote — only its length.
func healthcheck() int {
	cfg, err := config.LoadBootstrap()
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", sanitize.ErrorString(err))
		return 1
	}
	// An empty Transport ignores HTTP_PROXY and friends: the probe must reach
	// this process directly, never detour through a proxy that happens to be
	// configured in the environment.
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{}}
	resp, err := client.Get(healthcheckURL(cfg.AdminAddr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", sanitize.ErrorString(err))
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	// Bounded read: /readyz answers "ok\n" (and at most a state token), but a
	// probe pointed at the wrong port can be answered by anything at all.
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if readErr != nil {
		fmt.Fprintln(os.Stderr, "healthcheck: reading the probe response:", sanitize.ErrorString(readErr))
		return 1
	}
	if resp.StatusCode != http.StatusOK || string(body) != proxyserver.ReadyBody {
		// The failure body is the readiness state token — a fixed vocabulary the
		// process owns, never anything a route or an upstream said — and even so
		// only its length is reported.
		fmt.Fprintf(os.Stderr, "healthcheck: status %d, response length %d\n", resp.StatusCode, len(body))
		return 1
	}
	return 0
}

// healthcheckURL builds the probe URL against the bootstrap admin address. A
// wildcard or hostless bind addresses all interfaces, so the probe goes to the
// loopback equivalent instead.
func healthcheckURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		panic(fmt.Sprintf("healthcheckURL requires a validated host:port address: %q", addr))
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: proxyserver.ReadyPath}).String()
}

type runningListener struct {
	name   string
	server *proxyserver.Server
	ln     net.Listener
}

func warnUnavailableKindListeners(log zerolog.Logger, cfg *config.RuntimeConfig, bootstrap *config.BootstrapConfig) {
	var v4, v6 int
	for _, route := range cfg.AllRoutes() {
		switch route.Kind {
		case config.EgressV4:
			v4++
		case config.EgressV6:
			v6++
		}
	}
	if bootstrap.V4ListenAddr != "" && v4 == 0 {
		log.Warn().Str("listener", "v4").Msg("listener has no eligible routes; replying 503 Service Unavailable")
	}
	if bootstrap.V6ListenAddr != "" && v6 == 0 {
		log.Warn().Str("listener", "v6").Msg("listener has no eligible routes; replying 503 Service Unavailable")
	}
}

// controlPlane is the opened durable configuration substrate: the store, the
// generation store the reconciler publishes into, the reconciler that
// materializes revisions into it, and the revision the first generation came
// from.
//
// generations and reconciler.pool are the same *pool.Store, and that identity is
// the substrate's central invariant: the reconciler publishes a durable revision
// into the one generation store the proxy listeners, the admin mux, the rotation
// engine and the warm pool all read. A reconciler publishing into a store nothing
// serves would still apply every process-global effect of a revision — the log
// level, the "configuration reloaded" line — which is what made the broken
// wiring self-concealing: the logs announced a revision the gateway never served.
type controlPlane struct {
	store       configstore.Repository
	generations *pool.Store
	reconciler  *control.Reconciler
}

// servedRevision names the durable revision the first generation was built
// from, or NoRevision when this instance is running file-seeded with no store
// configured.
type servedRevision = configstore.Revision

// openControlPlane opens the durable store, migrates its schema, and resolves
// the configuration this instance should start from.
//
// The seed decision, and why it is narrow: the runtime YAML is the seed for a
// store that has no committed revision, and nothing else. That path exists
// because a store has to get its first revision from somewhere, and requiring
// an operator to commit one by hand before any instance can start would mean a
// fresh deployment cannot come up on its own. Once a revision exists the YAML is
// never read again for the serving configuration — an instance converges on the
// active revision instead. Seeding an already-seeded store would let one
// instance's local file overwrite the cluster's configuration, which is exactly
// the file-as-authority behavior this store replaces, so Seed refuses it.
//
// Without RPGW_CONFIG_STORE_DSN there is no store at all: the process reads its
// YAML, serves it, and reloads it on change exactly as before. That keeps a
// single-instance deployment — and the existing e2e suite — working with no
// database in the picture.
func openControlPlane(ctx context.Context, bootstrap *config.BootstrapConfig) (*controlPlane, *config.RuntimeConfig, servedRevision, error) {
	// The YAML is read first either way: it is the seed, and it is the whole
	// configuration when no store is configured. Its errors are already
	// sanitized and secret-free.
	seed, err := config.LoadRuntime(bootstrap.ConfigFile)
	if err != nil {
		return nil, nil, 0, err
	}
	if bootstrap.ConfigStoreDSN == "" {
		return nil, seed, configstore.NoRevision, nil
	}

	repo, err := configstore.NewPostgres(ctx, bootstrap.ConfigStoreDSN)
	if err != nil {
		// The DSN is a secret; this error is pgx's own and never quotes it.
		return nil, nil, 0, err
	}
	// Migrations run before anything binds. A failure here is fatal: an
	// instance that cannot trust its schema must not serve, and an unknown
	// future schema version is refused rather than worked around.
	if err := repo.Migrate(ctx); err != nil {
		repo.Close()
		return nil, nil, 0, err
	}
	version, err := repo.SchemaVersion(ctx)
	if err != nil {
		repo.Close()
		return nil, nil, 0, err
	}
	log := setupDynamicLogger(seed.LogLevel)
	log.Info().Int("schema_version", version).Msg("config store schema ready")

	// The reconciler publishes into this store, and this store is the one run()
	// serves from — the boot generation is the serving generation, reconfigured
	// in place as later revisions are materialized. It is built over the seed with
	// a zero-route pool purely so it has a generation to publish into; Seed below
	// replaces that pool with the materialized routes' own snapshot before
	// anything binds, and PublishRevision's reconfigure retains route identity
	// across the swap. Building a second store here and handing run() that one
	// instead would strand every later revision in a store nothing serves.
	generations := pool.NewStore(seed, pool.NewRoutes(nil, seed.CooldownBase, seed.CooldownMax))
	reconciler := control.NewReconciler(repo, generations, log, control.Options{Interval: bootstrap.ReconcileInterval})

	// Seed commits the first revision only when the store has none, and
	// otherwise converges on the active one. It is also what validates: a
	// durable revision that this build refuses is reported here rather than
	// discovered by the first reconcile tick, while the failure is still a
	// startup decision.
	revision, err := reconciler.Seed(ctx, seed)
	if err != nil {
		repo.Close()
		return nil, nil, 0, err
	}
	materialized := generations.Load()
	if revision.IsValid() {
		log.Info().Int64("revision", int64(revision)).Int("upstreams", len(materialized.Config.AllRoutes())).
			Msg("serving durable configuration revision")
	}
	// generations, not materialized.Config, is what the caller serves from: the
	// config is only this generation's value, and it is the store that later
	// revisions republish into.
	return &controlPlane{store: repo, generations: generations, reconciler: reconciler}, materialized.Config, revision, nil
}

func run() error {
	// or healthy. The bootstrap env and config may be invalid, or a listener
	// bind may fail — in every such startup failure the notify channel stays
	// armed until the deferred signal.Stop, and a SIGTERM arriving before the
	// select loop below simply queues on the buffered channel: without this
	// registration, SIGINT/SIGTERM/SIGHUP keep their default dispositions while
	// the process is momentarily reachable (listeners up, /healthz answering),
	// and a process manager that stops a just-started instance could kill it
	// with no drain.
	// Two slots, not one: registration precedes the select loop by
	// milliseconds of startup, and Go drops signals that arrive while a
	// Notify buffer is full — an ignored SIGHUP landing in that window
	// must not be able to displace the SIGTERM that follows it.
	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	bootstrap, err := config.LoadBootstrap()
	if err != nil {
		return err
	}

	// The durable configuration store is opened and migrated BEFORE any
	// listener binds and before the runtime YAML is consulted. Two properties
	// depend on that order: a process must never serve against a schema its code
	// does not expect, and the configuration the first generation is built from
	// must be the one the cluster agrees on rather than whichever local file
	// this instance happened to have.
	//
	// A failed migration is fatal here rather than a degraded mode. Refusing to
	// start is the honest outcome: an instance that serves from its local file
	// while the cluster serves another revision is a split brain, which is
	// strictly worse than not running.
	storeCtx, cancelStore := context.WithCancel(context.Background())
	defer cancelStore()
	controlPlane, initialCfg, served, err := openControlPlane(storeCtx, bootstrap)
	if err != nil {
		return err
	}
	if controlPlane != nil {
		defer controlPlane.store.Close()
	}

	runtimeCfg := initialCfg
	log := setupDynamicLogger(runtimeCfg.LogLevel)
	warnUnavailableKindListeners(log, runtimeCfg, bootstrap)
	// The store publishes one immutable generation (validated config + pool
	// snapshot). Handlers load it once per operation; a new revision builds the
	// next pool snapshot and swaps the whole generation atomically. The pool
	// serves both origins; manual routes additionally carry rotation state.
	poolStore := selectServingStore(controlPlane, runtimeCfg, served)
	engine := rotation.New(poolStore, log)
	// The warm pool keeps half-established upstream connections ready for the
	// serving path to borrow (one non-blocking pop per attempt, cold dial on
	// any miss) while never writing route health itself: cooldown, auth, and
	// rotation state change only on the request path. It follows config
	// generations on its own; a disabled config parks it at zero idle
	// connections and every dial is cold again.
	warm := warmpool.New(poolStore, log, nil)

	listeners := make([]runningListener, 0, 3)
	listenerViews := make(map[string]*proxyserver.Server, 3)
	addListener := func(name, addr string, kinds ...config.EgressKind) error {
		if addr == "" {
			return nil
		}
		srv := proxyserver.NewRuntime(poolStore, log, version, name, kinds...)
		srv.UseWarmPool(warm)
		if bootstrap.Account != nil {
			srv.UseInboundAccount(bootstrap.Account.Username, bootstrap.Account.Password)
		}
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("%s listener: %w", name, err)
		}
		listeners = append(listeners, runningListener{name: name, server: srv, ln: ln})
		listenerViews[name] = srv
		return nil
	}
	// Bootstrap validation already proved the addresses are well-formed and
	// non-overlapping; a bind failure here is an occupied port or a missing
	// interface, both fatal before serving starts.
	for _, spec := range []struct {
		name, addr string
		kinds      []config.EgressKind
	}{
		{proxyserver.MixedListener, bootstrap.MixedListenAddr, []config.EgressKind{config.EgressV4, config.EgressV6}},
		{"v4", bootstrap.V4ListenAddr, []config.EgressKind{config.EgressV4}},
		{"v6", bootstrap.V6ListenAddr, []config.EgressKind{config.EgressV6}},
	} {
		if err := addListener(spec.name, spec.addr, spec.kinds...); err != nil {
			return err
		}
	}

	started := time.Now()
	// The lifecycle is the process's own readiness statement, read by /readyz
	// and written only by the shutdown path. It is created before the admin mux
	// so the handler closure and shutdownAll share one machine.
	lc := proxyserver.NewLifecycle()
	adminSrv := &http.Server{
		Handler:           proxyserver.AdminMux(version, started, poolStore, listenerViews, engine.Rotations, engine.IPRevisits, warm.Snapshot, lc),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	// Bind before announcing: a failed bind is fatal before serving starts,
	// and the log must carry the address that actually listens.
	adminLn, err := net.Listen("tcp", bootstrap.AdminAddr)
	if err != nil {
		return fmt.Errorf("admin listener: %w", err)
	}

	errCh := make(chan error, len(listeners)+1)
	for _, listener := range listeners {
		listener := listener
		go func() {
			log.Info().Str("listener", listener.name).Str("addr", listener.ln.Addr().String()).Str("version", version).Msg("proxy listening")
			// Serve returns nil once shutdown closes the listener.
			if err := listener.server.Serve(listener.ln); err != nil {
				errCh <- fmt.Errorf("%s listener: %w", listener.name, err)
			}
		}()
	}
	go func() {
		log.Info().Str("addr", adminLn.Addr().String()).Msg("admin listening")
		if err := adminSrv.Serve(adminLn); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("admin listener: %w", err)
		}
	}()

	// The two configuration sources are mutually exclusive by construction, and
	// exactly one of them runs.
	//
	// With a durable store configured, the reconciler is the sole authority and
	// the poller never starts. The YAML was read exactly once, above, to seed
	// the first revision; an in-place edit of that file afterwards changes
	// nothing, which is the point. Two authorities that both react to changes
	// would let a local edit silently overwrite a cluster-wide revision, and the
	// store would stop being the authority — so in this mode the file is a seed
	// and only a seed.
	//
	// With no store configured there is no durable authority at all, and the
	// poller keeps the pre-existing behavior exactly. That is what keeps a
	// single-instance deployment — and the e2e suite, which drives the real
	// binary with a file and no database — working unchanged.
	//
	// Both feed one `reload` channel, so the process-global side effects of a
	// configuration change — the log level and the kind-listener warnings — have
	// exactly one writer in either mode.
	reload := make(chan *config.RuntimeConfig, 1)
	reloadSource := "poll"
	// reloadAuthority names, in the SIGHUP line, where a configuration change
	// would have to come from. It is mode-accurate on purpose: telling a
	// file-mode operator that changes arrive "through the durable revision"
	// would point them at a subsystem they are not running.
	reloadAuthority := "configuration reloads are poller-driven, stop with SIGTERM"
	// One context governs whichever source runs — exactly one of the two branches
	// below starts one — and the select loop cancels it on the way out. Deriving
	// it here rather than per branch keeps cancelReload defined on every path
	// without a dead placeholder value; only one goroutine ever consumes it.
	reloadCtx, cancelReload := context.WithCancel(context.Background())
	defer cancelReload()
	if controlPlane != nil {
		reloadSource = "revision"
		reloadAuthority = "configuration changes arrive through the durable revision, stop with SIGTERM"
		// The subscriber receives only validated, already-published
		// configurations, so the process-global effects can never run against a
		// configuration the gateway refused to serve.
		controlPlane.reconciler.Subscribe(func(next *config.RuntimeConfig) {
			select {
			case reload <- next:
			default:
				// A publication is already queued; the newer value supersedes it
				// rather than being applied twice.
			}
		})
		// Reconciled into the real store, so a revision committed by another
		// instance reaches this one's serving generation.
		go controlPlane.reconciler.Run(reloadCtx)
	} else {
		go watchConfigFile(reloadCtx, bootstrap.ConfigFile, poolStore, reload, log)
	}

	// The rotation engine owns manual-route egress IP rotation. Its context is
	// canceled before the listeners drain so in-flight rotations stop promptly
	// and never extend shutdown beyond the shared grace budget.
	engineCtx, engineCancel := context.WithCancel(context.Background())
	defer engineCancel()
	go engine.Run(engineCtx)
	warm.Start()

	// Ready once every proxy listener and the admin listener are bound and
	// their serve goroutines are running: from this instant a probe that reaches
	// /readyz is answered by a process that is certainly serving every listener.
	// The signal handler was armed before any of it, so a SIGTERM that arrived
	// during startup already took the graceful path and the deferred cancels
	// above have already unwound — this transition can only move forward from
	// here.
	lc.MarkReady()

	// A published configuration — from a durable revision or from the file
	// poller — arrives here as one value on one channel, handled by this
	// serialized loop. It carries the process-global side effects only; the
	// generation itself was already published atomically by whoever produced
	// the value, and a rejected configuration never reaches this point at all.
	reconfigure := func(next *config.RuntimeConfig, source string) {
		// Only this goroutine writes the global level, so the package-global
		// atomic swap is race-free and every future event picks it up.
		zerolog.SetGlobalLevel(parseZerologLevel(next.LogLevel))
		warnUnavailableKindListeners(log, next, bootstrap)
		log.Info().Str("source", source).Int("upstreams", len(next.AllRoutes())).
			Msg("configuration reloaded")
	}

	hupLogged := false
	for {
		select {
		case err := <-errCh:
			cancelReload()
			shutdownAll(log, lc, engineCancel, warm.Stop, listeners, adminSrv, bootstrap.ShutdownGrace)
			return err
		case sig := <-sigCh:
			// SIGHUP is deliberately ignored — never a reload, never a drain.
			// One info line on first receipt tells the operator why nothing
			// happened; later ones stay silent so a looping sender cannot
			// flood the log. Any other signal is the graceful-stop path.
			if sig == syscall.SIGHUP {
				if !hupLogged {
					hupLogged = true
					log.Info().Msg("SIGHUP received; ignored — " + reloadAuthority)
				}
				continue
			}
			log.Info().Str("signal", sig.String()).Str("grace", bootstrap.ShutdownGrace.String()).Msg("shutting down")
			cancelReload()
			shutdownAll(log, lc, engineCancel, warm.Stop, listeners, adminSrv, bootstrap.ShutdownGrace)
			return nil
		case next := <-reload:
			reconfigure(next, reloadSource)
		}
	}
}

// selectServingStore returns the generation store run() serves from, and is the
// single place that decision is made — which is why it is a named function with
// its own regression test rather than four lines inline: the durable-revision
// defect this guards against was invisible precisely because the choice was
// spread between openControlPlane and run().
//
// In store mode it returns the very store the reconciler publishes into
// (controlPlane.generations, the same *pool.Store handed to
// control.NewReconciler). Returning a second store built here instead is the
// original defect: the reconciler would keep publishing later revisions into a
// store nothing serves, while still applying every process-global effect of the
// revision — the log level, the "configuration reloaded" line — so the logs
// announced a revision the gateway never served.
//
// It also stamps the boot generation with the revision it came from, so /status
// reports the revision actually serving rather than zero. The stamp goes
// through the same publication path every later revision uses, so there is no
// second way for a generation to acquire a revision, and the reconfigure is a
// no-op on identity, retaining every route's health and rotation state.
//
// In file mode controlPlane is nil: there is no durable store, the local YAML is
// the whole configuration, and the poller republishes into the store built here.
// Nothing is stamped, because a zero revision on the generation means exactly
// "not from the durable store".
func selectServingStore(cp *controlPlane, runtimeCfg *config.RuntimeConfig, served configstore.Revision) *pool.Store {
	if cp != nil {
		if served.IsValid() {
			cp.generations.PublishRevision(runtimeCfg, int64(served))
		}
		return cp.generations
	}
	return pool.NewStore(runtimeCfg, pool.NewRoutes(runtimeCfg.AllRoutes(), runtimeCfg.CooldownBase, runtimeCfg.CooldownMax))
}

// watchConfigFile is the file-seeded reload path: it publishes a changed runtime
// YAML to the live generation store and reports the published value on out.
//
// It runs only when no durable store is configured. It keeps the same ordering
// the reconciler does — LoadRuntime validates completely, Publish builds the next
// pool snapshot and swaps the whole generation, and only a configuration that
// passed validation is ever published — so invalid input keeps the previous
// generation and its route health serving untouched. Publication happens in this
// goroutine before the value is reported, so the process-global effects in the
// main loop can never run ahead of the generation they describe.
func watchConfigFile(ctx context.Context, path string, generations *pool.Store, out chan<- *config.RuntimeConfig, log zerolog.Logger) {
	poller := config.NewPoller(path, config.DefaultPollInterval, log)
	// NewPoller seeds the baseline with the file's content right now — the
	// content the boot-time load already published — so the first tick is quiet
	// unless the file genuinely changes. Constructed here rather than by the
	// caller so the baseline is taken after that publication, never before it.
	go poller.Run(ctx, log)
	for {
		select {
		case <-ctx.Done():
			return
		case <-poller.Changes():
			// The poller hash-gates on applied content, so one signal means one
			// distinct configuration; no debounce is needed.
			next, err := config.LoadRuntime(path)
			if err != nil {
				log.Warn().Str("source", "poll").Str("error", sanitize.ErrorString(err)).
					Msg("reload failed; keeping previous configuration")
				continue
			}
			generations.Publish(next)
			select {
			case out <- next:
			default:
				// Coalescing send, matching the poller's own coalescing: a
				// configuration applied while a previous one was still queued is
				// superseded by the newer value rather than applied twice.
			}
		}
	}
}

// shutdownAll stops the rotation engine and the warm pool first, then closes
// every proxy listener socket at once and drains each one's active client
// sessions plus the admin listener concurrently, against one shared grace
// budget. A drained listener returns immediately, so an idle process exits at
// once; once the budget expires the remaining sessions' client connections are
// force-closed. Established tunnels are never broken before that deadline.
//
// Ordering, and why each step is where it is:
//
//  1. Unready FIRST, before a single socket is touched. From this instant
//     /readyz answers 503 while /healthz keeps answering 200 and every
//     listener keeps accepting — the window a load balancer needs. Only then
//     does the head start run, so a probe scheduled before the signal still
//     lands on a live socket rather than a closed port.
//  2. The rotation engine, then the warm pool, inside the same budget. The
//     order between them is deliberate: reversing it would let parked warm
//     sockets outlive the sessions they exist to accelerate.
//  3. Every listen socket closed, then every drain started — never interleaved.
//     Closing them one at a time and draining in between kept the not-yet-closed
//     listeners serving, and each Server only sets its own shuttingDown flag
//     inside its own Shutdown, so those listeners went on admitting brand-new
//     sessions that the already-expired deadline then force-closed. Draining
//     concurrently also stops one long-lived tunnel on the mixed listener from
//     consuming the whole budget and leaving the v4 and v6 listeners none.
//
// The trade-off is real: one long tunnel on ANY listener now ends the accept
// phase for all of them, where before only the listeners reached later in the
// sequence stopped early. That is the correct shape for a draining gateway —
// it should be accepting nothing — but it changes the failure profile from
// "some listeners still serve" to "none do, promptly".
//
// Budget invariant: the one ctx deadline is created here and governs the warm
// pool teardown, every proxy listener drain, and the admin shutdown alike —
// pre-drain work (rotation cancel, warm stop) shares the same clock instead of
// holding its own. The head start is DRAWN from that budget rather than added
// to it, so total signal→exit stays within grace. The worst case is grace plus
// the per-listener force-close tail (proxyserver's forceCloseWait, 1s) — one
// per proxy listener that was still draining when the budget expired, and the
// drains now run concurrently, so at worst that is a single 1s tail rather
// than one per listener in sequence. With the default 55s grace that is ~56s,
// and the surrounding orchestrator's kill timer (compose stop_grace_period:
// 60s) must stay above it.
func shutdownAll(log zerolog.Logger, lc *proxyserver.Lifecycle, engineCancel context.CancelFunc, warmStop func(context.Context), listeners []runningListener, adminSrv *http.Server, grace time.Duration) {
	// The deadline governs the whole drain. Creating it before stopping the
	// rotation engine and the warm pool means their unwinding consumes the
	// same budget the listeners drain against — a process with a warm worker
	// stuck in a greeting read against a black-hole upstream is bounded by
	// grace, not by a separate fixed 1s cap on top of it.
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	// Step 1: stop advertising readiness while every socket is still open.
	// The head start is capped at grace/2 and drawn from the budget above, so
	// this pause can never push the process past its own grace.
	head := proxyserver.Propagation(grace)
	lc.BeginDraining()
	log.Info().Dur("grace", grace).Dur("propagation", head).Msg("readiness unready; listeners still accepting")
	if head > 0 {
		timer := time.NewTimer(head)
		select {
		case <-timer.C:
		case <-ctx.Done():
			// The grace budget cannot carry the head start after all (only
			// reachable if a caller passed a grace shorter than the cap, which
			// propagation() already guards — kept so the wait can never outlive
			// the process's own budget).
			timer.Stop()
		}
	}

	engineCancel()
	log.Debug().Msg("rotation engine canceled")
	// The warm pool stops next: its parked upstream connections close within
	// the shared budget, before listener drain, so its sockets never outlive
	// the sessions they exist to accelerate.
	warmStop(ctx)
	log.Debug().Msg("warm pool stopped")
	start := time.Now()

	// Step 3a: close every listen socket before draining any of them. Each
	// Server then refuses new sessions from its own Shutdown, and none of them
	// is still accepting while another drains.
	for _, listener := range listeners {
		listener.ln.Close() //nolint:errcheck // stop accepting immediately
	}

	// Step 3b: drain all proxy listeners concurrently under the one shared
	// budget. The admin drain joins the same wait: it has no sessions beyond
	// its own probe requests, so serializing it would only add its share of the
	// budget to the total instead of overlapping it.
	type drainedListener struct {
		name string
		err  error
	}
	results := make(chan drainedListener, len(listeners))
	for _, listener := range listeners {
		listener := listener
		go func() {
			results <- drainedListener{name: listener.name, err: listener.server.Shutdown(ctx)}
		}()
	}
	adminErr := make(chan error, 1)
	go func() { adminErr <- shutdownServer(adminSrv, ctx) }()

	drained := 0
	for range listeners {
		result := <-results
		if result.err != nil {
			log.Warn().Str("listener", result.name).Str("error", sanitize.ErrorString(result.err)).
				Msg("proxy listener closed; grace expired and sessions were force-closed")
			continue
		}
		drained++
		log.Info().Str("listener", result.name).Msg("proxy listener drained")
	}
	// The admin listener only reports a failed graceful shutdown when the
	// budget expired with requests still in flight; it always ends closed
	// either way, so the error is a report, not a branch.
	if err := <-adminErr; err != nil {
		log.Warn().Str("error", sanitize.ErrorString(err)).Msg("admin listener closed; grace expired")
	} else {
		log.Info().Msg("admin listener closed")
	}

	// Terminal: nothing can accept a connection now, so /readyz stops answering
	// "ready" permanently even if something answers the admin socket late.
	lc.MarkStopped()
	log.Info().Int("listeners", len(listeners)).Int("drained", drained).
		Str("elapsed", time.Since(start).Truncate(time.Millisecond).String()).
		Msg("shutdown complete")
}

func shutdownServer(server *http.Server, ctx context.Context) error {
	return server.Shutdown(ctx)
}

func parseZerologLevel(level string) zerolog.Level {
	switch level {
	case "debug":
		return zerolog.DebugLevel
	case "warn":
		return zerolog.WarnLevel
	case "error":
		return zerolog.ErrorLevel
	default:
		return zerolog.InfoLevel
	}
}

// setupDynamicLogger installs the initial global level (the reload loop is
// the only other writer) and returns the process logger.
func setupDynamicLogger(level string) zerolog.Logger {
	zerolog.SetGlobalLevel(parseZerologLevel(level))
	return logging.New(os.Stdout)
}
