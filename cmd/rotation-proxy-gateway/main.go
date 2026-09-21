// Command rotation-proxy-gateway runs a SOCKS5 proxy with v4, v6, and mixed
// egress listener views plus an always-on admin listener. Every client tunnel
// is relayed through SOCKS5 routes from a shared health-aware pool.
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

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Println(version)
			return
		case "healthcheck":
			os.Exit(healthcheck())
		}
	}
	if err := run(); err != nil {
		fatalLog.Error().Str("err", sanitize.ErrorString(err)).Msg("fatal")
		os.Exit(1)
	}
}

// healthcheck probes the bootstrap-configured admin listener. It deliberately
// does not parse runtime YAML: a bad reload must not make a healthy, already
// running process fail Docker's health probe.
func healthcheck() int {
	cfg, err := config.LoadBootstrap()
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrap config:", sanitize.ErrorString(err))
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(healthcheckURL(cfg.AdminAddr))
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", sanitize.ErrorString(err))
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	if resp.StatusCode != http.StatusOK || string(body) != "ok\n" {
		fmt.Fprintf(os.Stderr, "healthcheck: status %d, body %q\n", resp.StatusCode, body)
		return 1
	}
	return 0
}

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
	return (&url.URL{Scheme: "http", Host: net.JoinHostPort(host, port), Path: "/healthz"}).String()
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
		log.Warn().Str("listener", "v4").Msg("listener has no eligible routes; replying a general SOCKS failure")
	}
	if bootstrap.V6ListenAddr != "" && v6 == 0 {
		log.Warn().Str("listener", "v6").Msg("listener has no eligible routes; replying a general SOCKS failure")
	}
}

func run() error {
	bootstrap, err := config.LoadBootstrap()
	if err != nil {
		return err
	}
	runtimeCfg, err := config.LoadRuntime(bootstrap.ConfigFile)
	if err != nil {
		return err
	}

	log := setupDynamicLogger(runtimeCfg.LogLevel)
	warnUnavailableKindListeners(log, runtimeCfg, bootstrap)
	// The store publishes one immutable generation (validated config + pool
	// snapshot). Handlers load it once per operation; reload builds the next
	// pool snapshot and swaps the whole generation atomically. The pool serves
	// both origins; manual routes additionally carry rotation state.
	store := pool.NewStore(runtimeCfg, pool.NewRoutes(runtimeCfg.AllRoutes(), runtimeCfg.CooldownBase, runtimeCfg.CooldownMax))
	engine := rotation.New(store, log)
	// The warm pool keeps half-established upstream connections ready for the
	// serving path to borrow (one non-blocking pop per attempt, cold dial on
	// any miss) while never writing route health itself: cooldown, auth, and
	// rotation state change only on the request path. It follows config
	// generations on its own; a disabled config parks it at zero idle
	// connections and every dial is cold again.
	warm := warmpool.New(store, log, nil)

	listeners := make([]runningListener, 0, 3)
	listenerViews := make(map[string]*proxyserver.Server, 3)
	addListener := func(name, addr string, kinds ...config.EgressKind) error {
		if addr == "" {
			return nil
		}
		srv := proxyserver.NewRuntime(store, log, version, name, kinds...)
		srv.UseWarmPool(warm)
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
	adminSrv := &http.Server{
		Handler:           proxyserver.AdminMux(version, started, store, listenerViews, engine.Rotations, warm.Snapshot),
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

	poller := config.NewPoller(bootstrap.ConfigFile, config.DefaultPollInterval, log)
	pollCtx, cancelPoll := context.WithCancel(context.Background())
	defer cancelPoll()
	go poller.Run(pollCtx, log)

	// The rotation engine owns manual-route egress IP rotation. Its context is
	// canceled before the listeners drain so in-flight rotations stop promptly
	// and never extend shutdown beyond the shared grace budget.
	engineCtx, engineCancel := context.WithCancel(context.Background())
	defer engineCancel()
	go engine.Run(engineCtx)
	warm.Start()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Reloads from the poller arrive on one channel and are handled by this
	// serialized loop; the source label only records how it was reached.
	reload := func(source string) {
		next, err := config.LoadRuntime(bootstrap.ConfigFile)
		if err != nil {
			log.Warn().Str("source", source).Str("error", sanitize.ErrorString(err)).Msg("reload failed; keeping previous configuration")
			return
		}
		// LoadRuntime fully validates before Publish builds the next pool
		// snapshot and swaps the whole generation. Invalid input keeps the
		// previous generation (and its route health) serving untouched.
		store.Publish(next)
		// Only this goroutine writes the global level, so the package-global
		// atomic swap is race-free and every future event picks it up.
		zerolog.SetGlobalLevel(parseZerologLevel(next.LogLevel))
		warnUnavailableKindListeners(log, next, bootstrap)
		log.Info().Str("source", source).Int("upstreams", len(next.AllRoutes())).Msg("configuration reloaded")
	}

	for {
		select {
		case err := <-errCh:
			shutdownAll(log, engineCancel, warm.Stop, listeners, adminSrv, bootstrap.ShutdownGrace)
			return err
		case sig := <-sigCh:
			log.Info().Str("signal", sig.String()).Str("grace", bootstrap.ShutdownGrace.String()).Msg("shutting down")
			shutdownAll(log, engineCancel, warm.Stop, listeners, adminSrv, bootstrap.ShutdownGrace)
			return nil
		case <-poller.Changes():
			// The poller hash-gates on applied content, so one signal means one
			// distinct configuration; no debounce is needed.
			reload("poll")
		}
	}
}

// shutdownAll stops the rotation engine first, then closes every proxy
// listener socket and drains each one's active SOCKS sessions plus the admin
// listener against one shared grace budget. A drained listener returns
// immediately, so an idle process exits at once; once the budget expires the
// remaining sessions' client connections are force-closed and later listeners
// stop waiting. Established tunnels are never broken before that deadline.
//
// Budget invariant: every listener shares the one ctx deadline, so the worst
// case is grace plus the per-listener force-close tail (proxyserver's
// forceCloseWait, 1s) times the three listeners, plus the admin shutdown —
// with the default 55s grace that is ~58s, and the surrounding orchestrator's
// kill timer (compose stop_grace_period: 60s) must stay above it.
func shutdownAll(log zerolog.Logger, engineCancel context.CancelFunc, warmStop func(), listeners []runningListener, adminSrv *http.Server, grace time.Duration) {
	engineCancel()
	log.Debug().Msg("rotation engine canceled")
	// The warm pool stops next: its parked upstream connections close within
	// a bounded wait, before listener drain, so its sockets never outlive the
	// sessions they exist to accelerate.
	warmStop()
	log.Debug().Msg("warm pool stopped")
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	start := time.Now()
	drained := 0
	for _, listener := range listeners {
		listener.ln.Close() //nolint:errcheck // stop accepting immediately
		if err := listener.server.Shutdown(ctx); err != nil {
			log.Warn().Str("listener", listener.name).Str("error", sanitize.ErrorString(err)).
				Msg("proxy listener closed; grace expired and sessions were force-closed")
			continue
		}
		drained++
		log.Info().Str("listener", listener.name).Msg("proxy listener drained")
	}
	if err := shutdownServer(adminSrv, ctx); err != nil {
		log.Warn().Str("error", sanitize.ErrorString(err)).Msg("admin listener closed; grace expired")
	} else {
		log.Info().Msg("admin listener closed")
	}
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
