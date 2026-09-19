// Command rotation-proxy-gateway runs a SOCKS5 proxy with v4, v6, and mixed
// egress listener views plus an always-on admin listener. Every client tunnel
// is relayed through SOCKS5 routes from a shared health-aware pool.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/pool"
	"rotation-proxy-gateway/internal/proxyserver"
	"rotation-proxy-gateway/internal/rotation"
	"rotation-proxy-gateway/internal/sanitize"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

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
		slog.Error("fatal", "err", sanitize.ErrorString(err))
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

func warnUnavailableKindListeners(log *slog.Logger, cfg *config.RuntimeConfig, bootstrap *config.BootstrapConfig) {
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
		log.Warn("listener has no eligible routes; replying a general SOCKS failure", "listener", "v4")
	}
	if bootstrap.V6ListenAddr != "" && v6 == 0 {
		log.Warn("listener has no eligible routes; replying a general SOCKS failure", "listener", "v6")
	}
}

func run() error {
	bootstrap, err := config.LoadBootstrap()
	if err != nil {
		return err
	}
	runtimeCfg, err := config.LoadRuntime(bootstrap.ConfigFile, bootstrap)
	if err != nil {
		return err
	}

	log, level := setupDynamicLogger(runtimeCfg.LogLevel)
	warnUnavailableKindListeners(log, runtimeCfg, bootstrap)
	// The store publishes one immutable generation (validated config + pool
	// snapshot). Handlers load it once per operation; reload builds the next
	// pool snapshot and swaps the whole generation atomically. The pool serves
	// both origins; manual routes additionally carry rotation state.
	store := pool.NewStore(runtimeCfg, pool.NewRoutes(runtimeCfg.AllRoutes(), runtimeCfg.CooldownBase, runtimeCfg.CooldownMax, runtimeCfg.Balance))
	engine := rotation.New(store, log)

	listeners := make([]runningListener, 0, 3)
	listenerViews := make(map[string]*proxyserver.Server, 3)
	addListener := func(name, addr string, kinds ...config.EgressKind) error {
		if addr == "" {
			return nil
		}
		srv := proxyserver.NewRuntime(store, log, version, name, kinds...)
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
		{"mixed", bootstrap.MixedListenAddr, []config.EgressKind{config.EgressV4, config.EgressV6}},
		{"v4", bootstrap.V4ListenAddr, []config.EgressKind{config.EgressV4}},
		{"v6", bootstrap.V6ListenAddr, []config.EgressKind{config.EgressV6}},
	} {
		if err := addListener(spec.name, spec.addr, spec.kinds...); err != nil {
			return err
		}
	}

	started := time.Now()
	adminSrv := &http.Server{
		Addr:              bootstrap.AdminAddr,
		Handler:           proxyserver.AdminMux(version, started, store, listenerViews, engine.Rotations),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, len(listeners)+1)
	for _, listener := range listeners {
		listener := listener
		go func() {
			log.Info("proxy listening", "listener", listener.name, "addr", listener.ln.Addr().String(), "version", version)
			// Serve returns nil once shutdown closes the listener.
			if err := listener.server.Serve(listener.ln); err != nil {
				errCh <- fmt.Errorf("%s listener: %w", listener.name, err)
			}
		}()
	}
	go func() {
		log.Info("admin listening", "addr", bootstrap.AdminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	// Reloads from the poller arrive on one channel and are handled by this
	// serialized loop; the source label only records how it was reached.
	reload := func(source string) {
		next, err := config.LoadRuntime(bootstrap.ConfigFile, bootstrap)
		if err != nil {
			log.Warn("reload failed; keeping previous configuration", "source", source, "error", sanitize.ErrorString(err))
			return
		}
		// LoadRuntime fully validates before Publish builds the next pool
		// snapshot and swaps the whole generation. Invalid input keeps the
		// previous generation (and its route health) serving untouched.
		store.Publish(next)
		level.Set(parseSlogLevel(next.LogLevel))
		warnUnavailableKindListeners(log, next, bootstrap)
		log.Info("configuration reloaded", "source", source, "upstreams", len(next.AllRoutes()))
	}

	for {
		select {
		case err := <-errCh:
			shutdownAll(engineCancel, listeners, adminSrv, bootstrap.ShutdownGrace)
			return err
		case sig := <-sigCh:
			log.Info("shutting down", "signal", sig.String(), "grace", bootstrap.ShutdownGrace.String())
			shutdownAll(engineCancel, listeners, adminSrv, bootstrap.ShutdownGrace)
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
func shutdownAll(engineCancel context.CancelFunc, listeners []runningListener, adminSrv *http.Server, grace time.Duration) {
	engineCancel()
	ctx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	for _, listener := range listeners {
		listener.ln.Close()           //nolint:errcheck // stop accepting immediately
		listener.server.Shutdown(ctx) //nolint:errcheck // expiry force-closes inside
	}
	shutdownServer(adminSrv, ctx)
}

func shutdownServer(server *http.Server, ctx context.Context) {
	server.Shutdown(ctx) //nolint:errcheck // best-effort
}

func parseSlogLevel(level string) slog.Level {
	switch level {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func setupDynamicLogger(level string) (*slog.Logger, *slog.LevelVar) {
	var current slog.LevelVar
	current.Set(parseSlogLevel(level))
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: &current})), &current
}

// setupLogger remains available to callers that only need a fixed logger.
func setupLogger(level string) *slog.Logger {
	log, _ := setupDynamicLogger(level)
	return log
}
