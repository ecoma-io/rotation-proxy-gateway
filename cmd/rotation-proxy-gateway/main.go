// Command rotation-proxy-gateway runs a SOCKS5-backed HTTP forward proxy
// with v4, v6, and mixed egress listener views plus an always-on admin listener.
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
	"rotation-proxy-gateway/internal/sanitize"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

const shutdownGrace = 10 * time.Second

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
	defer resp.Body.Close()
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
	http   *http.Server
}

func warnUnavailableKindListeners(log *slog.Logger, cfg *config.RuntimeConfig, bootstrap *config.BootstrapConfig) {
	var v4, v6 int
	for _, route := range cfg.Routes {
		switch route.Kind {
		case config.EgressV4:
			v4++
		case config.EgressV6:
			v6++
		}
	}
	if bootstrap.V4ListenAddr != "" && v4 == 0 {
		log.Warn("listener has no eligible routes; returning 502", "listener", "v4")
	}
	if bootstrap.V6ListenAddr != "" && v6 == 0 {
		log.Warn("listener has no eligible routes; returning 502", "listener", "v6")
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
	// pool snapshot and swaps the whole generation atomically.
	store := pool.NewStore(runtimeCfg, pool.NewRoutes(runtimeCfg.Routes, runtimeCfg.CooldownBase, runtimeCfg.CooldownMax))

	listeners := make([]runningListener, 0, 3)
	listenerViews := make(map[string]*proxyserver.Server, 3)
	addListener := func(name, addr string, kinds ...config.EgressKind) {
		if addr == "" {
			return
		}
		srv := proxyserver.NewRuntime(store, log, version, name, kinds...)
		listeners = append(listeners, runningListener{
			name:   name,
			server: srv,
			http: &http.Server{
				Addr:              addr,
				Handler:           srv,
				ReadHeaderTimeout: 30 * time.Second,
				IdleTimeout:       2 * time.Minute,
				// No WriteTimeout: hijacked CONNECT tunnels and streamed bodies
				// must not be cut off mid-flight.
			},
		})
		listenerViews[name] = srv
	}
	addListener("mixed", bootstrap.MixedListenAddr, config.EgressV4, config.EgressV6)
	addListener("v4", bootstrap.V4ListenAddr, config.EgressV4)
	addListener("v6", bootstrap.V6ListenAddr, config.EgressV6)

	started := time.Now()
	adminSrv := &http.Server{
		Addr:              bootstrap.AdminAddr,
		Handler:           proxyserver.AdminMux(version, started, store, listenerViews),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, len(listeners)+1)
	for _, listener := range listeners {
		listener := listener
		go func() {
			log.Info("proxy listening", "listener", listener.name, "addr", listener.http.Addr, "version", version)
			if err := listener.http.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

	watcher := newConfigWatcher(bootstrap.ConfigFile, configPollInterval, log)
	watchCtx, cancelWatch := context.WithCancel(context.Background())
	defer cancelWatch()
	go watcher.Run(watchCtx, log)

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
		log.Info("configuration reloaded", "source", source, "upstreams", len(next.Routes))
	}

	for {
		select {
		case err := <-errCh:
			shutdownAll(listeners, adminSrv)
			return err
		case sig := <-sigCh:
			log.Info("shutting down", "signal", sig.String())
			shutdownAll(listeners, adminSrv)
			return nil
		case <-watcher.Changes():
			// The poller hash-gates on applied content, so one signal means one
			// distinct configuration; no debounce is needed.
			reload("poll")
		}
	}
}

func shutdownAll(listeners []runningListener, adminSrv *http.Server) {
	for _, listener := range listeners {
		shutdownServer(listener.http)
	}
	shutdownServer(adminSrv)
	for _, listener := range listeners {
		listener.server.CloseTunnels() // Shutdown ignores hijacked CONNECT conns
	}
}

func shutdownServer(server *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
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
