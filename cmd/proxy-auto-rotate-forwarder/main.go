// Command proxy-auto-rotate-forwarder runs a SOCKS5-backed HTTP forward proxy
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
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"

	"proxy-auto-rotate-forwarder/internal/config"
	"proxy-auto-rotate-forwarder/internal/pool"
	"proxy-auto-rotate-forwarder/internal/proxyserver"
	"proxy-auto-rotate-forwarder/internal/sanitize"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

const (
	shutdownGrace  = 10 * time.Second
	reloadDebounce = 250 * time.Millisecond
)

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
		host, port = addr, ""
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
	store := config.NewStore(runtimeCfg)
	pl := pool.NewRoutes(runtimeCfg.Routes, runtimeCfg.CooldownBase, runtimeCfg.CooldownMax)

	listeners := make([]runningListener, 0, 3)
	listenerViews := make(map[string]*proxyserver.Server, 3)
	addListener := func(name, addr string, kinds ...config.EgressKind) {
		if addr == "" {
			return
		}
		srv := proxyserver.NewRuntime(pl, store, log, version, name, kinds...)
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
		Handler:           proxyserver.AdminMux(version, started, pl, listenerViews),
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

	watchEvents := make(chan fsnotify.Event, 1)
	watcher, err := config.WatchRuntime(bootstrap.ConfigFile, func(event fsnotify.Event) {
		select {
		case watchEvents <- event:
		default:
		}
	})
	if err != nil {
		shutdownAll(listeners, adminSrv)
		return fmt.Errorf("watch runtime config: %w", err)
	}
	// Viper owns the fsnotify watcher. Keep the instance reachable for the
	// process lifetime; its callback feeds the serialized loop below.
	_ = watcher

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	var reloadMu sync.Mutex
	reload := func(source string) {
		reloadMu.Lock()
		defer reloadMu.Unlock()
		next, err := config.LoadRuntime(bootstrap.ConfigFile, bootstrap)
		if err != nil {
			log.Warn("reload failed; keeping previous configuration", "source", source, "error", sanitize.ErrorString(err))
			return
		}
		// All validation is complete before any mutable serving state changes.
		pl.ReloadRoutes(next.Routes)
		pl.SetCooldowns(next.CooldownBase, next.CooldownMax)
		store.Store(next)
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
			if sig == syscall.SIGHUP {
				reload("sighup")
				continue
			}
			log.Info("shutting down", "signal", sig.String())
			shutdownAll(listeners, adminSrv)
			return nil
		case <-watchEvents:
			// Editors and bind-mount updaters commonly emit several events for
			// one atomic rewrite. Coalesce the burst before parsing the file.
			timer := time.NewTimer(reloadDebounce)
			draining := true
			for draining {
				select {
				case <-watchEvents:
					if !timer.Stop() {
						select {
						case <-timer.C:
						default:
						}
					}
					timer.Reset(reloadDebounce)
				case <-timer.C:
					draining = false
				}
			}
			reload("watch")
		}
	}
}

func shutdownAll(listeners []runningListener, adminSrv *http.Server) {
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	for _, listener := range listeners {
		listener.http.Shutdown(sctx) //nolint:errcheck // best-effort
	}
	adminSrv.Shutdown(sctx) //nolint:errcheck // best-effort
	for _, listener := range listeners {
		listener.server.CloseTunnels() // Shutdown ignores hijacked CONNECT conns
	}
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
