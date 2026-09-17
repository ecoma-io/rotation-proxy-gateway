// Command proxy-auto-rotate-forwarder runs a zero-dependency HTTP forward
// proxy that rotates across a pool of upstream proxies, auto-rotating on
// failure with exponential cooldown, plus an always-on admin listener
// (healthz, status) and SIGHUP pool reload.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"proxy-auto-rotate-forwarder/internal/config"
	"proxy-auto-rotate-forwarder/internal/pool"
	"proxy-auto-rotate-forwarder/internal/proxyserver"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "dev"

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
		slog.Error("fatal", "err", err.Error())
		os.Exit(1)
	}
}

// healthcheck probes the admin listener's /healthz; used by Docker
// HEALTHCHECK (there is no shell in the scratch image). Exit 1 on failure.
func healthcheck() int {
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "config:", err)
		return 1
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + cfg.AdminAddr + "/healthz")
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
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

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	log := setupLogger(cfg.LogLevel)
	urls, err := config.ParseProxies(cfg.ProxiesFile)
	if err != nil {
		return fmt.Errorf("load proxies: %w", err)
	}
	pl := pool.New(urls, cfg.Mode, cfg.CooldownBase, cfg.CooldownMax)
	srv := proxyserver.New(pl, cfg, log, version)

	proxySrv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           srv,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		// No WriteTimeout: hijacked CONNECT tunnels and streamed bodies must
		// not be cut off mid-flight.
	}
	adminSrv := &http.Server{
		Addr:              cfg.AdminAddr,
		Handler:           srv.AdminMux(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}

	errCh := make(chan error, 2)
	go func() {
		log.Info("proxy listening", "addr", cfg.ListenAddr, "upstreams", len(urls), "mode", string(cfg.Mode), "version", version)
		if err := proxySrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()
	go func() {
		log.Info("admin listening", "addr", cfg.AdminAddr)
		if err := adminSrv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	for {
		select {
		case err := <-errCh:
			shutdownAll(proxySrv, adminSrv, srv)
			return err
		case sig := <-sigCh:
			if sig == syscall.SIGHUP {
				// Reload the pool file; keep serving with the old pool on
				// error.
				if err := reload(pl, srv, cfg, log); err != nil {
					log.Warn("reload failed; keeping previous pool", "err", err.Error())
				}
				continue
			}
			log.Info("shutting down", "signal", sig.String())
			shutdownAll(proxySrv, adminSrv, srv)
			return nil
		}
	}
}

func shutdownAll(proxySrv, adminSrv *http.Server, srv *proxyserver.Server) {
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	proxySrv.Shutdown(sctx) //nolint:errcheck // best-effort
	adminSrv.Shutdown(sctx) //nolint:errcheck // best-effort
	srv.CloseTunnels()      // Shutdown ignores hijacked CONNECT conns
}

func reload(pl *pool.Pool, srv *proxyserver.Server, cfg *config.Config, log *slog.Logger) error {
	urls, err := config.ParseProxies(cfg.ProxiesFile)
	if err != nil {
		return err
	}
	pl.Reload(urls)
	srv.ResetTransports()
	log.Info("pool reloaded", "upstreams", len(urls))
	return nil
}

func setupLogger(level string) *slog.Logger {
	lvl := slog.LevelInfo
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	}
	return slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
