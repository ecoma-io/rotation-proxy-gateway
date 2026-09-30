// Command coordhelper is the test harness for the two-process coordination
// tests. It is a real program that drives the real coordinator against a real
// Redis, in its own OS process, so a test can stop it with SIGSTOP and resume it
// with SIGCONT exactly as it would a gateway that paused.
//
// It is not part of the gateway binary and never ships. It exists because the
// scenario the coordination package has to survive — an instance that stops
// renewing long enough to be replaced, then resumes believing it still owns the
// lease — cannot be produced inside one process. An injected clock proves the
// arithmetic; only a second process proves that a real lease really lapses
// against a real authority and that a real takeover really fences it.
//
// Its stdout is a transcript of space-separated key=value fields, one event per
// line, which the parent test parses:
//
//	acquired token=<n> owner=<id>
//	commit-refused fenced_token=<n>
//	adopted_epoch <epoch> notifications=<n> routes_moved=<n>
//
// It reads its configuration from the environment rather than argv, because the
// Redis address may embed a password and argv is world-readable in /proc.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"rotation-proxy-gateway/internal/config"
	"rotation-proxy-gateway/internal/coord"
	"rotation-proxy-gateway/internal/pool"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "coordhelper: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()

	addr := os.Getenv("RPGW_HELPER_REDIS")
	if addr == "" {
		return errors.New("RPGW_HELPER_REDIS is required")
	}
	namespace := os.Getenv("RPGW_HELPER_NAMESPACE")
	leaseName := envOrDefault("RPGW_HELPER_LEASE", coord.DefaultLeaseName)
	route := os.Getenv("RPGW_HELPER_ROUTE")

	// A short lease keeps the test fast. The expiry is still Redis's: the
	// process stops renewing and the key runs out against the server's clock.
	leaseTTL := 1500 * time.Millisecond
	store, err := coord.New(ctx, addr, coord.Options{Namespace: namespace, LeaseTTL: leaseTTL, OpTimeout: 5 * time.Second})
	if err != nil {
		return err
	}
	defer func() { _ = store.Close() }()

	// The controller owns identity and the lease. Its owner id is the process
	// identity, so two helpers are two distinct cluster members.
	ctrl := coord.NewController(store, zerolog.Nop(), coord.ControllerOptions{
		Owner:     os.Getenv("RPGW_HELPER_OWNER") + "-" + instanceID(),
		LeaseName: leaseName,
	})

	// A real generation with one manual route, so epoch adoption has somewhere
	// to land. The route carries no credentials: the tests never exercise a
	// secret path, and a helper that had one would risk writing it to a
	// transcript the test prints on failure.
	gen := pool.NewStore(
		&config.RuntimeConfig{ManualRoutes: []config.ManualRouteSpec{{RouteSpec: config.RouteSpec{Kind: config.EgressV4}}}},
		pool.NewRoutes(nil, time.Second, time.Minute),
	)

	// adoptEpoch is the seam the gateway supplies: raise every route's local
	// epoch to the cluster's, which is what makes internal/warmpool discard
	// connections stamped before it. routes_moved is the pool's own count, not
	// one this helper invents.
	adoptEpoch := func(e coord.Epoch) int {
		g := gen.Load()
		return g.Pool.AdoptClusterEpoch(uint64(e))
	}

	// Readiness: binding the listener is the parent's signal that this process
	// is far enough along to be stopped.
	if listen := os.Getenv("RPGW_HELPER_LISTEN"); listen != "" {
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			return fmt.Errorf("helper readiness listener: %w", err)
		}
		defer func() { _ = ln.Close() }()
	}

	// Keep the lease alive on a ticker. It stops the instant this process is
	// stopped, which is the whole premise: a paused instance cannot renew.
	leaseCtx, stopLease := context.WithCancel(ctx)
	defer stopLease()
	go ctrl.RunLease(leaseCtx)

	// The reconcile loop runs even while this process is stopped — it does not,
	// which is exactly why the test's takeover is not something this process
	// could have prevented.
	watchCtx, stopWatch := context.WithCancel(ctx)
	defer stopWatch()
	go ctrl.Watch(watchCtx, zerolog.Nop(), func(e coord.Epoch) {
		if moved := ctrl.AdoptAll(e, adoptEpoch); moved > 0 {
			fmt.Printf("adopted_epoch %s routes_moved=%d\n", e, moved)
		}
	})

	// Take the lease. If another instance holds it, keep trying: the parent
	// starts B before A lapses, and B must be waiting when the moment comes.
	for ctx.Err() == nil {
		lease, err := ctrl.TryAcquire(ctx)
		switch {
		case err != nil:
			fmt.Fprintf(os.Stderr, "coordhelper: acquire: %v\n", err)
			time.Sleep(50 * time.Millisecond)
		case lease.IsZero():
			// Held elsewhere; keep waiting.
			time.Sleep(50 * time.Millisecond)
		default:
			fmt.Printf("acquired token=%d owner=%s\n", lease.Token, lease.Owner)
			// Hold the lease until the parent tells us to commit or we are
			// stopped. Renewals keep happening in RunLease.
			holdAndReport(ctx, ctrl, lease, route, adoptEpoch)
			return nil
		}
	}
	return ctx.Err()
}

// holdAndReport reports a commit attempt for a held lease.
//
// If the lease is still ours it commits a rotation and reports the epoch. If it
// has been taken over — this process was stopped long enough to be replaced and
// has now resumed — the commit is refused, and the refusal is reported with the
// stale token so the parent can prove which token was fenced.
//
// Nothing local is reported after a refusal, and that absence is asserted: a
// fenced commit must record no observed IP at all.
func holdAndReport(ctx context.Context, ctrl *coord.Controller, lease coord.Lease, route string, adoptEpoch func(coord.Epoch) int) {
	if route == "" {
		// Nothing to commit; just stay alive so the parent can stop and
		// resume this process.
		<-ctx.Done()
		return
	}
	epoch, committed, err := ctrl.CommitRotation(ctx, coord.Commit{
		Lease:      ctrl.Held(),
		Route:      route,
		BaselineIP: "198.51.100.30",
		ObservedIP: "203.0.113.31",
		StartedAt:  time.Now(),
	}, adoptEpoch)
	switch {
	case errors.Is(err, coord.ErrFenced), errors.Is(err, coord.ErrNotHolder):
		fmt.Printf("commit-refused fenced_token=%d\n", lease.Token)
		// Stay alive briefly so the parent can read the transcript, then exit.
		time.Sleep(2 * time.Second)
		return
	case err != nil:
		fmt.Fprintf(os.Stderr, "coordhelper: commit: %v\n", err)
		return
	default:
		fmt.Printf("commit-ok epoch=%s committed=%v\n", epoch, committed)
	}
	<-ctx.Done()
}

// instanceID derives this process's cluster identity from its pid and a random
// suffix, so two helpers started in the same run never collide.
func instanceID() string {
	return fmt.Sprintf("%d-%s", os.Getpid(), coord.GenerateOwnerID())
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
