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
	"net/url"
	"os"
	"os/signal"
	"sync"
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
	// to land. A pool with zero routes would report nothing to adopt and the
	// warm-connection invalidation this exercise exists to demonstrate would
	// never be exercised.
	//
	// The route carries no credentials. The tests never exercise a secret path,
	// and a helper that had one would risk writing it into a transcript the
	// test prints on failure. The URL is loopback so nothing dials out.
	routeURL, err := url.Parse("socks5://127.0.0.1:1")
	if err != nil {
		return err
	}
	cfg := &config.RuntimeConfig{
		ManualRoutes: []config.ManualRouteSpec{{
			RouteSpec:      config.RouteSpec{URL: routeURL, Kind: config.EgressV4},
			RotateInterval: time.Hour,
		}},
	}
	gen := pool.NewStore(cfg, pool.NewRoutes(cfg.AllRoutes(), time.Second, time.Minute))

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
		moved := ctrl.AdoptAll(e, adoptEpoch)
		// Report every adoption, including one that moved no routes. The parent
		// distinguishes "observed the epoch and had nothing to move" from
		// "never observed it", which are different failures.
		fmt.Printf("adopted_epoch=%s routes_moved=%d\n", e, moved)
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
			// The procedure is now "in flight": the route is drained and the
			// egress IP verified locally, but nothing has been committed to the
			// cluster. Commit immediately unless this instance is meant to be
			// paused mid-procedure (test A).
			holdAndReport(ctx, ctrl, lease, route, adoptEpoch, gen)
			return nil
		}
	}
	return ctx.Err()
}

// holdAndReport holds an acquired lease until the parent tells this process to
// commit, then attempts the commit and reports what the authority decided.
//
// The wait is what makes the scenario real. A procedure that committed the
// instant it acquired would leave nothing to fence: the instance would already
// have written before the parent could stop it. Holding here means the parent
// can SIGSTOP this process with a verified-but-uncommitted rotation in hand,
// which is the exact state a gateway is in between its verify step and its
// commit.
//
// When the commit finally runs:
//
//   - If the lease is still ours, it commits and reports the epoch.
//   - If the lease was taken over while this process was stopped, the commit is
//     refused and the refusal is reported with the stale token, so the parent
//     can prove which token was fenced.
//
// Nothing local is reported after a refusal, and that absence is asserted by
// the parent: a fenced commit must record no observed IP at all.
func holdAndReport(
	ctx context.Context,
	ctrl *coord.Controller,
	lease coord.Lease,
	route string,
	adoptEpoch func(coord.Epoch) int,
	gen *pool.Store,
) {
	if route == "" {
		// Nothing to commit; just stay alive so the parent can stop and
		// resume this process.
		<-ctx.Done()
		return
	}

	// Report the procedure as in flight and verified-but-uncommitted. If this
	// is the paused instance, wait for the gate to open (on SIGCONT). Otherwise
	// commit immediately so the takeover proceeds without waiting.
	fmt.Printf("verified observed=203.0.113.31 pending=1\n")
	if os.Getenv("RPGW_HELPER_WAIT") != "" {
		<-commitGate()
	}

	// Re-read the lease the authority actually holds rather than trusting the
	// one captured at acquisition. After a pause it may be gone, and using the
	// stale copy is precisely the bug this scenario reproduces: the process
	// believes it still owns the lease.
	held := ctrl.Held()
	epoch, committed, err := ctrl.CommitRotation(ctx, coord.Commit{
		Lease:      held,
		Route:      route,
		BaselineIP: "198.51.100.30",
		ObservedIP: "203.0.113.31",
		StartedAt:  time.Now(),
	}, func(e coord.Epoch) int {
		g := gen.Load()
		return g.Pool.AdoptClusterEpoch(uint64(e))
	})
	switch {
	case errors.Is(err, coord.ErrFenced):
		fmt.Printf("commit-refused fenced_token=%d reason=fenced\n", lease.Token)
		// Stay alive briefly so the parent can read the transcript.
		time.Sleep(2 * time.Second)
		return
	case errors.Is(err, coord.ErrNotHolder):
		fmt.Printf("commit-refused fenced_token=%d reason=not_holder\n", lease.Token)
		time.Sleep(2 * time.Second)
		return
	case err != nil:
		fmt.Fprintf(os.Stderr, "coordhelper: commit: %v\n", err)
		time.Sleep(2 * time.Second)
		return
	default:
		fmt.Printf("commit-ok epoch=%s committed=%v routes_moved=%d\n", epoch, committed, adoptEpoch(epoch))
	}
	<-ctx.Done()
}

// commitGate blocks until this process is told to commit, or the process is
// stopped. It is closed by SIGCONT resuming the helper after a pause.
//
// The distinction that matters: while stopped the helper executes nothing, so
// it cannot commit. That is what the scenario needs — an instance that is
// mid-procedure and unaware its lease lapsed.
func commitGate() <-chan struct{} {
	gateOnce.Do(func() {
		gate = make(chan struct{})
		// A resumed process opens its gate. Detecting the resume rather than
		// polling keeps the helper honest: it commits when it is actually
		// running again, not on a timer that might fire while it is stopped.
		sigs := make(chan os.Signal, 4)
		signal.Notify(sigs, syscall.SIGCONT)
		go func() {
			<-sigs
			select {
			case <-gate:
			default:
				close(gate)
			}
		}()
	})
	return gate
}

var (
	gateOnce sync.Once
	gate     chan struct{}
)

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
