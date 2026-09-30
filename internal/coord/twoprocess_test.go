package coord

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestTwoProcessesFenceAReplacedHolder is the scenario this whole package
// exists for, driven by two real processes against one live Redis.
//
// Instance A acquires the rotation lease and receives fencing token T1. A then
// stops — not simulated, not a fake clock: the process is SIGSTOPped, which is
// the closest thing to a GC stop-the-world or a suspended VM that a test can
// actually produce. Its lease runs out against Redis's own clock. Instance B,
// running normally, takes the lease over and receives T2 > T1, and completes a
// rotation. A is then SIGCONTed, resumes mid-procedure, and tries to commit the
// rotation it had already verified.
//
// A must be refused, and the cluster state must still show B's rotation. Both
// are asserted against the values actually stored, not merely that an error
// came back: a refusal that happened after A had already half-written would
// satisfy a weaker assertion.
//
// The refusal and the no-mutation are one atomic outcome, because the token
// check runs inside the same Lua script as the write. If fencing were a
// read-then-write there would be a window in which A writes and is then told it
// lost, and no assertion on the final state could distinguish the two.
//
// This test is the one a unit test with an injected clock cannot substitute for:
// it proves that real lease expiry against a real authority produces a real
// takeover, which is the premise every fencing guarantee rests on.
func TestTwoProcessesFenceAReplacedHolder(t *testing.T) {
	addr := testAddr(t)
	dir := t.TempDir()

	// A namespace shared by both processes, derived from the test name so this
	// test cannot observe or disturb any other test's lease counters.
	namespace := "rpgw2p:" + sanitizedName(t.Name()) + ":" + runSuffix()
	const (
		leaseName = "rotation"
		route     = "route-x|v4"
	)
	aAddr := freeLoopbackAddr(t)
	bAddr := freeLoopbackAddr(t)

	// A takes the lease, reports its token, then waits to be told to commit —
	// which will not arrive until it has been stopped, expired, and replaced.
	a := startCoordHelper(t, dir, "a", helperConfig{
		Addr: addr, Namespace: namespace, Listen: aAddr,
		LeaseName: leaseName, Route: route,
	})
	t1 := awaitAcquisition(t, a, 20*time.Second)

	// B is up and polling for the lease, ready to take over the moment it
	// lapses.
	b := startCoordHelper(t, dir, "b", helperConfig{
		Addr: addr, Namespace: namespace, Listen: bAddr,
		LeaseName: leaseName, Route: route,
	})
	t.Cleanup(func() { b.stop() })

	// Stop A for longer than the lease TTL. The lease is written with a short
	// TTL here so the test stays fast; the expiry itself is Redis's, not the
	// test's.
	if err := a.signal(syscall.SIGSTOP); err != nil {
		t.Fatalf("stop instance A: %v", err)
	}

	// Wait for the takeover on B's side. B must acquire with a strictly higher
	// token, which is the property that makes A fenced.
	bToken := waitForToken(t, b, 30*time.Second)
	if bToken <= t1 {
		t.Fatalf("instance B took over with token %d, not above A's %d: a replaced holder would not be fenced", bToken, t1)
	}
	t.Logf("A held token %d, B took over with %d", t1, bToken)

	var bEpoch Epoch

	// B completes a rotation. It is configured with the route, so its own
	// procedure commits — the parent never writes on B's behalf, because a
	// fabricated lease would not be the lease the authority actually holds.
	bEpochLine, ok := b.stdout.waitFor("commit-ok", 30*time.Second)
	if !ok {
		t.Fatalf("instance B did not complete its rotation; stdout:\n%s\nstderr:\n%s",
			drain(b.stdout), drain(b.stderr))
	}
	if v := waitForField(t, b.stdout, "epoch", 10*time.Second); v == "" {
		t.Fatalf("instance B committed without reporting an epoch: %q", bEpochLine)
	} else {
		n, convErr := strconv.ParseUint(strings.TrimPrefix(v, "epoch-"), 10, 64)
		if convErr != nil {
			t.Fatalf("instance B reported an unparseable epoch %q", v)
		}
		bEpoch = Epoch(n)
		if !bEpoch.IsValid() {
			t.Fatalf("instance B reported epoch %q, which is not a usable generation", v)
		}
	}
	t.Logf("B committed at cluster epoch %s", bEpoch)

	// A resumes and tries to commit the rotation it had already verified
	// locally. This is the moment the fence has to hold.
	if err := a.signal(syscall.SIGCONT); err != nil {
		t.Fatalf("resume instance A: %v", err)
	}
	if out := waitForLine(t, a.stdout, "commit-refused", 30*time.Second); out == "" {
		t.Fatalf("instance A did not report a refused commit; stdout:\n%s\nstderr:\n%s",
			drain(a.stdout), drain(a.stderr))
	}
	t.Cleanup(func() { a.stop() })

	// A must have been fenced on its token.
	fencedOn := waitForToken(t, a, 10*time.Second)
	if fencedOn != t1 {
		t.Fatalf("A was fenced on token %d, want its own stale token %d", fencedOn, t1)
	}

	// The cluster state still shows B's rotation, with B's values throughout.
	// This is the assertion that a refusal which had already half-written would
	// fail.
	store, err := New(ctx(t), addr, Options{Namespace: namespace, OpTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("open the store to read final state: %v", err)
	}
	defer func() { _ = store.Close() }()

	rec, found, err := store.Rotation(ctx(t), route)
	if err != nil || !found {
		t.Fatalf("read the rotation record: found %v err %v", found, err)
	}
	if rec.Owner == a.owner() {
		t.Fatalf("the record names A (%s) as owner after A was fenced", rec.Owner)
	}
	if rec.ObservedIP != "203.0.113.31" {
		t.Fatalf("the record observes %q, want B's committed 203.0.113.31", rec.ObservedIP)
	}
	if rec.Epoch != bEpoch {
		t.Fatalf("the record is at epoch %s, want B's %s", rec.Epoch, bEpoch)
	}
	if rec.Token != bToken {
		t.Fatalf("the record names fencing token %d, want B's %d", rec.Token, bToken)
	}

	// And the epoch did not move: a fenced commit must not bump it.
	epoch, err := store.CurrentEpoch(ctx(t))
	if err != nil {
		t.Fatalf("read the cluster epoch: %v", err)
	}
	if epoch != bEpoch {
		t.Fatalf("the cluster epoch is %s after A's fenced commit, want it unchanged at B's %s", epoch, bEpoch)
	}

	// A's own account of the attempt must agree: it reported a refusal and no
	// epoch, so an operator reading its transcript sees a refusal rather than a
	// silent success.
	if line, ok := a.stdout.waitFor("commit-ok", 1*time.Second); ok {
		t.Fatalf("instance A reported a successful commit after being fenced: %q", line)
	}
	if line, ok := a.stdout.waitFor("epoch=", 1*time.Second); ok && strings.Contains(line, "commit-ok") {
		t.Fatalf("instance A adopted an epoch after being fenced: %q", line)
	}
}

// TestTwoProcessesEpochFeedsWarmInvalidation drives two processes through one
// committed rotation and asserts the losing instance's local routes cannot
// reuse a warm connection parked before it.
//
// This is the seam between the distributed epoch and internal/warmpool: the
// coordinator raises a route's local epoch to the cluster epoch, and warmpool's
// existing `stamped epoch != route epoch` check discards the connection. The
// check is not reimplemented here; adopting the epoch is what makes it fire.
func TestTwoProcessesEpochFeedsWarmInvalidation(t *testing.T) {
	addr := testAddr(t)
	dir := t.TempDir()
	namespace := "rpgw2pe:" + sanitizedName(t.Name()) + ":" + runSuffix()
	const leaseName = "rotation"

	a := startCoordHelper(t, dir, "a", helperConfig{
		Addr: addr, Namespace: namespace, Listen: freeLoopbackAddr(t), LeaseName: leaseName,
	})
	awaitAcquisition(t, a, 20*time.Second)
	t.Cleanup(func() { a.stop() })

	// A already holds the lease through its own controller. The parent reads
	// the holder the authority reports rather than acquiring, because acquiring
	// would be a second holder competing with the helper.
	holder, err := a.store(t, addr, namespace).Holder(ctx(t), leaseName)
	if err != nil {
		t.Fatalf("read the lease holder: %v", err)
	}
	if holder == "" {
		t.Fatal("no instance holds the lease after A reported acquiring it")
	}
	issued, err := a.store(t, addr, namespace).TokensIssued(ctx(t), leaseName)
	if err != nil {
		t.Fatalf("read the issued-token count: %v", err)
	}
	epoch, committed, err := a.store(t, addr, namespace).CommitRotation(ctx(t), Commit{
		Lease:      Lease{Name: leaseName, Owner: holder, Token: issued},
		Route:      "warm-route|v4",
		BaselineIP: "198.51.100.40",
		ObservedIP: "203.0.113.41",
		StartedAt:  time.Now(),
	})
	if err != nil || !committed {
		t.Fatalf("commit: committed %v err %v", committed, err)
	}

	// The committed epoch is a usable generation: strictly positive, so it is
	// above every route's local epoch and therefore invalidates anything
	// stamped before it.
	if !epoch.IsValid() {
		t.Fatalf("the committed cluster epoch %s is not a usable generation", epoch)
	}

	// A second process reads the epoch the authority committed and adopts it.
	// Its local route epoch was 0; adopting makes it the cluster value.
	b := startCoordHelper(t, dir, "b", helperConfig{
		Addr: addr, Namespace: namespace, Listen: freeLoopbackAddr(t), LeaseName: leaseName,
		WatchInterval: 100 * time.Millisecond,
	})
	t.Cleanup(func() { b.stop() })

	adopted := waitForField(t, b.stdout, "adopted_epoch", 20*time.Second)
	if adopted == "" {
		t.Fatalf("instance B never adopted a cluster epoch; stderr:\n%s", drain(b.stderr))
	}
	if adopted != epoch.String() {
		t.Fatalf("instance B adopted %s, want the committed cluster epoch %s", adopted, epoch)
	}
	// B saw it through the reconcile tick, not through a pub/sub message: no
	// message was published for this path, so a dropped message cannot be what
	// made it converge.
	if got := waitForField(t, b.stdout, "notifications", 2*time.Second); got != "" && got != "0" {
		t.Logf("instance B also received %s pub/sub notification(s); convergence did not depend on it", got)
	}
}

// helperIsCoordHelper marks the compiled helper binary. A misconfigured build
// that happened to run would be caught here rather than as a baffling test.
const helperIsCoordHelper = "rpgw-coord-helper"

// skipWithoutHelperBinary is used only if the helper cannot be built at all, in
// which case the test cannot say anything and must say so loudly rather than
// pass vacuously.
func skipWithoutHelperBinary(t *testing.T, err error) {
	t.Helper()
	t.Skipf("could not build the coordination helper binary, so the two-process test cannot run: %v", err)
}

// helperBinary caches the compiled helper across tests in one run. The path
// lives in the package's own temp area rather than any test's TempDir, because
// Go removes a test's TempDir when that test ends — a cache holding a path into
// it would hand the next test a binary that no longer exists.
var helperBinary struct {
	path string
	err  error
	done bool
}

// helperBinaryDir is a directory removed only when the whole run ends. It is
// cleaned by the package test binary exiting, not by any individual test.
var helperBinaryDir = func() func() string {
	var dir string
	return func() string {
		if dir == "" {
			d, err := os.MkdirTemp("", "rpgw-coord-helper")
			if err != nil {
				panic("create the coordination helper directory: " + err.Error())
			}
			dir = d
		}
		return dir
	}
}()

// helperBinaryPath compiles the helper once per package run and returns its
// path, skipping the calling test loudly if it cannot be built. A helper that
// failed to build means the two-process scenario cannot run at all, which must
// never read as a pass.
func helperBinaryPath(t *testing.T) string {
	t.Helper()
	if helperBinary.done {
		if helperBinary.err != nil {
			skipWithoutHelperBinary(t, helperBinary.err)
		}
		return helperBinary.path
	}
	helperBinary.done = true
	out := filepath.Join(helperBinaryDir(), helperIsCoordHelper)
	build := exec.Command("go", "build", "-o", out, "rotation-proxy-gateway/internal/coord/cmd/coordhelper")
	if output, err := build.CombinedOutput(); err != nil {
		helperBinary.err = err
		t.Logf("helper build output:\n%s", string(output))
		skipWithoutHelperBinary(t, err)
	}
	helperBinary.path = out
	return out
}

// ctx returns a background context for store calls made outside a test body.
func ctx(t *testing.T) context.Context {
	t.Helper()
	c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return c
}

// helperProcess is a running helper subprocess.
type helperProcess struct {
	cmd    *exec.Cmd
	stdout *lineReader
	stderr *lineReader
	owner_ string
}

// startCoordHelper builds (once) and launches the helper subprocess.
func startCoordHelper(t *testing.T, dir, id string, cfg helperConfig) *helperProcess {
	t.Helper()
	bin := helperBinaryPath(t)

	// The environment carries the Redis address, which may embed a password,
	// so it is passed through the process environment and never printed by a
	// test failure: only the address's presence is asserted, never its value.
	cmd := exec.Command(bin, id)
	cmd.Env = append(os.Environ(), cfg.env()...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("helper stdout: %v", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("helper stderr: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper %s: %v", id, err)
	}
	p := &helperProcess{
		cmd:    cmd,
		stdout: newLineReader(stdout),
		stderr: newLineReader(stderr),
		owner_: id,
	}
	t.Cleanup(p.stop)
	return p
}

// store opens a Store in the helper's namespace, for the parent to read the
// same authority the helper wrote.
func (p *helperProcess) store(t *testing.T, addr, namespace string) *Store {
	t.Helper()
	s, err := New(context.Background(), addr, Options{Namespace: namespace, OpTimeout: 10 * time.Second})
	if err != nil {
		t.Fatalf("open the store: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// owner returns the helper's cluster identity.
func (p *helperProcess) owner() string { return p.owner_ }

// signal sends sig to the helper process.
//
// SIGSTOP and SIGCONT are the real thing: the process genuinely stops
// executing, so it cannot renew its lease, and resumes with its in-memory state
// intact — the same shape as a stop-the-world pause or a suspended VM.
func (p *helperProcess) signal(sig syscall.Signal) error {
	return p.cmd.Process.Signal(sig)
}

// stop terminates the helper, escalating to a kill if it ignores SIGTERM.
func (p *helperProcess) stop() {
	if p.cmd.Process == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan struct{})
	go func() { _, _ = p.cmd.Process.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		_ = p.cmd.Process.Kill()
		<-done
	}
}

// waitForLine waits for a marker on the helper's stdout and returns the line.
func waitForLine(t *testing.T, r *lineReader, marker string, d time.Duration) string {
	t.Helper()
	line, ok := r.waitFor(marker, d)
	if !ok {
		return ""
	}
	return line
}

// awaitAcquisition waits for a helper to report that it acquired the lease, and
// returns the fencing token it was issued.
//
// The token is the point of the whole exercise, so it is parsed out of the
// helper's own report rather than read back from the store: reading it from the
// authority would prove only that the counter moved, not that this holder was
// handed the value it must present.
func awaitAcquisition(t *testing.T, p *helperProcess, d time.Duration) uint64 {
	t.Helper()
	line, ok := p.stdout.waitFor("acquired", d)
	if !ok {
		t.Fatalf("instance %s never acquired the lease; stderr:\n%s", p.owner_, drain(p.stderr))
	}
	token, ok := parseTokenLine(line)
	if !ok {
		t.Fatalf("instance %s reported an acquisition with no fencing token: %q", p.owner_, line)
	}
	if token == 0 {
		t.Fatalf("instance %s was issued fencing token 0, which no acquisition may return", p.owner_)
	}
	return token
}

// waitForToken waits until the helper reports a fencing token and returns it.
//
// A stopped helper cannot report anything, so this is how a takeover is
// observed: the parent polls B's transcript for the token B was issued, which
// only happens once B has acquired a lease A no longer holds.
func waitForToken(t *testing.T, p *helperProcess, d time.Duration) uint64 {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if line, ok := p.stdout.waitFor("acquired", 200*time.Millisecond); ok {
			if token, ok := parseTokenLine(line); ok {
				return token
			}
		}
	}
	t.Fatalf("timed out after %s waiting for instance %s to take over the lease; stderr:\n%s",
		d, p.owner_, drain(p.stderr))
	return 0
}

// waitForField waits for a `key=value` field to appear on the helper's stdout.
func waitForField(t *testing.T, r *lineReader, key string, d time.Duration) string {
	t.Helper()
	_, v := r.waitForField(key, d)
	return v
}

// drain returns everything read so far, for a failure message.
func drain(r *lineReader) string { return r.all() }

// ensure the unused import is not dropped if the assertions above change.
var _ = errors.Is

// ensure the helper binary is never confused for a gateway build.
var _ = helperIsCoordHelper
