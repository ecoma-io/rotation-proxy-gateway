# Phase 6 — Traffic admission modes (one procedure, two policies)

Worktree: .claude/worktrees/phase6-traffic-admission (branch johnitvn/phase6-traffic-admission), based off origin/main.

## What exists now

- `internal/config/runtime.go`: added `RotationMode` (`disruptive` default, `seamless`), `RotationSettings.Mode`, `ResolveMode()`, validation in `parseRotationSettings` and `RotationSettings.validate()`.
- `internal/pool/rotation.go`: added `Proxy.AdmitRotationEpoch()` to advance the rotation epoch **without** setting `rotating` (seamless admission). `BeginRotation` still sets `rotating.Store(true)` then increments epoch (flag-then-epoch) as before.
- `internal/rotation/admission.go`: new policy layer. `TrafficAdmissionPolicy` interface with `Name`, `Admit`, `HoldTraffic`, `Readmit`, `ShouldContinue`. `disruptivePolicy` calls `p.BeginRotation(phase)`. `seamlessPolicy` calls `p.AdmitRotationEpoch()` at admission, holds a per-proxy seam state with admission time `visibleAt`, and `ShouldContinue` anchors the 10s changeover timeout to `visibleAt` (not `now`) so polls do not extend it. `releaseHold` is attempt-guarded. `ChangeoverTimeout = 10s`, `holdBackFrom = 200ms`. `Mode` is alias `config.RotationMode`.
- `internal/rotation/engine.go`: `Engine.policyFor` caches per-route seamless policy; `RotationProcedure` carries `policy`, `seam`, and `attempt` (epoch snapshot at admission). Admission point 1: `policy.Admit(..., RotationDraining)`, `rp.attempt = p.RotationEpoch()`. Drain uses `policy.ShouldContinue`. Admission point 2: `policy.HoldTraffic` after rotate call returns (before verify). Admission point 3: after verify, `releaseHold` if seamless. Scheduler drops seamless policy entry when a route leaves config. `runProcedure` calls `policy.Readmit` only on `true` return (completed rotation). No `if mode == seamless` inside the procedure sequence — one body.
- Tests: `internal/rotation/admission_test.go` rewritten to cover shared procedure, disruptive eligibility, seamless serving across rotation, epoch-without-flag, failed verification safety in both modes, collision handling, epoch-once-per-procedure, shutdown-interruption safety, commit-exactly-once, and holdback boundaries. All rotation tests pass.

## Structural evidence (one procedure, two policies)

- `RotationProcedure.run(ctx context.Context) bool` is a single code path: drain → baseline probe → rotate call → verify → commit/abandon → backoff. The only mode-dependent hooks are the three policy calls and the attempt-guarded hold release. The loop `policy.ShouldContinue` replaces what used to be a fixed drain deadline check in effect but is implemented by the policy (disruptive returns deadline unchanged; seamless returns its anchored deadline).
- `policyFor` chooses `disruptivePolicy{}` by default or a cached `seamlessPolicy` for that route id; no second engine.
- Admission hooks: `Admit` (phase), `HoldTraffic` (before verify), `Readmit` (on success). Eligibility remains governed by `p.rotating` (disruptive sets it; seamless never sets it) and the pool's existing predicates — no second eligibility mechanism introduced.

## Where policy hooks into pool

- Only via `Proxy`: `BeginRotation(phase)` (flag + epoch) and `AdmitRotationEpoch()` (epoch only). `PickFor`/`availableAt` still read `rotating` (the same atomic.Bool). In-flight accounting unchanged (`serve()` raises `inFlight` before advancing pass). Warm pool uses `RotationEpoch()` to invalidate parked connections (invariant preserved).

## Epoch handling

- Disruptive: `Admit` calls `BeginRotation` → flag true, epoch++.
- Seamless: `Admit` calls `AdmitRotationEpoch()` → flag remains false, epoch++. Hold release uses attempt-guarded check (`releaseHold` compares against the epoch snapshot at admission). Epoch invariant with warm pool unchanged: connections whose epoch != route's current epoch are discarded.

## Not yet verified (honest list)

- Unmap canonicalisation: AUDITED, invariant already holds. `pool.IPIdentity` canonicalizes via `net.ParseIP(ip).To16()`, which yields the same 16 bytes for `1.2.3.4` and `::ffff:1.2.3.4`, and every rotation comparison (baseline, unverified current-IP, cross-route collision, history membership) goes through it via `CanonicalIP`/`SameIP`. Covered by existing tests `internal/pool/rotation_identity_test.go` (v4 vs mapped form, both directions, and that unrelated addresses do not collapse) and `rotation_history_test.go:129`. No new canonicalisation code was added in this phase. `parseIPLine` rejects non-literals before they reach rotation state. `socksdial` also uses To16 for the wire request, unrelated to egress identity.
- `internal/config/documentkeys.go` on the `configstore-durable` branch: new `rotation.mode` key must be added to the allowlist for the Document→Runtime path; that branch is separate work (not present here).
- No live-provider/e2e validation of seamless (unit tests only). Benchmarks/e2e not run.
- Shutdown path with an active seamless rotation: `runProcedure` respects context cancellation (drain uses context with deadline in scheduler path) and `AbandonRotation`/pool state transitions unchanged; interruption tests pass in unit form but full process shutdown not exercised.
