# e2e benchmarks

These benchmarks measure the gateway's end-to-end overhead with the real
binary, a real SOCKS5 hop (`SocksSim`), and a real HTTP target. They exist so
optimization work is grounded in measured deltas on the machine that matters.

## What changed in the SOCKS5 migration

These numbers were captured **after** the gateway's migration from an inbound
HTTP forward proxy to an inbound SOCKS5-only server (RFC 1928 no-auth,
CONNECT-only; a pure TCP relay once the tunnel is up). The HTTP-era benchmarks
were deleted with the buffered/streaming body distinction that no longer
exists.

The per-request cost through the gateway is now **one inbound SOCKS5 handshake
plus one outbound SOCKS5 handshake** per tunnel: no HTTP parsing, no body
buffering, no request replay in the gateway. HTTP exists only at the two ends.
Post-migration baselines must be captured fresh — the numbers are **not
comparable** to the old HTTP-era benchmarks, which measured a different path
(and the throughput expectations changed character entirely).

## Workflow

Recorded baseline numbers are deliberately **not** stored here: throughput and
latency differ across hardware, so a committed number goes stale immediately.
Before optimizing:

1. On your machine, at the commit you are about to change:

   ```bash
   go test ./e2e/ -run=NONE -bench=. -benchmem -count=5 > /tmp/bench-before.txt
   ```

2. Make the change, then run the same command into `bench-after.txt`.
3. Compare distributions, not single runs — `benchstat` (golang.org/x/perf)
   is the standard tool:

   ```bash
   go run golang.org/x/perf/cmd/benchstat@latest /tmp/bench-before.txt /tmp/bench-after.txt
   ```

4. Claim an improvement only when the delta is statistically significant
   (benchstat shows it) and repeats agree.

## What each benchmark measures

| Benchmark                             | Path exercised                                                                         | What it isolates                                  |
| ------------------------------------- | -------------------------------------------------------------------------------------- | ------------------------------------------------- |
| `BenchmarkDirect_SmallGET`            | client → target with no proxy: the floor                                               | pure HTTP baseline                                |
| `BenchmarkProxied_SmallGET`           | client → gateway → SOCKS5 → target, small GET                                          | setup latency + relay for one full request        |
| `BenchmarkProxied_SmallGETParallel`   | same, fresh tunnel per request, `GOMAXPROCS` workers                                   | per-request setup under concurrency               |
| `BenchmarkProxied_TunnelSetup`        | inbound SOCKS5 greet/CONNECT → route pick → outbound SOCKS5 setup, then close; no HTTP | setup-latency floor: the double handshake alone   |
| `BenchmarkProxied_BulkGET_1MiB`       | one tunnel reused, 1MiB HTTP response relayed per iteration (`SetBytes` reports MB/s)  | relay throughput, setup excluded                  |
| `BenchmarkHA_SingleProxyDowntime`     | 4 routes, continuous load; one route down 2.5s mid-window, back at 5s                  | availability and tail latency across one failure  |
| `BenchmarkHA_ConcurrentDowntime`      | same, but two of four routes fail at the same instant                                  | fallback behavior under concurrent failures       |
| `BenchmarkHA_RotationUnderTraffic`    | 2 manual routes rotating every 1.5s under continuous load                              | what rotation windows cost a serving pool         |
| `BenchmarkHA_BurstExhaust`            | 2-worker steady load → 32-worker burst → steady load again, all on 4 routes            | burst absorption and post-burst recovery          |
| `BenchmarkWarmAB_SteadyTunnels`       | paired gateways (warm off vs on), 2 workers, fresh tunnel + small GET per op           | steady-state latency effect of borrowing          |
| `BenchmarkWarmAB_TunnelSetupOnly`     | paired gateways, 1 worker, tunnels opened and closed with no payload                   | pure setup cost a parked connection removes       |
| `BenchmarkWarmAB_BurstExhaust`        | paired gateways: low → 32-worker burst → low, on 4 routes                              | burst fallback and post-burst recovery under warm |
| `BenchmarkWarmHA_SingleProxyDowntime` | paired gateways over the HA single-failure scenario, warm off vs on                    | failure-window behavior with parked connections   |
| `BenchmarkWarmHA_ConcurrentDowntime`  | paired gateways over the concurrent-failure scenario, warm off vs on                   | discard/fallback when half the pool dies          |

The gap between `Direct` and `Proxied` small GET is the full per-request cost
of one gateway hop plus one SOCKS5 hop: the per-tunnel inbound and outbound
handshakes plus the relay of the small HTTP exchange through them.

`Proxied_TunnelSetup` and `Proxied_SmallGET` split the setup-latency side of
that gap into its parts: the former measures the double handshake with no HTTP
on top, so its value subtracted from the small GET is roughly the cost of
speaking HTTP through an established tunnel. `Proxied_BulkGET_1MiB` measures
the other axis — steady-state relay throughput — with setup removed from the
timed loop entirely (the tunnel is established once, before `ResetTimer`).

## HA scenarios

The `BenchmarkHA_*` set (ha_test.go) measures **traffic-level outcomes**, not
setup or relay cost. Each iteration runs one full 8s scenario window against a
fresh gateway, sims, and target, with a worker pool driving fresh-tunnel
requests through the mixed listener continuously (`runLoad` in load_test.go).
Failures are injected at fixed offsets (down at 2.5s, recovered at 5s) so every
iteration sees the same shape; HA gateways use a 1s/5s cooldown so a recovered
route is re-admitted inside the window. Reported metrics per benchmark:

- `success_ratio`, `failed_ops`, `p50_ms`/`p95_ms`/`p99_ms` over successful
  operations — the client-visible distribution, not pool internals.
- Downtime benchmarks additionally report `downtime_*` (operations completing
  inside the failure window) and `recovered_*` (after recovery).
- `BenchmarkHA_BurstExhaust` prefixes each phase (`low1_`, `burst_`, `low2_`).
- `BenchmarkHA_RotationUnderTraffic` reports `rotations` completed in-window.

These benchmarks assert nothing — functional tests own correctness; the HA
numbers exist to compare behavior changes (for example a connection-pooling
feature) as distributions: a change is only acceptable if `success_ratio` does
not regress and tail latency during failure windows does not worsen. Run the
same before/after workflow as above:

```bash
go test ./e2e/ -run=NONE -bench=HA -benchmem -count=5 > /tmp/ha-before.txt
```

One scenario window is several seconds long, so each HA benchmark takes
roughly (count × iterations × window) wall-clock; keep that in mind when
raising `-count`.

## Cold vs warm A/B

The `BenchmarkWarmAB_*` set (warmab_test.go) and `BenchmarkWarmHA_*` set
(warmha_test.go) are **paired**: one iteration runs the identical scenario
against two fresh gateways — `warm-pool.enabled: false` (control, reported
under `cold_`) and `true` (candidate, under `warm_`) — inside the same
process, back to back, so machine drift lands on both sides of the pair.
benchstat over `-count` runs then reads each `cold_*`/`warm_*` column pair.

The upstream latency is the scenario axis (`rtt=0s/10ms/30ms`
sub-benchmarks): the sims delay every SOCKS5 reply by that amount, shaping
the upstream as a remote endpoint whose greeting and CONNECT each cost one
network round trip — exactly the setup a parked half-handshake removes. At
`rtt=0s` upstream setup is nearly free loopback, the hardest case for any
warm pool.

`warm_borrow_ratio` (borrowed ÷ successful ops) proves which path actually
served: near 1.0 means the pool kept up with consumption (borrow wakes the
replenisher); a low value means the window fell back to cold dials — an
honest measurement of a pool outpaced, not a broken benchmark.

```bash
# /tmp on this class of machine can be a small tmpfs; the e2e binary build
# needs real space — point TMPDIR at the root filesystem when in doubt.
TMPDIR=~/.tmp-bench go test ./e2e/ -run=NONE -bench='WarmAB|WarmHA' -count=5 \
  | tee /tmp/warmab.txt
benchstat /tmp/warmab.txt
```

First measurement of the warm pool (i7-10700K, 2026-09-21, `count=5`
medians, min-idle 2 / max-idle 4 per route): steady and setup-only p50/p95
improve by **one upstream RTT** — 21.1→10.9ms at rtt=10ms (−48%), 61.3→31.1ms
at rtt=30ms (−49%) — with borrow_ratio ≈ 1.0; at rtt=0s the win shrinks to
~20% (0.38→0.30ms), the expected floor. Under a 32-worker burst the pool
falls back cold (borrow_ratio 0.28–0.62) and the burst window tracks the
control within noise, while the low-load phases around it keep the full
steady-state win. Absolute numbers age; the **shape** is the reproducible
claim: one RTT of upstream setup removed per borrow, zero regression when
the pool is exhausted.

## Interpretation caveats — read before drawing conclusions

- The setup-latency benchmarks (`SmallGET`, `SmallGETParallel`, `TunnelSetup`)
  are dominated by **connection setup, not copying**: each test iteration opens
  a fresh inbound SOCKS5 tunnel through the gateway plus a fresh outbound SOCKS5
  tunnel through the route, and closes it. Copy-path optimizations cannot move
  these numbers; connection reuse would be a behavior change, not a tuning knob
  (keep-alives are deliberately disabled so every iteration is one new tunnel).
- The relay-throughput benchmark (`BulkGET_1MiB`) is the complement: it reuses
  one tunnel for all iterations so `ns/op` reflects bytes moved end-to-end, and
  `B/op`/`allocs/op` capture the in-process client write, `ReadResponse`, and
  discard copies per iteration.
- `B/op` and `allocs/op` cover **the test process only** (client + SOCKS sim +
  HTTP target server, which are in-process). The gateway is a separate OS
  process; its memory is invisible to these counters, though its cost is
  included in ns/op. Gateway-internal allocation or pick-path work therefore
  needs the in-process micro-benches instead: `internal/socksdial`
  (`BenchmarkDial`, `BenchmarkDialAuthenticated` — full outbound handshake per
  iteration) and `internal/pool` (`BenchmarkPickFor`, `BenchmarkPickForBalanced`
  — pick, report, release under full parallelism). Loopback e2e `ns/op` is
  handshake-RTT-dominated and routinely cannot resolve a real few-percent
  gateway win; a pinned unit test (for example the inbound framing read
  budget) can prove a deterministic improvement the benchmark cannot see.
- The echo/bulk body target (a prebuilt `[]byte` written per request) and the
  in-process SOCKS sim contribute their own allocations to proxied benchmarks;
  same-target before/after comparisons cancel them out, absolute values do not.
- Bench configs use `log-level: error` so logging stays out of the
  measurement; benchmarks skip under `-test.short` like the rest of the
  package.
- Use the same `-benchtime` and `-count` for before/after; `-count≥5` plus
  benchstat is the minimum for a trustworthy claim.
