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

| Benchmark                           | Path exercised                                                                         | What it isolates                                |
| ----------------------------------- | -------------------------------------------------------------------------------------- | ----------------------------------------------- |
| `BenchmarkDirect_SmallGET`          | client → target with no proxy: the floor                                               | pure HTTP baseline                              |
| `BenchmarkProxied_SmallGET`         | client → gateway → SOCKS5 → target, small GET                                          | setup latency + relay for one full request      |
| `BenchmarkProxied_SmallGETParallel` | same, fresh tunnel per request, `GOMAXPROCS` workers                                   | per-request setup under concurrency             |
| `BenchmarkProxied_TunnelSetup`      | inbound SOCKS5 greet/CONNECT → route pick → outbound SOCKS5 setup, then close; no HTTP | setup-latency floor: the double handshake alone |
| `BenchmarkProxied_BulkGET_1MiB`     | one tunnel reused, 1MiB HTTP response relayed per iteration (`SetBytes` reports MB/s)  | relay throughput, setup excluded                |

The gap between `Direct` and `Proxied` small GET is the full per-request cost
of one gateway hop plus one SOCKS5 hop: the per-tunnel inbound and outbound
handshakes plus the relay of the small HTTP exchange through them.

`Proxied_TunnelSetup` and `Proxied_SmallGET` split the setup-latency side of
that gap into its parts: the former measures the double handshake with no HTTP
on top, so its value subtracted from the small GET is roughly the cost of
speaking HTTP through an established tunnel. `Proxied_BulkGET_1MiB` measures
the other axis — steady-state relay throughput — with setup removed from the
timed loop entirely (the tunnel is established once, before `ResetTimer`).

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
  included in ns/op.
- The echo/bulk body target (a prebuilt `[]byte` written per request) and the
  in-process SOCKS sim contribute their own allocations to proxied benchmarks;
  same-target before/after comparisons cancel them out, absolute values do not.
- Bench configs use `log-level: error` so logging stays out of the
  measurement; benchmarks skip under `-test.short` like the rest of the
  package.
- Use the same `-benchtime` and `-count` for before/after; `-count≥5` plus
  benchstat is the minimum for a trustworthy claim.
