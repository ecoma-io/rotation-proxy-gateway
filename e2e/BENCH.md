# e2e benchmarks

These benchmarks measure the gateway's end-to-end overhead with the real
binary, a real SOCKS5 hop (`SocksSim`), and a real HTTP target. They exist so
optimization work is grounded in measured deltas on the machine that matters.

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

| Benchmark | Path exercised |
|---|---|
| `BenchmarkDirect_SmallGET` | client → target with no proxy: the floor |
| `BenchmarkProxied_SmallGET` | client → gateway → SOCKS5 → target, small GET |
| `BenchmarkProxied_SmallGETParallel` | same, shared client across `GOMAXPROCS` workers |
| `BenchmarkProxied_ReplayablePOST_64KiB` | body at/under `max-body-buffer`: buffered replay path |
| `BenchmarkProxied_StreamingPOST_2MiB` | body far above a 64KiB cap: streaming path |
| `BenchmarkProxied_BulkGET_1MiB` | download throughput (`SetBytes` reports MB/s) |

The gap between `Direct` and `Proxied` small GET is the full per-request cost
of one gateway hop plus one SOCKS5 hop.

## Interpretation caveats — read before drawing conclusions

- The small-GET gap is dominated by **connection setup, not copying**: the
  gateway opens a fresh SOCKS5 tunnel for every request *by design* (client
  TCP → gateway, gateway TCP → SOCKS endpoint, SOCKS CONNECT handshake), and
  each test request closes its connection. Copy-path optimizations cannot move
  this number; connection reuse would be a behavior change, not a tuning knob.
- `B/op` and `allocs/op` cover **the test process only** (client + HTTP target
  server, which are in-process). The gateway is a separate OS process; its
  memory is invisible to these counters, though its cost is included in ns/op.
- The echo body target (`io.ReadAll` + write) contributes its own allocations
  to POST benchmarks; same-target before/after comparisons cancel it out,
  absolute values do not.
- Bench configs use `log-level: error` so logging stays out of the
  measurement; benchmarks skip under `-test.short` like the rest of the
  package.
- Use the same `-benchtime` and `-count` for before/after; `-count≥5` plus
  benchstat is the minimum for a trustworthy claim.
