# Contributing to rotation-proxy-gateway

Thank you for wanting to contribute. This is a single-maintainer project:
issues and pull requests are both welcome, and both go through the same
gates.

By contributing you agree that your work is licensed under the Apache
License 2.0, and that you have the right to grant that license.

## The behavior contract

The [`docs/`](docs/) pages are the authoritative behavior contract: failure
classification, reload semantics, shutdown ordering, rotation states, and
what may never reach a log line or `/status`. [`README.md`](README.md) is the
entry point, and [`AGENTS.md`](AGENTS.md) carries the working guidance built
on top of the contract.

A change that moves documented behavior updates the affected docs page and
AGENTS in the same pull request. A document that lags the code is a defect,
not a follow-up.

## Setting up

- **Go ≥ 1.25** — `go.mod` declares the floor, and CI installs with
  `go-version-file: go.mod`, so the module owns its toolchain version.
- **Node ≥ 24 and pnpm ≥ 11** — only for the repository hooks and formatting
  (nothing here ships to npm). `pnpm install` runs `lefthook install`; if a
  repository's hooks did not run for you, it is because that step was
  skipped. Do not skip it.
- `golangci-lint` is optional locally — CI downloads and checksum-pins its
  own copy, so a local copy at any recent v2 works.

## The commands

| Command                                                                                  | What it does                                                                                                                      |
| ---------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `gofmt -w .`                                                                             | Format; the first half of every change                                                                                            |
| `go vet ./...`                                                                           | Vet; CI runs golangci-lint's default roster, whose superset includes it                                                           |
| `go test -race ./...`                                                                    | The full suite, including the black-box E2E tests                                                                                 |
| `go test -short -race ./...`                                                             | Unit only — the E2E suite skips itself under `-short`                                                                             |
| `go test ./e2e/`                                                                         | Just the black-box suite: the real binary as a subprocess against in-process SOCKS5/HTTP/rotate-API simulators (no Docker needed) |
| `go build -ldflags "-X main.version=0.1.0-dev" -o bin/rpgw ./cmd/rotation-proxy-gateway` | Build the binary                                                                                                                  |
| `pnpm format` / `pnpm format:check`                                                      | Prettier over the docs, workflows, and config files                                                                               |

## What the hooks do

| Hook         | Commands                                                                   |
| ------------ | -------------------------------------------------------------------------- |
| `pre-commit` | `gofmt -w` over staged `*.go` · prettier over staged docs/workflows/config |
| `commit-msg` | commitlint over the message                                                |
| `pre-push`   | `go test ./...`                                                            |

Bypassing a hook with `--no-verify` is occasionally the right call during a
rebase. It is never the right way to land a change.

## Commit messages

Conventional Commits, enforced by commitlint both on the hook and on the
pull-request title in CI:

```
<type>(<scope>): <subject>
```

- Types: `feat`, `fix`, `docs`, `style`, `refactor`, `perf`, `test`,
  `build`, `ci`, `chore`, `revert`.
- Scopes name the area: `pool`, `rotation`, `proxyserver`, `socksdial`,
  `config`, `cmd`, `e2e`, `docs`, `deps`, `ci`, `workspace`, `release`.
  The scope is optional; `deps` and `ci` exist so that dependency-automation
  pull requests pass the same gate as human ones.
- Breaking changes add `!` before the colon and a `BREAKING CHANGE:` footer.
- Subject at most 100 characters; body line length unlimited.

**AI-assisted disclosure.** If a commit was AI-assisted, it carries a
trailer: `Assisted-by: <tool>` or `Generated-by: <tool>`. One trailer per
pull request, on the last commit — merges are squash merges, and the
squashed commit concatenates trailers, so per-commit trailers would
duplicate.

## Tests

- Unit tests live beside the code under `internal/`. E2E tests live under
  `e2e/` and drive the real binary as a subprocess, with in-process
  simulators for SOCKS5 upstreams, HTTP targets, and the rotate API. They
  need nothing but Go; skip them with `-short` when iterating.
- A test that only pins the loud direction is not a test. This is
  credential-carrying network infrastructure: prefer the case where a change
  fails _quietly_ — a credential that reaches a log line, a route that
  cools down when it must not, auth state that survives a reload it should
  not survive.
- E2E benchmark baselines and their caveats live in [`e2e/BENCH.md`](e2e/BENCH.md).

## Opening a pull request

1. Branch from `main`.
2. Make the change, add the tests, run the commands.
3. Fill the pull-request template honestly — especially "Could this fail
   silently?" Writing "no" is fine when it is true; leaving it blank is not.
4. Keep it focused: one behavior per pull request, docs in the same pass.

**Squash, always.** The pull-request title becomes the squash commit's
subject, so the title itself must be a valid Conventional Commit — CI runs
commitlint on it before anything else matters.

## How a release happens

[release-please](https://github.com/googleapis/release-please) owns
`CHANGELOG.md` and the version tag; do not hand-edit either. Every merged
`feat`/`fix` commit updates an open release pull request; merging that pull
request tags `v<version>` and publishes the Docker image to
`ghcr.io/ecoma-io/rotation-proxy-gateway` — both the version tag and
`latest`, except that a prerelease never moves `latest`. A
`Release-As: <version>` footer on a commit forces a version once.

## Reporting problems

- Bugs: [the bug report form](.github/ISSUE_TEMPLATE/bug_report.yml).
- Anything security-shaped — a credential reaching a log line, a redaction
  that missed a format, listener exposure: [SECURITY.md](SECURITY.md),
  never a public issue.

## Ownership of what you contribute

You keep the copyright. What you grant is the Apache License 2.0 right to
use and redistribute the work as part of this project — and, per the
section above, a clear statement of which parts a machine helped write.
