## Description

Closes #

## Type of change

- [ ] Bug fix — behavior disagrees with the documented contract
- [ ] Contract change — documented behavior moves; README/AGENTS updated in this PR
- [ ] New feature
- [ ] Refactor — no behavior change
- [ ] Documentation only
- [ ] Build / CI / tooling

## Contract impact

- [ ] Trivial — moves no documented behavior (failure classification, reload, shutdown, rotation states, the logging/`/status` contract)
- [ ] Contract-bearing — the affected README/AGENTS sections are updated in this same PR

## Could this fail silently?

<!-- The dangerous direction in this repository is the quiet one: a credential
     that reaches a log line, a route that cools down when it must not, a
     state that survives a reload it should not survive. Writing "no" is fine
     when it is true; leaving this blank is not. -->

- [ ] It cannot, and I considered the quiet direction
- [ ] It could, and a test pins the case where it would — test name:

## How this was verified

1.

- [ ] `gofmt -w .` — clean
- [ ] `go vet ./...` — clean
- [ ] `go test -race ./...` — green
- [ ] `go test ./e2e/` — green (or a `-short` run plus one line on why E2E is unaffected)

## Checklist

- [ ] Self-reviewed the diff
- [ ] Docs updated in the same pass (README/AGENTS when behavior moves)
- [ ] No `config.yaml`, credentials, or route URLs anywhere in the diff
- [ ] I have the right to contribute this work under the Apache License 2.0

## AI-assisted development

If any commit in this pull request was AI-assisted, the pull request's last
commit carries its disclosure trailer — `Assisted-by: <tool>` or
`Generated-by: <tool>` — one trailer per pull request, not one per commit.

- [ ] No AI-assisted commits in this PR
- [ ] AI-assisted — the disclosure trailer is on the last commit
