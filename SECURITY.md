# Security Policy

## Reporting a vulnerability

**Do not open a public issue.** A public report of a credential leak is
itself a disclosure of the credential.

- Preferred: [a private security advisory](https://github.com/ecoma-io/rotation-proxy-gateway/security/advisories/new)
  (the repository's _Security_ tab → _Report a vulnerability_).
- Or email **john.itvn@gmail.com** with: a description of the issue, a
  reproduction or proof of concept, and your assessment of the impact.

Please never paste real credentials, `config.yaml` contents, or route URLs
into any report — a PoC that needs them should hold placeholders.

## What counts as a vulnerability here

rotation-proxy-gateway is credential-carrying network infrastructure: its
runtime config holds SOCKS5 route credentials and rotation-provider
credentials in plaintext, and its whole job is to move other people's
traffic through those credentials. Two defect classes therefore count as
security vulnerabilities even when the underlying mechanism is an ordinary
bug:

- **A credential, URL userinfo, rotate-API header/body, or route identity
  reaching logs, `/status`, error text, or a proxied response.** The
  documented contract forbids each of these (see
  [docs/failure-and-health.md](docs/failure-and-health.md) and
  [docs/observability.md](docs/observability.md)); a redaction that
  misses a format fails in the quiet direction — the report is a leak, not
  a typo.
- **A path that lets a proxy client reach what the network policy did not
  intend to expose** — the admin listener's endpoints, the rotation
  provider API, or a route pool the caller did not configure for that
  listener.

Supply-chain defects in the CI itself (an unpinned action, an unpinned
container image, a workflow interpolating attacker-reachable input into a
shell command) are also in scope; `.github/semgrep/` pins the classes this
repository treats as vulnerabilities in its own automation.

Everything else — a miscounted metric, a wrong status code, a cooldown
that expires a second early — is an ordinary bug, and the
[public tracker](https://github.com/ecoma-io/rotation-proxy-gateway/issues)
is the right place for it.

## Supported versions

This project is pre-1.0. Security fixes are applied to the `main` branch
and released in the next version; there is no long-term support branch and
no backport policy for older tags.

## Service levels

Stated honestly for a single-maintainer project:

- **Acknowledgement** within 48 hours of a report.
- **Fix published** within 14 days of a confirmed report — "published"
  meaning a tagged release, not an unmerged commit.
- The **disclosure date** is agreed with the reporter; credit in the
  release notes unless anonymity is preferred.
