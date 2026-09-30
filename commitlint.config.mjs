// Conventional Commits, enforced twice: the commit-msg hook, and the
// pull-request title in CI — merges are squash merges, so the title becomes
// the commit subject and must pass the same gate. `header-max-length` 100
// comes from the conventional default and is what the PR-title check leans
// on; body line length is unlimited.
// `deps` and `ci` exist so dependency-automation pull requests (Renovate's
// semanticCommitScope settings in .github/renovate.json5) pass the same gate
// as human ones; `release` belongs to release-please's release PR.
export default {
  extends: ["@commitlint/config-conventional"],
  rules: {
    "scope-enum": [
      2,
      "always",
      [
        "pool",
        "routing",
        "rotation",
        "proxyserver",
        "socksdial",
        "warmpool",
        "config",
        "cmd",
        "e2e",
        "docs",
        "deps",
        "ci",
        "workspace",
        "release",
        // Added by the HTTP-forward-proxy migration (#92). `inbound` is the
        // ingress protocol layer, which the SOCKS era expressed inside
        // proxyserver and which the HTTP era gives its own seam: request
        // parsing, `Proxy-Authorization`, and the x-ecoma-* control headers are
        // ingress concerns, while proxyserver keeps the route-selection and
        // relay engine they feed. The migration phases that follow add
        // `store` (durable configuration and analytics), `coord` (Redis lease,
        // fencing, and the distributed rotation epoch), and `api` (the admin
        // resource endpoints); they are added when those packages land, so a
        // scope never names a package that does not exist.
        "inbound",
        // Added with internal/coord, the Redis coordination authority: the
        // lease, its fencing tokens, and the cluster rotation epoch.
        "coord",
      ],
    ],
    "body-max-line-length": [0],
  },
};
