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
      ],
    ],
    "body-max-line-length": [0],
  },
};
