# Changelog

## [1.0.0] - 2026-11-03

### Added

- `rbacpath` CLI with `audit`, `paths` and `caps`, reading a single object, a `List`,
  a JSON array or JSONL, and reporting text, JSON or Markdown.
- 12 capabilities (`CAP001`–`CAP012`) covering cluster-admin shape, cluster-wide and
  namespaced secret reads, pod and controller creation, RoleBinding and
  ClusterRoleBinding creation, `bind`/`escalate`, impersonation, token minting,
  `nodes/proxy` and `pods/exec`.
- 5 composed escalation paths (`PATH001`–`PATH005`) evaluated over confirmed
  capabilities only.
- 8 workload rules (`W001`–`W008`) for explicit security-context and image decisions.
- RBAC resolution that honours namespaced ClusterRole bindings, `pods/<subresource>`
  as a distinct resource, `resourceNames` narrowing, and group membership including
  `system:serviceaccounts:<ns>`.
- Exit codes: `0` clean, `2` threshold breached, `3` export unreadable.
- Two synthetic fixtures with verdicts pinned in the test suite (98 tests).
- GitHub Actions CI on Python 3.11 and 3.12, gating on the fixtures' exit codes and
  on the test suite.
