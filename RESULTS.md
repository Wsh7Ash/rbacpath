# Results

What was built, what was measured, and what the measurements showed.

## Verdict on the shipped examples

`examples/export-risky.json` — 16 objects, 3 namespaces:

```
summary   6 error  6 warn  4 info   3 path(s)   band high-risk (score 82)
```

| id | finding | severity |
|---|---|---|
| `PATH001` | `default/default` reaches any role it can bind, including cluster-admin | error |
| `PATH003` | `ci/deployer` reaches every ServiceAccount token in the cluster | error |
| `PATH004` | `prod/app` reaches every secret in `prod` | warn |
| `CAP002` | `ci/deployer` reads secrets cluster-wide (ClusterRoleBinding) | error |
| `CAP006` | `default/default` creates RoleBindings in `default` | error |
| `CAP004` | `prod/app` creates pods in `prod` | warn |
| `W001` | `DaemonSet prod/agent` privileged | error |
| `W002` | `DaemonSet prod/agent` mounts hostPath `/` | error |
| `W003`–`W006` | host namespace, root user, privilege escalation, SYS_ADMIN | warn |
| `W007` | two workloads automount the `app` token | info |
| `W008` | `prod/api` uses `:latest` | info |
| `CAP001` | `prod/admin` holds wildcard rules | info |

`examples/export-clean.json` — least-privilege Role, `resourceNames`-scoped configmap
read, non-root container with a dropped capability set and `automountServiceAccountToken: false`:

```
summary   0 error  0 warn  0 info   0 path(s)   band clean (score 0)
```

## Verification actually run

Everything below was executed; nothing is inferred from reading the code.

- `python -m pytest -q` from the source tree: **98 passed**.
- Fresh venv, `pip install -e ".[dev]"`, `pytest -q`: **98 passed**; `rbacpath --version`
  → `rbacpath 1.0.0`.
- Risky export text report: `6 error 6 warn 4 info 3 path(s) band high-risk (score 82)`,
  exit `2`.
- Clean export: `0 error 0 warn 0 info band clean (score 0)`, exit `0`.
- `--fail-on warn` on the risky export → `2`; `--fail-on none` → `0`;
  `--fail-on info` on the clean export → `0`.
- `--format json` parses, has `tool`/`version`/`target`/`export`/`summary`/`identities`/
  `findings`, 16 findings of which 3 are paths, and findings arrive severity-ordered.
- `--format markdown` starts `# rbacpath report:` and emits an `## Escalation paths`
  section; `--out` writes the same bytes to a file.
- `paths --from system:serviceaccount:ci:deployer` returns only `PATH003`;
  `paths` on the clean export prints `no escalation path found in this export`.
- `caps` lists all 12; `caps --format json` returns 12 rows with
  `id`/`scope`/`severity`/`leads_to`.
- Unreadable path and a JSON file with no Kubernetes kinds → exit `3` with a message on
  stderr, distinguishable from the gate's `2`.
- Secret scan over the tree: no credentials, no tokens, no private keys.

## Defects found by testing, and fixed

Recorded because each one would have produced a wrong verdict.

1. **`pods` was treated as granting `pods/exec`.** The subresource check built
   `{resource, resource/subresource}` as candidates, so a rule listing `pods` matched
   an `exec` request. The risky fixture exposed it: `prod/app` (create pods) was
   reported with `CAP012` (exec) as well as `CAP004`. RBAC treats the subresource as a
   distinct resource, so the candidate set for a subresource request is now
   `{resource/subresource}` — exact, or a wildcard. Regression test added
   (`test_a_rule_on_pods_does_not_grant_pods_exec`).
2. **Capabilities with more than one API surface were unreachable.** `CAP005`
   (workload controllers) required *creating a Deployment and creating a Job*, and
   `CAP008` required *bind on ClusterRoles and bind on Roles*, because requirements
   were evaluated as a conjunction. Both were false negatives on realistic roles.
   Capabilities now declare `any_of=True` where alternatives are genuinely
   alternatives, and `_satisfies` honours it in both cluster and namespace scope.
3. **`resourceNames`-scoped grants were counted as full reach.** A `get secrets` rule
   limited to one secret satisfied "reads all secrets". Capability matching now rejects
   a match whose rule carries `resourceNames`; the assertion that the clean fixture
   produces zero capabilities is what pins it.
4. **`system:masters` was assumed for any user bound to the group.** The first
   implementation gave `user:root` full cluster authority whenever *some* binding named
   the group — inventing a critical finding from a name. Membership is decided by the
   authenticator and is not in the export, so the bypass now applies only when the
   group itself is the identity, and the limitation is documented.
5. **The example paths were wrong for the tests themselves.** `conftest.py` resolved
   `ROOT` as the parent of the project directory, so every CLI test read
   `projects/2026-11-03/examples/...` and got exit `3`. Sixteen tests failing at once is
   what made the one-line error obvious.
6. **Ranking contradicted the report.** Identities were ranked by finding severity, so
   a namespace pod-creator ranked above an identity holding cluster-admin (`CAP001` is
   `info` by design). Ranking is now by *reach* (`CAP001` = 4, cluster escalation = 3,
   namespace = 2) while severity stays as reported — the two questions are different
   and the output said the wrong one.
7. **Human-facing output was not ASCII.** Em dashes and middle dots reached a
   `cp1252` console as `�`. Text and Markdown output is now ASCII, which also keeps
   piped logs diffable.

## What is not verified

- No production cluster was audited; both fixtures are synthetic. False-positive rates
  outside the fixtures are unknown.
- Admission control is invisible to the tool. A grant that a policy engine blocks is
  still reported, because the grant is what needs fixing.
- Aggregated ClusterRoles, if their rules are absent from the export, understate
  grants; this is warned about, not resolved.
- The `system:masters` case is modelled conservatively and can understate: a real user
  in that group is not identified by name from the export.
