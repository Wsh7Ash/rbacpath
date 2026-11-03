# rbacpath

Read a Kubernetes export and answer what its RBAC **actually** grants, including the
escalation paths that only appear when two grants are composed.

`rbacpath` is offline: it reads JSON you already exported, talks to no cluster, and
needs no credentials. The question it answers is not "which rules exist" — that is a
`kubectl get` away — but "which identity can reach what", which is a different thing
and the one that decides severity.

```
$ rbacpath audit cluster.json
rbacpath 1.0.0  cluster.json
export    ClusterRole 4, ClusterRoleBinding 2, DaemonSet 1, Deployment 1,
          Namespace 3, RoleBinding 2, ServiceAccount 4
namespaces ci, default, prod

summary   6 error  6 warn  4 info   3 path(s)   band high-risk (score 82)

paths
  PATH001  system:serviceaccount:default:default reaches any role it can bind,
           including cluster-admin
        via CAP006 -> ... can take full control of the namespace by binding
            cluster-admin to itself in default (default-edits-rbac (RoleBinding);
            ClusterRole rbac-editor; scope default; verbs create; resources
            rolebindings; apiGroups rbac.authorization.k8s.io)
  PATH003  system:serviceaccount:ci:deployer reaches every ServiceAccount token,
           including cluster-admin
  PATH004  system:serviceaccount:prod:app reaches every secret in the affected
           namespaces
```

## Install

```bash
pip install -e ".[dev]"
rbacpath --version
```

Python 3.10+. No runtime dependencies outside the standard library.

## Usage

```bash
# a cluster export, one file
kubectl get clusterroles,clusterrolebindings,roles,rolebindings,serviceaccounts,namespaces \
  -A -o json > cluster.json
rbacpath audit cluster.json

# workload-level settings live on the workloads
kubectl get pods,deployments,daemonsets,statefulsets,jobs,cronjobs -A -o json > workloads.json
rbacpath audit workloads.json
```

Input forms accepted: a single object, a `List`, a JSON array of objects, or JSONL
(one object per line). YAML is not parsed — a hand-written YAML parser is a source of
silent misreads, and `-o json` is one flag away.

```bash
rbacpath audit export.json                     # text report
rbacpath audit export.json --format json       # machine-readable
rbacpath audit export.json --format markdown   # for a ticket or a PR comment
rbacpath audit export.json --out report.md --format markdown
rbacpath audit export.json --fail-on warn      # pipeline gate
rbacpath paths export.json --from system:serviceaccount:ci:deployer
rbacpath caps                                  # the capability catalogue
```

Exit codes:

| code | meaning |
|---|---|
| `0` | nothing at or above the `--fail-on` threshold (default `error`) |
| `2` | threshold breached |
| `3` | the export could not be read |

A failing gate and a broken tool never look alike, which matters when the gate is
wired into CI.

## What it reports

### 12 capabilities (`CAP001`–`CAP012`)

What an identity can *do*, not which verbs it holds. Each names the scope where it
was found and the binding and role that grant it:

| id | capability | scope | severity |
|---|---|---|---|
| `CAP001` | wildcard rules (cluster-admin shape) | cluster | info |
| `CAP002` | reads secrets cluster-wide | cluster | error |
| `CAP003` | reads secrets in a namespace | namespace | warn |
| `CAP004` | creates pods | namespace | warn |
| `CAP005` | creates workload controllers | namespace | warn |
| `CAP006` | creates RoleBindings | namespace | error |
| `CAP007` | creates ClusterRoleBindings | cluster | error |
| `CAP008` | holds `bind`/`escalate` on roles | cluster | error |
| `CAP009` | impersonates users, groups, ServiceAccounts | cluster | error |
| `CAP010` | mints ServiceAccount tokens | namespace | warn |
| `CAP011` | reaches the kubelet through `nodes/proxy` | cluster | error |
| `CAP012` | execs into pods | namespace | warn |

`CAP001` is `info` on purpose. Platform ServiceAccounts are often legitimately
cluster-admin, and a rule that shouts about them teaches readers to ignore the output.
What matters is who can *reach* that identity, which is what the paths section is for.

### 5 composed paths (`PATH001`–`PATH005`)

A path fires only when every capability it needs was already confirmed, and its
evidence is the same binding text, so a path cannot claim more than the capability
pass found. The compositions that matter:

- `PATH001` — create bindings, or hold `bind`/`escalate` → **any role, including
  cluster-admin**. One object, no exploit.
- `PATH002` — impersonate → **cluster-admin**, if a cluster-admin subject exists to
  impersonate.
- `PATH003` — read secrets cluster-wide → **every ServiceAccount token**, including
  any bound to cluster-admin.
- `PATH004` — create pods → **every secret in the namespace**, because a created pod
  can mount them. Pod-create is secret-read even without a `get` on secrets.
- `PATH005` — `nodes/proxy` → **command execution on every node**.

### 8 workload rules (`W001`–`W008`)

`privileged`, `hostPath`, host namespaces, running as root, permitted privilege
escalation, added capabilities, automounted tokens, mutable image references.

Only **explicit** settings are reported. An absent `securityContext` is not flagged:
almost every manifest omits something, and a rule that fires on absence is noise. The
settings someone wrote down — `privileged: true`, `hostPath: /`, `runAsUser: 0` — are
the decisions worth arguing about.

## The four RBAC details that decide a verdict

These are where reviews of this domain usually go wrong, so each has a test:

1. **A ClusterRole bound by a RoleBinding is namespaced.** The rules apply, but only
   inside the binding's namespace. Treating that as cluster-wide is the most common
   false positive.
2. **A rule on `pods` does not grant `pods/exec`.** The subresource is a distinct
   resource in RBAC, and only the `pods/exec` form or a wildcard matches it.
3. **`resourceNames` narrows a rule.** `get secrets` with
   `resourceNames: [db-password]` is not "reads all secrets", so it is not counted as
   a capability at all. Reporting it would overstate the finding.
4. **Group membership is real.** `system:serviceaccounts:<ns>` and
   `system:authenticated` are subjects; a ServiceAccount belongs to both.

`system:masters` is honoured when the group is evaluated as an identity. Which users
are in it is decided by the authenticator and is **not** in the export, so it is never
assumed for a user or ServiceAccount — guessing would invent a critical finding.

## Limits

Stated because a report that hides them is worse than no report:

- **Declared state only.** The export is a snapshot of objects. Admission controllers,
  policy engines (Kyverno, Gatekeeper, Pod Security Admission), audit logs and
  runtime behaviour are not in it. A `create pods` grant may be blocked in practice by
  a policy this tool cannot see — the grant is still the thing to fix.
- **Aggregated ClusterRoles are not resolved.** If a ClusterRole uses
  `aggregationRule`, its rules come from other ClusterRoles matched by label; the
  export must contain them or the grants are understated, and the tool says so in
  `export warnings`.
- **ClusterRole contents must be present.** A binding to a ClusterRole that is absent
  from the export grants nothing here; this is warned about rather than guessed.
- **No YAML.** Convert with `-o json`.
- **No API discovery.** A wildcard resource match is reported as a wildcard, not
  expanded against the live API's resource list.
- **Fixtures are synthetic.** Both examples were written by hand. No production
  cluster was audited while building this, so real-world false-positive rates are
  unknown; the example verdicts are pinned by tests so any change is visible.
- **`resourceNames` grants are invisible.** By design (see above), a narrow grant
  produces no finding — the tool reports reach, not inventory.

## Scoring

`score = 10·errors + 3·warnings + 1·info`. Band: `high-risk` with any error,
`review` with any warning, otherwise `clean`. The score is for ranking two exports
against each other; it is not a compliance statement.

## Development

```bash
python -m pytest -q          # 98 tests
```

Tests are grouped by the contract they defend: `test_model.py` (loading), `test_rbac.py`
(resolution semantics), `test_capabilities.py`, `test_paths_workloads.py`,
`test_cli.py` (exit codes and output shape), `test_examples.py` (pinned verdicts).

## License

MIT.
