"""The cluster model and the export loader.

The input is the JSON a cluster can actually give you: `kubectl get ... -o json`
for a single object, `kubectl get ... -o json` piped through a List, a JSON array
of objects you assembled, or JSONL. YAML is deliberately not parsed: a hand-written
YAML parser is a source of silent misreads, and `-o json` is one flag away.
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field

WORKLOAD_KINDS = (
    "Pod",
    "Deployment",
    "DaemonSet",
    "StatefulSet",
    "ReplicaSet",
    "Job",
    "CronJob",
)

RBAC_KINDS = ("Role", "ClusterRole", "RoleBinding", "ClusterRoleBinding")


class LoadError(Exception):
    """The export could not be read as Kubernetes objects."""


@dataclass(frozen=True)
class Subject:
    kind: str
    name: str
    namespace: str | None = None

    @property
    def identity(self) -> str:
        if self.kind == "ServiceAccount":
            return f"system:serviceaccount:{self.namespace or 'default'}:{self.name}"
        if self.kind == "User":
            return f"user:{self.name}"
        return f"group:{self.name}"


@dataclass(frozen=True)
class PolicyRule:
    verbs: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    api_groups: tuple[str, ...] = ()
    resource_names: tuple[str, ...] = ()

    @property
    def unrestricted(self) -> bool:
        """A rule with resourceNames limits itself to those objects."""
        return not self.resource_names


@dataclass(frozen=True)
class Role:
    name: str
    namespace: str | None
    rules: tuple[PolicyRule, ...]
    aggregated: bool = False


@dataclass(frozen=True)
class Binding:
    name: str
    namespace: str | None
    role_kind: str
    role_name: str
    subjects: tuple[Subject, ...]

    @property
    def scope(self) -> str | None:
        """None means cluster-wide; a namespace means the binding is scoped to it."""
        return self.namespace


@dataclass(frozen=True)
class ServiceAccount:
    name: str
    namespace: str

    @property
    def identity(self) -> str:
        return f"system:serviceaccount:{self.namespace}:{self.name}"


@dataclass(frozen=True)
class Workload:
    kind: str
    name: str
    namespace: str
    service_account: str
    pod_spec: dict

    @property
    def label(self) -> str:
        return f"{self.kind} {self.namespace}/{self.name}"

    @property
    def service_account_identity(self) -> str:
        return f"system:serviceaccount:{self.namespace}:{self.service_account}"


@dataclass
class Cluster:
    source: str
    namespaces: tuple[str, ...] = ()
    roles: dict[tuple[str | None, str], Role] = field(default_factory=dict)
    bindings: tuple[Binding, ...] = ()
    service_accounts: tuple[ServiceAccount, ...] = ()
    workloads: tuple[Workload, ...] = ()
    kind_counts: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def namespace_list(self) -> tuple[str, ...]:
        derived = {sa.namespace for sa in self.service_accounts}
        derived |= {w.namespace for w in self.workloads}
        derived |= {b.namespace for b in self.bindings if b.namespace}
        return tuple(sorted(set(self.namespaces) | derived))

    def identity_ids(self) -> tuple[str, ...]:
        ids = {sa.identity for sa in self.service_accounts}
        for binding in self.bindings:
            for subject in binding.subjects:
                if subject.kind in {"User", "Group"}:
                    ids.add(subject.identity)
        return tuple(sorted(ids))

    def workloads_for(self, identity: str) -> tuple[Workload, ...]:
        return tuple(w for w in self.workloads if w.service_account_identity == identity)


def _strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _policy_rules(raw: object) -> tuple[PolicyRule, ...]:
    rules: list[PolicyRule] = []
    if not isinstance(raw, list):
        return ()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        rules.append(
            PolicyRule(
                verbs=_strings(entry.get("verbs")),
                resources=_strings(entry.get("resources")),
                api_groups=_strings(entry.get("apiGroups")),
                resource_names=_strings(entry.get("resourceNames")),
            )
        )
    return tuple(rules)


def _subjects(raw: object) -> tuple[Subject, ...]:
    subjects: list[Subject] = []
    if not isinstance(raw, list):
        return ()
    for entry in raw:
        if not isinstance(entry, dict):
            continue
        kind = entry.get("kind")
        name = entry.get("name")
        if not isinstance(kind, str) or not isinstance(name, str):
            continue
        namespace = entry.get("namespace")
        subjects.append(
            Subject(kind=kind, name=name, namespace=namespace if isinstance(namespace, str) else None)
        )
    return tuple(subjects)


def _pod_spec(kind: str, obj: dict) -> dict | None:
    spec = obj.get("spec")
    if not isinstance(spec, dict):
        return None
    if kind == "Pod":
        return spec
    if kind == "CronJob":
        job = spec.get("jobTemplate")
        template = job.get("spec", {}).get("template") if isinstance(job, dict) else None
    else:
        template = spec.get("template")
    if not isinstance(template, dict):
        return None
    pod = template.get("spec")
    return pod if isinstance(pod, dict) else None


def _objects(payload: object) -> list[dict]:
    if isinstance(payload, dict):
        if payload.get("kind") == "List" and isinstance(payload.get("items"), list):
            return [item for item in payload["items"] if isinstance(item, dict)]
        return [payload]
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    return []


def _parse_text(text: str, source: str) -> list[dict]:
    try:
        return _objects(json.loads(text))
    except json.JSONDecodeError:
        pass
    objects: list[dict] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            decoded = json.loads(line)
        except json.JSONDecodeError:
            raise LoadError(
                f"{source}: not valid JSON, and the line-oriented fallback found a "
                "line that is not a JSON object either"
            ) from None
        objects.extend(_objects(decoded))
    if not objects:
        raise LoadError(f"{source}: no JSON objects found")
    return objects


def load_export(path: str) -> Cluster:
    try:
        with open(path, encoding="utf-8-sig") as handle:
            text = handle.read()
    except OSError as exc:
        raise LoadError(f"{path}: cannot be read ({exc})") from exc

    objects = _parse_text(text, path)
    counts: Counter[str] = Counter()
    namespaces: set[str] = set()
    roles: dict[tuple[str | None, str], Role] = {}
    bindings: list[Binding] = []
    service_accounts: list[ServiceAccount] = []
    workloads: list[Workload] = []
    warnings: list[str] = []

    for obj in objects:
        kind = obj.get("kind")
        metadata = obj.get("metadata")
        if not isinstance(kind, str) or not isinstance(metadata, dict):
            warnings.append("skipped an object without a kind or metadata block")
            continue
        name = metadata.get("name")
        if not isinstance(name, str) or not name:
            warnings.append(f"skipped a {kind} without metadata.name")
            continue
        raw_namespace = metadata.get("namespace")
        namespace = raw_namespace if isinstance(raw_namespace, str) and raw_namespace else "default"
        counts[kind] += 1

        if kind == "Namespace":
            namespaces.add(name)
        elif kind == "ServiceAccount":
            service_accounts.append(ServiceAccount(name=name, namespace=namespace))
        elif kind in {"Role", "ClusterRole"}:
            scope = None if kind == "ClusterRole" else namespace
            role = Role(
                name=name,
                namespace=scope,
                rules=_policy_rules(obj.get("rules")),
                aggregated=bool(obj.get("aggregationRule")),
            )
            roles[(scope, name)] = role
            if role.aggregated:
                warnings.append(
                    f"{kind} {name} uses aggregationRule; the aggregated rules must be "
                    "present in the export or its grants are understated"
                )
        elif kind in {"RoleBinding", "ClusterRoleBinding"}:
            role_ref = obj.get("roleRef")
            if not isinstance(role_ref, dict):
                warnings.append(f"{kind} {namespace}/{name} has no roleRef, skipped")
                continue
            ref_kind = role_ref.get("kind")
            ref_name = role_ref.get("name")
            if not isinstance(ref_kind, str) or not isinstance(ref_name, str):
                warnings.append(f"{kind} {namespace}/{name} has an incomplete roleRef, skipped")
                continue
            bindings.append(
                Binding(
                    name=name,
                    namespace=None if kind == "ClusterRoleBinding" else namespace,
                    role_kind=ref_kind,
                    role_name=ref_name,
                    subjects=_subjects(obj.get("subjects")),
                )
            )
        elif kind in WORKLOAD_KINDS:
            pod_spec = _pod_spec(kind, obj)
            if pod_spec is None:
                warnings.append(f"{kind} {namespace}/{name} has no pod template, skipped")
                continue
            service_account = pod_spec.get("serviceAccountName") or pod_spec.get("serviceAccount")
            workloads.append(
                Workload(
                    kind=kind,
                    name=name,
                    namespace=namespace,
                    service_account=service_account if isinstance(service_account, str) else "default",
                    pod_spec=pod_spec,
                )
            )
        else:
            counts.pop(kind, None)

    if not counts:
        raise LoadError(
            f"{path}: no Kubernetes objects recognised; expected Role, ClusterRole, "
            "RoleBinding, ClusterRoleBinding, ServiceAccount or workload objects"
        )

    cluster = Cluster(
        source=path,
        namespaces=tuple(sorted(namespaces)),
        roles=roles,
        bindings=tuple(bindings),
        service_accounts=tuple(service_accounts),
        workloads=tuple(workloads),
        kind_counts=dict(sorted(counts.items())),
        warnings=warnings,
    )
    missing = sorted(
        name for name in {b.role_name for b in cluster.bindings if b.role_kind == "ClusterRole"}
        if (None, name) not in cluster.roles
    )
    for name in missing:
        cluster.warnings.append(
            f"ClusterRole {name} is referenced by a binding but absent from the export; "
            "identities bound to it are understated"
        )
    return cluster
