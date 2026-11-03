"""What an identity can do, in terms of escalation rather than verbs.

Each capability names the verbs, resources and API group that grant it, and a
scope. Cluster-scoped capabilities need a binding that is effective cluster-wide;
namespace-scoped ones are evaluated per namespace and reported once with the
namespaces listed, so one over-broad binding does not produce forty findings.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import rbac
from .catalog import Finding
from .model import Cluster


@dataclass(frozen=True)
class Requirement:
    verbs: tuple[str, ...]
    resources: tuple[str, ...]
    group: str = ""
    subresource: str | None = None


@dataclass(frozen=True)
class Capability:
    id: str
    scope: str  # "cluster" | "namespace"
    requirements: tuple[Requirement, ...]
    leads_to: str
    # Several capabilities are reachable through more than one API surface —
    # deleting a Deployment is as good as creating a Pod — so their requirements
    # are alternatives rather than a conjunction.
    any_of: bool = False


CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        "CAP001",
        "cluster",
        (Requirement(("*",), ("*",), "*"),),
        "reach every object in the cluster",
    ),
    Capability(
        "CAP002",
        "cluster",
        (Requirement(("get",), ("secrets",)), Requirement(("list",), ("secrets",))),
        "read every ServiceAccount token in the cluster",
    ),
    Capability(
        "CAP003",
        "namespace",
        (Requirement(("get",), ("secrets",)), Requirement(("list",), ("secrets",))),
        "read every secret in the namespace",
    ),
    Capability(
        "CAP004",
        "namespace",
        (Requirement(("create",), ("pods",)),),
        "read every secret in the namespace by mounting a pod",
    ),
    Capability(
        "CAP005",
        "namespace",
        (
            Requirement(
                ("create",),
                ("deployments", "daemonsets", "statefulsets", "replicasets"),
                "apps",
            ),
            Requirement(("create",), ("jobs", "cronjobs"), "batch"),
        ),
        "create pods with a template it controls",
        any_of=True,
    ),
    Capability(
        "CAP006",
        "namespace",
        (Requirement(("create",), ("rolebindings",), "rbac.authorization.k8s.io"),),
        "take full control of the namespace by binding cluster-admin to itself",
    ),
    Capability(
        "CAP007",
        "cluster",
        (Requirement(("create",), ("clusterrolebindings",), "rbac.authorization.k8s.io"),),
        "grant itself cluster-admin",
    ),
    Capability(
        "CAP008",
        "cluster",
        (
            Requirement(("bind", "escalate"), ("clusterroles",), "rbac.authorization.k8s.io"),
            Requirement(("bind", "escalate"), ("roles",), "rbac.authorization.k8s.io"),
        ),
        "bind any role in reach, including cluster-admin",
        any_of=True,
    ),
    Capability(
        "CAP009",
        "cluster",
        (
            Requirement(("impersonate",), ("users", "groups", "serviceaccounts")),
        ),
        "act as any identity it impersonates",
    ),
    Capability(
        "CAP010",
        "namespace",
        (Requirement(("create",), ("serviceaccounts",), "", "token"),),
        "mint a token for any ServiceAccount in the namespace",
    ),
    Capability(
        "CAP011",
        "cluster",
        (Requirement(("get",), ("nodes",), "", "proxy"),),
        "reach the kubelet API on every node",
    ),
    Capability(
        "CAP012",
        "namespace",
        (Requirement(("create",), ("pods",), "", "exec"),),
        "exec into any pod in the namespace",
    ),
)

BY_ID: dict[str, Capability] = {cap.id: cap for cap in CAPABILITIES}

# Cluster-admin already implies everything else, and a cluster-wide secret read
# already implies the same read in each namespace. Reporting both would pad the
# report with consequences of a finding the reader has already seen.
CAP001_SUBSUMES_ALL = "CAP001"
SUBSUMED: dict[str, frozenset[str]] = {
    "CAP002": frozenset({"CAP003"}),
}


def _usable(match) -> bool:
    """A capability is reach, so a grant narrowed to named objects does not count.

    ``get secrets`` with ``resourceNames: [db-password]`` is not "reads every
    secret"; counting it would overstate the finding, which is the failure mode that
    gets a tool switched off.
    """
    return match is not None and not match.restricted


def _match_cluster(cluster: Cluster, identity: str, requirement: Requirement):
    for verb in requirement.verbs:
        for resource in requirement.resources:
            match = rbac.allows(
                cluster,
                identity,
                verb,
                resource,
                requirement.group,
                requirement.subresource,
                namespace=None,
            )
            if _usable(match):
                return match
    return None


def _satisfies(cluster: Cluster, identity: str, capability: Capability) -> tuple[bool, str, list[str]]:
    """Return (granted, evidence, namespaces) for one identity and capability."""
    if capability.scope == "cluster":
        evidence: list[str] = []
        for requirement in capability.requirements:
            match = _match_cluster(cluster, identity, requirement)
            if match is None:
                if capability.any_of:
                    continue
                return False, "", []
            evidence.append(match.describe())
        if not evidence:
            return False, "", []
        return True, " | ".join(dict.fromkeys(evidence)), []

    namespaces: list[str] = []
    evidence: list[str] = []
    for namespace in cluster.namespace_list():
        granted_all = True
        satisfied = 0
        local: list[str] = []
        for requirement in capability.requirements:
            found = None
            for verb in requirement.verbs:
                for resource in requirement.resources:
                    found = rbac.allows(
                        cluster,
                        identity,
                        verb,
                        resource,
                        requirement.group,
                        requirement.subresource,
                        namespace=namespace,
                    )
                    if _usable(found):
                        break
                    found = None
                if found is not None:
                    break
            if found is None:
                if capability.any_of:
                    continue
                granted_all = False
                break
            satisfied += 1
            local.append(found.describe())
        if granted_all and satisfied == 0:
            granted_all = False
        if granted_all:
            namespaces.append(namespace)
            evidence.extend(local)
    if not namespaces:
        return False, "", []
    return True, " | ".join(dict.fromkeys(evidence)), namespaces


def _prune(granted: dict[str, tuple[str, list[str]]]) -> list[str]:
    """Drop capabilities another held capability already implies."""
    if CAP001_SUBSUMES_ALL in granted:
        return [CAP001_SUBSUMES_ALL]
    kept = []
    for cap_id in granted:
        implied = any(
            cap_id in SUBSUMED.get(other, frozenset()) for other in granted if other != cap_id
        )
        if not implied:
            kept.append(cap_id)
    return kept


def evaluate(cluster: Cluster) -> tuple[list[Finding], dict[str, set[str]]]:
    findings: list[Finding] = []
    by_identity: dict[str, set[str]] = {}
    for identity in cluster.identity_ids():
        granted: dict[str, tuple[str, list[str]]] = {}
        for capability in CAPABILITIES:
            ok, evidence, namespaces = _satisfies(cluster, identity, capability)
            if ok:
                granted[capability.id] = (evidence, namespaces)
        kept = _prune(granted)
        if kept:
            by_identity[identity] = set(kept)
        for cap_id in kept:
            capability = BY_ID[cap_id]
            evidence, namespaces = granted[cap_id]
            message = f"{identity} can {capability.leads_to}"
            if capability.scope != "cluster":
                shown = ", ".join(namespaces[:4])
                if len(namespaces) > 4:
                    shown += f", and {len(namespaces) - 4} more"
                message += f" in {shown}"
            findings.append(
                Finding(
                    id=capability.id,
                    message=message,
                    evidence=evidence,
                    identity=identity,
                )
            )
    return findings, by_identity


# Ranking is by reach, not by finding severity: holding cluster-admin is reported as
# context (info) because platform ServiceAccounts hold it legitimately, but an
# identity that reaches the whole cluster still belongs at the top of the list.
REACH: dict[str, int] = {
    "CAP001": 4,
    "CAP002": 3,
    "CAP006": 3,
    "CAP007": 3,
    "CAP008": 3,
    "CAP009": 3,
    "CAP011": 3,
    "CAP003": 2,
    "CAP004": 2,
    "CAP005": 2,
    "CAP010": 2,
    "CAP012": 2,
}


def ranked_identities(cluster: Cluster, by_identity: dict[str, set[str]]) -> list[dict]:
    rows = []
    for identity in cluster.identity_ids():
        caps = sorted(by_identity.get(identity, set()))
        reach = max((REACH.get(cap_id, 0) for cap_id in caps), default=0)
        rows.append({"identity": identity, "capabilities": caps, "reach": reach})
    rows.sort(key=lambda row: (-row["reach"], row["identity"]))
    return rows
