"""RBAC resolution.

Four details decide whether a verdict is right, and each is a place reviews go
wrong:

1. **A ClusterRole bound by a RoleBinding is namespaced.** The ClusterRole's rules
   apply, but only inside the binding's namespace. Treating that binding as
   cluster-wide is the most common false positive in this domain.
2. **Wildcards.** ``*`` in verbs, resources or apiGroups matches everything in that
   dimension, and appears in real cluster-admin roles.
3. **resourceNames narrows a rule.** ``get secrets`` with
   ``resourceNames: [db-password]`` is not "reads all secrets".
4. **Group membership.** ``system:serviceaccounts:<ns>`` and
   ``system:authenticated`` are real subjects; a ServiceAccount belongs to both.

``system:masters`` is hardcoded in the API server to bypass authorisation. Which
users are in that group is decided by the authenticator and is not in the export,
so the group is honoured when evaluated as an identity and never assumed for a
user or ServiceAccount.
"""

from __future__ import annotations

from dataclasses import dataclass

from .model import Binding, Cluster, PolicyRule, Subject

MASTERS_GROUP = "system:masters"


@dataclass(frozen=True)
class Match:
    rule: PolicyRule
    binding: Binding
    role_kind: str
    role_name: str

    @property
    def scope(self) -> str | None:
        return self.binding.namespace

    @property
    def restricted(self) -> bool:
        return bool(self.rule.resource_names)

    def describe(self) -> str:
        scope = self.scope or "cluster-wide"
        parts = [
            f"{self.binding.name} ({'ClusterRoleBinding' if self.scope is None else 'RoleBinding'})",
            f"{self.role_kind} {self.role_name}",
            f"scope {scope}",
            f"verbs {','.join(self.rule.verbs) or '-'}",
            f"resources {','.join(self.rule.resources) or '-'}",
            f"apiGroups {','.join(self.rule.api_groups) or '-'}",
        ]
        if self.rule.resource_names:
            parts.append(f"resourceNames {','.join(self.rule.resource_names)}")
        return "; ".join(parts)


def group_memberships(identity: str) -> frozenset[str]:
    groups = {"system:authenticated"}
    if identity.startswith("group:"):
        # A group evaluated as an identity is a member of itself. Membership in
        # system:masters is decided by the authenticator, not by RBAC, so the only
        # honest way to represent it here is to evaluate the group directly.
        groups.add(identity[len("group:"):])
        return frozenset(groups)
    prefix = "system:serviceaccount:"
    if identity.startswith(prefix):
        namespace = identity[len(prefix):].split(":")[0]
        groups.add("system:serviceaccounts")
        groups.add(f"system:serviceaccounts:{namespace}")
    return frozenset(groups)


def binding_applies(binding: Binding, identity: str) -> bool:
    memberships = group_memberships(identity)
    for subject in binding.subjects:
        if subject.kind == "User" and identity == f"user:{subject.name}":
            return True
        if subject.kind == "ServiceAccount":
            namespace = subject.namespace or binding.namespace or "default"
            if identity == f"system:serviceaccount:{namespace}:{subject.name}":
                return True
        if subject.kind == "Group" and subject.name in memberships:
            return True
    return False


def effective_rules(cluster: Cluster, identity: str) -> list[tuple[PolicyRule, Binding, str, str]]:
    """Every (rule, binding, role_kind, role_name) that reaches ``identity``."""
    out: list[tuple[PolicyRule, Binding, str, str]] = []
    for binding in cluster.bindings:
        if not binding_applies(binding, identity):
            continue
        if binding.role_kind == "ClusterRole":
            role = cluster.roles.get((None, binding.role_name))
        else:
            role = cluster.roles.get((binding.namespace, binding.role_name))
        if role is None:
            continue
        for rule in role.rules:
            out.append((rule, binding, binding.role_kind, binding.role_name))
    return out


def _rule_matches(
    rule: PolicyRule,
    verb: str,
    resource: str,
    group: str,
    subresource: str | None,
) -> bool:
    if not ("*" in rule.verbs or verb in rule.verbs):
        return False
    if not ("*" in rule.api_groups or group in rule.api_groups):
        return False
    if "*" in rule.resources:
        return True
    # A rule on "pods" does not grant "pods/exec"; the subresource is a distinct
    # resource in RBAC, and only the "pods/exec" form (or a wildcard) matches it.
    if subresource:
        return f"{resource}/{subresource}" in rule.resources
    return resource in rule.resources


def allows(
    cluster: Cluster,
    identity: str,
    verb: str,
    resource: str,
    group: str = "",
    subresource: str | None = None,
    namespace: str | None = None,
) -> Match | None:
    """First match granting ``verb`` on ``resource``.

    ``namespace=None`` requires cluster-wide scope; a namespace requires a rule that
    is effective there, which includes cluster-wide rules.
    """
    if MASTERS_GROUP in group_memberships(identity):
        synthetic = Binding(
            name=MASTERS_GROUP,
            namespace=None,
            role_kind="Group",
            role_name=MASTERS_GROUP,
            subjects=(Subject("Group", MASTERS_GROUP),),
        )
        return Match(PolicyRule(("*",), ("*",), ("*",)), synthetic, "Group", MASTERS_GROUP)

    for rule, binding, role_kind, role_name in effective_rules(cluster, identity):
        if not _rule_matches(rule, verb, resource, group, subresource):
            continue
        if namespace is None:
            if binding.namespace is not None:
                continue
        elif binding.namespace not in (None, namespace):
            continue
        return Match(rule, binding, role_kind, role_name)
    return None


def namespace_scope_hits(
    cluster: Cluster,
    identity: str,
    verbs: tuple[str, ...],
    resources: tuple[str, ...],
    group: str = "",
    subresource: str | None = None,
) -> list[tuple[str, Match]]:
    """Every namespace where at least one verb/resource pair is granted."""
    hits: list[tuple[str, Match]] = []
    for namespace in cluster.namespace_list():
        for verb in verbs:
            for resource in resources:
                match = allows(cluster, identity, verb, resource, group, subresource, namespace)
                if match is not None:
                    hits.append((namespace, match))
                    break
            else:
                continue
            break
    return hits
