"""RBAC resolution tests: the semantics that decide a verdict."""

from __future__ import annotations

import json

import pytest

from rbacpath import rbac
from rbacpath.model import load_export


def build(tmp_path, payload):
    path = tmp_path / "export.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_export(str(path))


def clusterrole(name, verbs, resources, groups=("",), resource_names=None):
    rule = {"verbs": list(verbs), "resources": list(resources), "apiGroups": list(groups)}
    if resource_names:
        rule["resourceNames"] = list(resource_names)
    return {"kind": "ClusterRole", "metadata": {"name": name}, "rules": [rule]}


def role(name, namespace, verbs, resources, groups=("",)):
    return {
        "kind": "Role",
        "metadata": {"name": name, "namespace": namespace},
        "rules": [{"verbs": list(verbs), "resources": list(resources), "apiGroups": list(groups)}],
    }


def binding(kind, name, role_kind, role_name, subjects, namespace=None):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return {
        "kind": kind,
        "metadata": metadata,
        "roleRef": {"kind": role_kind, "name": role_name},
        "subjects": subjects,
    }


def sa(name, namespace):
    return {"kind": "ServiceAccount", "name": name, "namespace": namespace}


def test_clusterrole_bound_by_rolebinding_is_namespace_scoped(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("secret-reader", ("get",), ("secrets",)),
            binding("RoleBinding", "b", "ClusterRole", "secret-reader", [sa("app", "prod")], "prod"),
        ],
    )
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "get", "secrets", namespace="prod")
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "get", "secrets") is None
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "get", "secrets", namespace="other") is None


def test_clusterrolebinding_is_cluster_wide(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("secret-reader", ("get",), ("secrets",)),
            binding("ClusterRoleBinding", "b", "ClusterRole", "secret-reader", [sa("app", "prod")]),
        ],
    )
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "get", "secrets") is not None


def test_role_only_applies_in_its_namespace(tmp_path):
    cluster = build(
        tmp_path,
        [
            role("reader", "prod", ("get",), ("configmaps",)),
            binding("RoleBinding", "b", "Role", "reader", [sa("app", "prod")], "prod"),
        ],
    )
    identity = "system:serviceaccount:prod:app"
    assert rbac.allows(cluster, identity, "get", "configmaps", namespace="prod") is not None
    assert rbac.allows(cluster, identity, "get", "configmaps", namespace="dev") is None


def test_wildcard_verb_and_resource(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("all", ("*",), ("*",), groups=("*",)),
            binding("ClusterRoleBinding", "b", "ClusterRole", "all", [sa("app", "prod")]),
        ],
    )
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "delete", "deployments", "apps")


def test_core_group_is_not_matched_by_an_apps_rule(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("apps-only", ("get",), ("deployments",), groups=("apps",)),
            binding("ClusterRoleBinding", "b", "ClusterRole", "apps-only", [sa("app", "prod")]),
        ],
    )
    identity = "system:serviceaccount:prod:app"
    assert rbac.allows(cluster, identity, "get", "deployments", "apps") is not None
    assert rbac.allows(cluster, identity, "get", "secrets", "") is None


def test_resource_names_mark_the_match_as_restricted(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("one-secret", ("get",), ("secrets",), resource_names=["db-password"]),
            binding("ClusterRoleBinding", "b", "ClusterRole", "one-secret", [sa("app", "prod")]),
        ],
    )
    match = rbac.allows(cluster, "system:serviceaccount:prod:app", "get", "secrets")
    assert match is not None
    assert match.restricted is True
    assert "resourceNames db-password" in match.describe()


def test_a_rule_on_pods_does_not_grant_pods_exec(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("pods", ("create",), ("pods",)),
            binding("ClusterRoleBinding", "b", "ClusterRole", "pods", [sa("app", "prod")]),
        ],
    )
    identity = "system:serviceaccount:prod:app"
    assert rbac.allows(cluster, identity, "create", "pods") is not None
    assert rbac.allows(cluster, identity, "create", "pods", subresource="exec") is None


def test_subresource_requires_the_subresource_form(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("exec", ("create",), ("pods/exec",)),
            binding("ClusterRoleBinding", "b", "ClusterRole", "exec", [sa("app", "prod")]),
        ],
    )
    identity = "system:serviceaccount:prod:app"
    assert rbac.allows(cluster, identity, "create", "pods", subresource="exec") is not None
    assert rbac.allows(cluster, identity, "create", "pods") is None


def test_group_membership_system_serviceaccounts_namespace(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("reader", ("get",), ("secrets",)),
            binding(
                "RoleBinding",
                "b",
                "ClusterRole",
                "reader",
                [{"kind": "Group", "name": "system:serviceaccounts:prod"}],
                "prod",
            ),
        ],
    )
    assert rbac.allows(cluster, "system:serviceaccount:prod:anything", "get", "secrets", namespace="prod")
    assert rbac.allows(cluster, "system:serviceaccount:dev:anything", "get", "secrets", namespace="prod") is None


def test_group_membership_system_authenticated(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("reader", ("get",), ("pods",)),
            binding(
                "ClusterRoleBinding",
                "b",
                "ClusterRole",
                "reader",
                [{"kind": "Group", "name": "system:authenticated"}],
            ),
        ],
    )
    assert rbac.allows(cluster, "user:alice", "get", "pods")


def test_user_subject_matches_only_that_user(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("reader", ("get",), ("pods",)),
            binding(
                "ClusterRoleBinding",
                "b",
                "ClusterRole",
                "reader",
                [{"kind": "User", "name": "alice"}],
            ),
        ],
    )
    assert rbac.allows(cluster, "user:alice", "get", "pods") is not None
    assert rbac.allows(cluster, "user:bob", "get", "pods") is None


def test_serviceaccount_subject_without_namespace_uses_binding_namespace(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("reader", ("get",), ("pods",)),
            binding("RoleBinding", "b", "ClusterRole", "reader", [{"kind": "ServiceAccount", "name": "app"}], "prod"),
        ],
    )
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "get", "pods", namespace="prod")


def test_system_masters_bypasses_authorisation(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("reader", ("get",), ("pods",)),
            binding(
                "ClusterRoleBinding",
                "b",
                "ClusterRole",
                "reader",
                [{"kind": "Group", "name": "system:masters"}],
            ),
        ],
    )
    match = rbac.allows(cluster, "group:system:masters", "delete", "nodes")
    assert match is not None
    assert match.binding.name == "system:masters"
    # A user is not in system:masters just because a binding names the group: the
    # authenticator decides membership, and it is not in the export.
    assert rbac.allows(cluster, "user:root", "delete", "nodes") is None


def test_no_binding_means_no_allow(tmp_path):
    cluster = build(tmp_path, [clusterrole("reader", ("get",), ("pods",)), {"kind": "Namespace", "metadata": {"name": "prod"}}])
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "get", "pods") is None


def test_binding_to_a_missing_role_grants_nothing(tmp_path):
    cluster = build(
        tmp_path,
        [binding("ClusterRoleBinding", "b", "ClusterRole", "ghost", [sa("app", "prod")])],
    )
    assert rbac.effective_rules(cluster, "system:serviceaccount:prod:app") == []


def test_unlisted_verb_does_not_match(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("reader", ("get",), ("pods",)),
            binding("ClusterRoleBinding", "b", "ClusterRole", "reader", [sa("app", "prod")]),
        ],
    )
    assert rbac.allows(cluster, "system:serviceaccount:prod:app", "delete", "pods") is None


def test_effective_rules_reports_the_binding(tmp_path):
    cluster = build(
        tmp_path,
        [
            clusterrole("reader", ("get",), ("pods",)),
            binding("RoleBinding", "rb", "ClusterRole", "reader", [sa("app", "prod")], "prod"),
        ],
    )
    rules = rbac.effective_rules(cluster, "system:serviceaccount:prod:app")
    assert len(rules) == 1
    assert rules[0][1].name == "rb"


def test_namespace_scope_hits_lists_each_namespace_once(tmp_path):
    cluster = build(
        tmp_path,
        [
            {"kind": "Namespace", "metadata": {"name": "a"}},
            {"kind": "Namespace", "metadata": {"name": "b"}},
            clusterrole("secrets", ("get", "list"), ("secrets",)),
            binding("ClusterRoleBinding", "b", "ClusterRole", "secrets", [sa("app", "a")]),
        ],
    )
    hits = rbac.namespace_scope_hits(
        cluster, "system:serviceaccount:a:app", ("get", "list"), ("secrets",)
    )
    assert [namespace for namespace, _ in hits] == ["a", "b"]
