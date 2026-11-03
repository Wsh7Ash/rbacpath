"""Capability detection tests."""

from __future__ import annotations

import json

from rbacpath import capabilities
from rbacpath.model import load_export


def build(tmp_path, payload):
    path = tmp_path / "export.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_export(str(path))


def rule(verbs, resources, groups=("",), subresource=None):
    resources = [f"{r}/{subresource}" if subresource else r for r in resources]
    return {"verbs": list(verbs), "resources": resources, "apiGroups": list(groups)}


def binding(kind, role_kind, role_name, namespace=None):
    metadata = {"name": "b"}
    if namespace:
        metadata["namespace"] = namespace
    return {
        "kind": kind,
        "metadata": metadata,
        "roleRef": {"kind": role_kind, "name": role_name},
        "subjects": [
            {"kind": "ServiceAccount", "name": "app", "namespace": namespace or "prod"}
        ],
    }


def one(tmp_path, kind, rules, namespace=None):
    payload = [
        {"kind": kind, "metadata": {"name": "r", **({"namespace": namespace} if namespace else {})}, "rules": rules},
        {"kind": "ServiceAccount", "metadata": {"name": "app", "namespace": namespace or "prod"}},
        binding(
            "RoleBinding" if namespace else "ClusterRoleBinding",
            kind,
            "r",
            namespace,
        ),
    ]
    cluster = build(tmp_path, payload)
    findings, by_identity = capabilities.evaluate(cluster)
    return {f.id for f in findings}, findings, by_identity


def test_cap001_wildcard_is_admin(tmp_path):
    ids, _, _ = one(tmp_path, "ClusterRole", [rule(["*"], ["*"], ["*"])])
    assert "CAP001" in ids


def test_cap001_subsumes_the_other_capabilities(tmp_path):
    ids, findings, _ = one(tmp_path, "ClusterRole", [rule(["*"], ["*"], ["*"])])
    assert ids == {"CAP001"}
    assert findings[0].severity == "info"


def test_cap002_cluster_wide_secrets(tmp_path):
    ids, findings, _ = one(tmp_path, "ClusterRole", [rule(["get", "list"], ["secrets"])])
    assert "CAP002" in ids
    assert any(f.severity == "error" for f in findings)


def test_cap002_subsumes_cap003(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["get"], ["secrets"]), rule(["list"], ["secrets"])],
    )
    assert "CAP002" in ids
    assert "CAP003" not in ids


def test_cap003_needs_both_get_and_list(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["get"], ["secrets"])],
        namespace="prod",
    )
    assert "CAP003" not in ids


def test_cap003_namespace_scoped_secrets(tmp_path):
    ids, findings, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["get"], ["secrets"]), rule(["list"], ["secrets"])],
        namespace="prod",
    )
    assert "CAP003" in ids
    assert all("prod" in f.message for f in findings if f.id == "CAP003")


def test_cap004_pod_create(tmp_path):
    ids, _, _ = one(tmp_path, "ClusterRole", [rule(["create"], ["pods"])], namespace="prod")
    assert "CAP004" in ids


def test_cap005_workload_controller_create(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["create"], ["deployments"], ["apps"])],
        namespace="prod",
    )
    assert "CAP005" in ids


def test_cap006_rolebinding_create(tmp_path):
    ids, findings, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["create"], ["rolebindings"], ["rbac.authorization.k8s.io"])],
        namespace="prod",
    )
    assert "CAP006" in ids
    assert any(f.id == "CAP006" and f.severity == "error" for f in findings)


def test_cap007_clusterrolebinding_create(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["create"], ["clusterrolebindings"], ["rbac.authorization.k8s.io"])],
    )
    assert "CAP007" in ids


def test_cap008_bind_on_clusterroles(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["bind"], ["clusterroles"], ["rbac.authorization.k8s.io"])],
    )
    assert "CAP008" in ids


def test_cap009_impersonate(tmp_path):
    ids, _, _ = one(tmp_path, "ClusterRole", [rule(["impersonate"], ["serviceaccounts"])])
    assert "CAP009" in ids


def test_cap010_token_creation(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["create"], ["serviceaccounts"], subresource="token")],
        namespace="prod",
    )
    assert "CAP010" in ids


def test_cap011_nodes_proxy(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["get"], ["nodes"], subresource="proxy")],
    )
    assert "CAP011" in ids


def test_cap012_pod_exec(tmp_path):
    ids, _, _ = one(
        tmp_path,
        "ClusterRole",
        [rule(["create"], ["pods"], subresource="exec")],
        namespace="prod",
    )
    assert "CAP012" in ids


def test_namespace_capability_not_reported_for_cluster_scope(tmp_path):
    ids, _, _ = one(tmp_path, "ClusterRole", [rule(["get"], ["secrets"]), rule(["list"], ["secrets"])])
    assert "CAP003" not in ids


def test_namespace_list_is_truncated_in_the_message(tmp_path):
    namespaces = [f"ns{i}" for i in range(6)]
    payload = [
        {"kind": "ClusterRole", "metadata": {"name": "r"}, "rules": [rule(["create"], ["pods"])]},
        {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "b"},
            "roleRef": {"kind": "ClusterRole", "name": "r"},
            "subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "ns0"}],
        },
    ]
    payload += [{"kind": "Namespace", "metadata": {"name": ns}} for ns in namespaces]
    payload.append({"kind": "ServiceAccount", "metadata": {"name": "app", "namespace": "ns0"}})
    findings, _ = capabilities.evaluate(build(tmp_path, payload))
    message = next(f.message for f in findings if f.id == "CAP004")
    assert "and 2 more" in message


def test_ranked_identities_puts_the_most_powerful_first(tmp_path):
    payload = [
        {"kind": "ClusterRole", "metadata": {"name": "admin"}, "rules": [rule(["*"], ["*"], ["*"])]},
        {"kind": "ClusterRole", "metadata": {"name": "pods"}, "rules": [rule(["create"], ["pods"])]},
        {"kind": "ServiceAccount", "metadata": {"name": "strong", "namespace": "prod"}},
        {"kind": "ServiceAccount", "metadata": {"name": "weak", "namespace": "prod"}},
        {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "b1"},
            "roleRef": {"kind": "ClusterRole", "name": "admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "strong", "namespace": "prod"}],
        },
        {
            "kind": "RoleBinding",
            "metadata": {"name": "b2", "namespace": "prod"},
            "roleRef": {"kind": "ClusterRole", "name": "pods"},
            "subjects": [{"kind": "ServiceAccount", "name": "weak", "namespace": "prod"}],
        },
    ]
    cluster = build(tmp_path, payload)
    findings, by_identity = capabilities.evaluate(cluster)
    rows = capabilities.ranked_identities(cluster, by_identity)
    assert rows[0]["identity"].endswith(":strong")
    assert rows[0]["capabilities"] == ["CAP001"]
