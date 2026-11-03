"""Loader and model tests."""

from __future__ import annotations

import json

import pytest

from rbacpath import model


def write(tmp_path, payload, name="export.json"):
    path = tmp_path / name
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def obj(kind, name, namespace=None, **extra):
    metadata = {"name": name}
    if namespace:
        metadata["namespace"] = namespace
    return {"kind": kind, "metadata": metadata, **extra}


def test_loads_a_single_object(tmp_path):
    cluster = model.load_export(write(tmp_path, obj("ServiceAccount", "app", "prod")))
    assert cluster.service_accounts[0].identity == "system:serviceaccount:prod:app"


def test_loads_a_list_with_items(tmp_path):
    payload = {"kind": "List", "items": [obj("Namespace", "prod")]}
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.namespaces == ("prod",)


def test_loads_a_bare_array(tmp_path):
    payload = [obj("Namespace", "a"), obj("Namespace", "b")]
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.namespace_list() == ("a", "b")


def test_loads_jsonl(tmp_path):
    path = tmp_path / "export.jsonl"
    path.write_text(
        "\n".join(json.dumps(obj("Namespace", name)) for name in ("a", "b")),
        encoding="utf-8",
    )
    cluster = model.load_export(str(path))
    assert set(cluster.namespace_list()) == {"a", "b"}


def test_namespace_defaults_to_default(tmp_path):
    cluster = model.load_export(write(tmp_path, obj("ServiceAccount", "app")))
    assert cluster.service_accounts[0].namespace == "default"


def test_object_without_kind_is_skipped_with_a_warning(tmp_path):
    cluster = model.load_export(
        write(tmp_path, [{"metadata": {"name": "x"}}, obj("Namespace", "prod")])
    )
    assert any("without a kind" in warning for warning in cluster.warnings)


def test_object_without_name_is_skipped_with_a_warning(tmp_path):
    cluster = model.load_export(
        write(tmp_path, [{"kind": "Namespace", "metadata": {}}, obj("Namespace", "prod")])
    )
    assert any("without metadata.name" in warning for warning in cluster.warnings)


def test_missing_file_is_a_load_error():
    with pytest.raises(model.LoadError):
        model.load_export("does-not-exist.json")


def test_invalid_json_is_a_load_error(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(model.LoadError):
        model.load_export(str(path))


def test_no_recognised_kinds_is_a_load_error(tmp_path):
    with pytest.raises(model.LoadError):
        model.load_export(write(tmp_path, [obj("ConfigMap", "settings")]))


def test_role_scope_is_namespace_clusterrole_is_none(tmp_path):
    payload = [
        obj("Role", "r", "prod", rules=[]),
        obj("ClusterRole", "cr", rules=[]),
    ]
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.roles[("prod", "r")].namespace == "prod"
    assert cluster.roles[(None, "cr")].namespace is None


def test_role_rules_are_parsed(tmp_path):
    payload = obj(
        "ClusterRole",
        "reader",
        rules=[{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}],
    )
    cluster = model.load_export(write(tmp_path, payload))
    rule = cluster.roles[(None, "reader")].rules[0]
    assert rule.verbs == ("get",)
    assert rule.resources == ("pods",)
    assert rule.api_groups == ("",)


def test_role_rule_strings_are_normalised(tmp_path):
    payload = obj("ClusterRole", "r", rules=[{"verbs": "get", "resources": "pods"}])
    cluster = model.load_export(write(tmp_path, payload))
    rule = cluster.roles[(None, "r")].rules[0]
    assert rule.verbs == ("get",)
    assert rule.resources == ("pods",)


def test_aggregated_role_is_warned_about(tmp_path):
    payload = obj("ClusterRole", "agg", aggregationRule={"clusterRoleSelectors": []}, rules=[])
    cluster = model.load_export(write(tmp_path, payload))
    assert any("aggregationRule" in warning for warning in cluster.warnings)


def test_binding_without_roleref_is_skipped(tmp_path):
    payload = [
        obj("ClusterRoleBinding", "broken", subjects=[]),
        obj("Namespace", "prod"),
    ]
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.bindings == ()
    assert any("no roleRef" in warning for warning in cluster.warnings)


def test_missing_clusterrole_is_warned_about(tmp_path):
    payload = [
        obj("ClusterRoleBinding", "b", roleRef={"kind": "ClusterRole", "name": "ghost"}, subjects=[]),
        obj("Namespace", "prod"),
    ]
    cluster = model.load_export(write(tmp_path, payload))
    assert any("ClusterRole ghost" in w and "understated" in w for w in cluster.warnings)


def test_pod_podspec_is_its_spec(tmp_path):
    payload = obj(
        "Pod",
        "p",
        "prod",
        spec={"serviceAccountName": "app", "containers": [{"name": "c"}]},
    )
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.workloads[0].pod_spec["serviceAccountName"] == "app"


def test_deployment_podspec_is_under_template(tmp_path):
    payload = obj(
        "Deployment",
        "d",
        "prod",
        spec={"template": {"spec": {"serviceAccountName": "app"}}},
    )
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.workloads[0].service_account == "app"


def test_cronjob_podspec_nests_through_jobtemplate(tmp_path):
    payload = obj(
        "CronJob",
        "c",
        "prod",
        spec={
            "jobTemplate": {
                "spec": {"template": {"spec": {"serviceAccountName": "batch"}}}
            }
        },
    )
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.workloads[0].service_account == "batch"


def test_workload_without_template_is_skipped(tmp_path):
    payload = [
        obj("Deployment", "d", "prod"),
        obj("Namespace", "prod"),
    ]
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.workloads == ()
    assert any("no pod template" in warning for warning in cluster.warnings)


def test_workload_service_account_defaults_to_default(tmp_path):
    payload = obj("Pod", "p", "prod", spec={"containers": []})
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.workloads[0].service_account == "default"


def test_identity_ids_include_users_and_groups_from_bindings(tmp_path):
    payload = [
        obj(
            "ClusterRoleBinding",
            "b",
            roleRef={"kind": "ClusterRole", "name": "x"},
            subjects=[
                {"kind": "User", "name": "alice"},
                {"kind": "Group", "name": "system:authenticated"},
            ],
        ),
        obj("ClusterRole", "x", rules=[]),
    ]
    cluster = model.load_export(write(tmp_path, payload))
    assert "user:alice" in cluster.identity_ids()
    assert "group:system:authenticated" in cluster.identity_ids()


def test_namespace_list_merges_declared_and_derived(tmp_path):
    payload = [
        obj("Namespace", "declared"),
        obj("ServiceAccount", "sa", "from-sa"),
        obj("Pod", "p", "from-pod", spec={"containers": []}),
    ]
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.namespace_list() == ("declared", "from-pod", "from-sa")


def test_kind_counts_exclude_unsupported_kinds(tmp_path):
    payload = [obj("Namespace", "a"), obj("ConfigMap", "c")]
    cluster = model.load_export(write(tmp_path, payload))
    assert cluster.kind_counts == {"Namespace": 1}
