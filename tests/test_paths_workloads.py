"""Path composition and workload rule tests."""

from __future__ import annotations

import json

from rbacpath import engine, paths, workloads
from rbacpath.catalog import Finding
from rbacpath.model import load_export


def build(tmp_path, payload):
    path = tmp_path / "export.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return load_export(str(path))


def pod(tmp_path, container=None, volumes=None, **pod_fields):
    spec = {"containers": [{"name": "c", "image": "img@sha256:" + "a" * 64, **(container or {})}]}
    if volumes:
        spec["volumes"] = volumes
    pod_fields.setdefault("automountServiceAccountToken", False)
    spec.update(pod_fields)
    cluster = build(tmp_path, [{"kind": "Pod", "metadata": {"name": "p", "namespace": "prod"}, "spec": spec}])
    return workloads.evaluate(cluster)


def test_privileged_container(tmp_path):
    findings = pod(tmp_path, {"securityContext": {"privileged": True}})
    assert [f.id for f in findings] == ["W001"]


def test_hostpath_volume(tmp_path):
    findings = pod(
        tmp_path,
        volumes=[{"name": "root", "hostPath": {"path": "/"}}],
        automountServiceAccountToken=False,
    )
    assert [f.id for f in findings] == ["W002"]


def test_host_namespaces(tmp_path):
    findings = pod(tmp_path, hostPID=True, hostNetwork=True, automountServiceAccountToken=False)
    assert [f.id for f in findings] == ["W003"]
    assert "hostPID = true" in findings[0].evidence


def test_runs_as_root(tmp_path):
    findings = pod(tmp_path, {"securityContext": {"runAsUser": 0}}, automountServiceAccountToken=False)
    assert [f.id for f in findings] == ["W004"]


def test_run_as_non_root_false(tmp_path):
    findings = pod(tmp_path, {"securityContext": {"runAsNonRoot": False}}, automountServiceAccountToken=False)
    assert [f.id for f in findings] == ["W004"]


def test_allow_privilege_escalation(tmp_path):
    findings = pod(tmp_path, {"securityContext": {"allowPrivilegeEscalation": True}}, automountServiceAccountToken=False)
    assert [f.id for f in findings] == ["W005"]


def test_added_capabilities(tmp_path):
    findings = pod(
        tmp_path,
        {"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}},
        automountServiceAccountToken=False,
    )
    assert [f.id for f in findings] == ["W006"]
    assert "SYS_ADMIN" in findings[0].evidence


def test_automount_is_information(tmp_path):
    findings = pod(tmp_path, automountServiceAccountToken=True)
    assert [f.id for f in findings] == ["W007"]
    assert findings[0].severity == "info"


def test_latest_tag_is_mutable(tmp_path):
    cluster = build(
        tmp_path,
        [
            {
                "kind": "Pod",
                "metadata": {"name": "p", "namespace": "prod"},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{"name": "c", "image": "nginx:latest"}],
                },
            }
        ],
    )
    assert [f.id for f in workloads.evaluate(cluster)] == ["W008"]


def test_digest_pinned_image_is_not_reported(tmp_path):
    findings = pod(tmp_path, automountServiceAccountToken=False)
    assert findings == []


def test_absent_security_context_is_not_a_finding(tmp_path):
    findings = pod(tmp_path, automountServiceAccountToken=False)
    assert findings == []


def test_init_containers_are_checked(tmp_path):
    cluster = build(
        tmp_path,
        [
            {
                "kind": "Pod",
                "metadata": {"name": "p", "namespace": "prod"},
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": [{"name": "main", "image": "img@sha256:" + "b" * 64}],
                    "initContainers": [
                        {
                            "name": "init",
                            "image": "img@sha256:" + "c" * 64,
                            "securityContext": {"privileged": True},
                        }
                    ],
                },
            }
        ],
    )
    findings = workloads.evaluate(cluster)
    assert [f.id for f in findings] == ["W001"]
    assert "init" in findings[0].message


def test_paths_compose_capabilities():
    capability_findings = [
        Finding("CAP007", "can bind", "b (ClusterRoleBinding) grants r", identity="system:serviceaccount:prod:app"),
        Finding("CAP009", "can impersonate", "b2 grants r2", identity="system:serviceaccount:prod:app"),
    ]
    by_identity = {"system:serviceaccount:prod:app": {"CAP007", "CAP009"}}
    found = paths.evaluate(None, by_identity, capability_findings)
    assert {f.id for f in found} == {"PATH001", "PATH002"}


def test_path_alternatives_require_every_capability():
    capability_findings = [Finding("CAP004", "pods", "e", identity="x")]
    by_identity = {"x": {"CAP004"}}
    found = paths.evaluate(None, by_identity, capability_findings)
    assert [f.id for f in found] == ["PATH004"]


def test_no_capabilities_no_paths():
    assert paths.evaluate(None, {"x": set()}, []) == []


def test_engine_sorts_errors_first(tmp_path):
    cluster = load_export(str(tmp_path / "missing.json")) if False else build(
        tmp_path,
        [
            {"kind": "ClusterRole", "metadata": {"name": "admin"}, "rules": [{"verbs": ["*"], "resources": ["*"], "apiGroups": ["*"]}]},
            {"kind": "ClusterRoleBinding", "metadata": {"name": "b"}, "roleRef": {"kind": "ClusterRole", "name": "admin"}, "subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "prod"}]},
            {"kind": "ServiceAccount", "metadata": {"name": "app", "namespace": "prod"}},
            {"kind": "Pod", "metadata": {"name": "p", "namespace": "prod"}, "spec": {"containers": [{"name": "c", "image": "img@sha256:" + "d" * 64}]}},
        ],
    )
    report = engine.audit(cluster)
    severities = [f.severity for f in report.findings]
    assert severities == ["info", "info"]
    assert report.summary.band == "clean"
