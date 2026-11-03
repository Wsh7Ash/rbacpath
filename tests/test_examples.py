"""Verdicts for the shipped examples, pinned so a refactor cannot change them."""

from __future__ import annotations

import json

from rbacpath import capabilities, engine
from rbacpath.model import load_export


def test_risky_export_verdict(risky_export):
    report = engine.audit(load_export(risky_export))
    assert report.summary.counts == {"error": 6, "warn": 6, "info": 4}
    assert report.summary.band == "high-risk"
    assert report.summary.score == 82


def test_risky_export_paths_and_identities(risky_export):
    report = engine.audit(load_export(risky_export))
    assert {f.id for f in report.path_findings()} == {"PATH001", "PATH003", "PATH004"}
    assert {row["identity"] for row in report.identities} == {
        "system:serviceaccount:prod:admin",
        "system:serviceaccount:ci:deployer",
        "system:serviceaccount:default:default",
        "system:serviceaccount:prod:app",
    }


def test_clean_export_verdict(clean_export):
    report = engine.audit(load_export(clean_export))
    assert report.findings == []
    assert report.summary.band == "clean"
    assert report.summary.score == 0


def test_clean_export_grant_is_restricted_so_no_capability(clean_export):
    cluster = load_export(clean_export)
    _, by_identity = capabilities.evaluate(cluster)
    assert by_identity == {}


def test_restricted_secret_grant_is_not_reported_as_full_read(tmp_path):
    payload = [
        {"kind": "ServiceAccount", "metadata": {"name": "app", "namespace": "prod"}},
        {
            "kind": "ClusterRole",
            "metadata": {"name": "one"},
            "rules": [
                {
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "verbs": ["get", "list"],
                    "resourceNames": ["db-password"],
                }
            ],
        },
        {
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "b"},
            "roleRef": {"kind": "ClusterRole", "name": "one"},
            "subjects": [{"kind": "ServiceAccount", "name": "app", "namespace": "prod"}],
        },
    ]
    path = tmp_path / "export.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    findings, _ = capabilities.evaluate(load_export(str(path)))
    assert findings == []
