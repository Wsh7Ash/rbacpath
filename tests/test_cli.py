"""CLI tests: the contract a pipeline sees."""

from __future__ import annotations

import json

import pytest

from rbacpath import cli


def test_version(capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == "rbacpath 1.0.0"


def test_caps_lists_every_capability(capsys):
    assert cli.main(["caps"]) == 0
    out = capsys.readouterr().out
    assert "CAP001" in out
    assert "CAP012" in out


def test_caps_json(capsys):
    assert cli.main(["caps", "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 12
    assert {"id", "scope", "severity", "leads_to"} <= set(rows[0])


def test_risky_export_exits_2(risky_export, capsys):
    assert cli.main(["audit", risky_export]) == 2
    out = capsys.readouterr().out
    assert "band high-risk" in out
    assert "paths" in out


def test_clean_export_exits_0(clean_export, capsys):
    assert cli.main(["audit", clean_export]) == 0
    out = capsys.readouterr().out
    assert "0 error  0 warn  0 info" in out
    assert "band clean" in out


def test_fail_on_warn(risky_export, clean_export, capsys):
    assert cli.main(["audit", risky_export, "--fail-on", "warn"]) == 2
    assert cli.main(["audit", clean_export, "--fail-on", "warn"]) == 0


def test_fail_on_none(risky_export):
    assert cli.main(["audit", risky_export, "--fail-on", "none"]) == 0


def test_fail_on_info(clean_export):
    assert cli.main(["audit", clean_export, "--fail-on", "info"]) == 0


def test_json_report_has_the_documented_shape(risky_export, capsys):
    assert cli.main(["audit", risky_export, "--format", "json", "--fail-on", "none"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["tool"] == "rbacpath"
    assert payload["summary"]["band"] == "high-risk"
    assert {"export", "identities", "findings"} <= set(payload)
    assert {"id", "severity", "evidence", "fix"} <= set(payload["findings"][0])


def test_markdown_report(risky_export, capsys):
    assert cli.main(["audit", risky_export, "--format", "markdown", "--fail-on", "none"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("# rbacpath report")
    assert "## Escalation paths" in out


def test_out_writes_a_file(risky_export, tmp_path, capsys):
    target = tmp_path / "report.json"
    assert cli.main(["audit", risky_export, "--format", "json", "--out", str(target), "--fail-on", "none"]) == 0
    payload = json.loads(target.read_text(encoding="utf-8"))
    assert payload["tool"] == "rbacpath"


def test_missing_file_exits_3(capsys):
    assert cli.main(["audit", "nope.json"]) == 3
    assert "cannot be read" in capsys.readouterr().err


def test_invalid_export_exits_3(tmp_path, capsys):
    bad = tmp_path / "bad.json"
    bad.write_text('{"kind": "ConfigMap", "metadata": {"name": "x"}}', encoding="utf-8")
    assert cli.main(["audit", str(bad)]) == 3
    assert "no Kubernetes objects recognised" in capsys.readouterr().err


def test_paths_command_lists_paths(risky_export, capsys):
    assert cli.main(["paths", risky_export]) == 0
    out = capsys.readouterr().out
    assert "PATH001" in out


def test_paths_command_filters_by_identity(risky_export, capsys):
    identity = "system:serviceaccount:ci:deployer"
    assert cli.main(["paths", risky_export, "--from", identity]) == 0
    out = capsys.readouterr().out
    assert "PATH003" in out
    assert identity in out


def test_paths_command_reports_no_path(clean_export, capsys):
    assert cli.main(["paths", clean_export]) == 0
    assert "no escalation path" in capsys.readouterr().out


def test_paths_json(risky_export, capsys):
    assert cli.main(["paths", risky_export, "--format", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert rows and {"id", "path", "identity"} <= set(rows[0])
