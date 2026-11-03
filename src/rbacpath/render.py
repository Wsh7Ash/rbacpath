"""Render a report.

The text form leads with the paths, because a path is the thing a reader must act
on: an identity that can reach cluster-admin matters more than the eight warnings
that produced it.
"""

from __future__ import annotations

import json

from . import __version__
from .catalog import SEVERITY_RANK, Finding
from .engine import Report


def _finding_dict(finding: Finding) -> dict:
    return {
        "id": finding.id,
        "severity": finding.severity,
        "title": finding.title,
        "message": finding.message,
        "evidence": finding.evidence,
        "identity": finding.identity,
        "location": finding.location,
        "rationale": finding.rule.rationale,
        "fix": finding.rule.fix,
    }


def as_dict(report: Report) -> dict:
    cluster = report.cluster
    summary = report.summary
    return {
        "tool": "rbacpath",
        "version": __version__,
        "target": cluster.source,
        "export": {
            "kinds": dict(cluster.kind_counts),
            "namespaces": list(cluster.namespace_list()),
            "service_accounts": len(cluster.service_accounts),
            "bindings": len(cluster.bindings),
            "roles": len(cluster.roles),
            "workloads": len(cluster.workloads),
            "warnings": list(cluster.warnings),
        },
        "summary": {
            "error": summary.counts.get("error", 0),
            "warn": summary.counts.get("warn", 0),
            "info": summary.counts.get("info", 0),
            "score": summary.score,
            "band": summary.band,
            "paths": len(report.path_findings()),
        },
        "identities": report.identities,
        "findings": [_finding_dict(finding) for finding in report.findings],
    }


def _header(report: Report) -> list[str]:
    cluster = report.cluster
    kinds = ", ".join(f"{kind} {count}" for kind, count in cluster.kind_counts.items())
    namespaces = ", ".join(cluster.namespace_list()) or "(none)"
    return [
        f"rbacpath {__version__}  {cluster.source}",
        f"export    {kinds}",
        f"namespaces {namespaces}",
        "",
    ]


def as_text(report: Report) -> str:
    lines = _header(report)
    summary = report.summary
    counts = summary.counts
    lines.append(
        f"summary   {counts.get('error', 0)} error  {counts.get('warn', 0)} warn  "
        f"{counts.get('info', 0)} info   {len(report.path_findings())} path(s)   "
        f"band {summary.band} (score {summary.score})"
    )
    lines.append("")

    path_findings = report.path_findings()
    if path_findings:
        lines.append("paths")
        for finding in path_findings:
            lines.append(f"  {finding.id}  {finding.message}")
            lines.append(f"        via {finding.evidence}")
        lines.append("")

    for severity in ("error", "warn", "info"):
        group = [f for f in report.findings if f.severity == severity and not f.id.startswith("PATH")]
        if not group:
            continue
        lines.append(severity)
        for finding in group:
            where = f"  [{finding.location}]" if finding.location else ""
            lines.append(f"  {finding.id}  {finding.message}{where}")
            lines.append(f"        evidence: {finding.evidence}")
        lines.append("")

    if report.identities:
        lines.append("identities")
        for row in report.identities:
            caps = ", ".join(row["capabilities"]) or "-"
            lines.append(f"  {row['identity']:<52} {caps}")
        lines.append("")

    if report.cluster.warnings:
        lines.append("export warnings")
        for warning in report.cluster.warnings:
            lines.append(f"  {warning}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def as_markdown(report: Report) -> str:
    summary = report.summary
    counts = summary.counts
    lines = [f"# rbacpath report: `{report.cluster.source}`", ""]
    lines.append(
        f"**{counts.get('error', 0)} error / {counts.get('warn', 0)} warn / "
        f"{counts.get('info', 0)} info / {len(report.path_findings())} path(s)** - "
        f"band **{summary.band}** (score {summary.score})"
    )
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append("| Kinds | " + ", ".join(f"`{k}` {v}" for k, v in report.cluster.kind_counts.items()) + " |")
    lines.append("| Namespaces | " + (", ".join(f"`{n}`" for n in report.cluster.namespace_list()) or "none") + " |")
    lines.append("")

    path_findings = report.path_findings()
    if path_findings:
        lines += ["## Escalation paths", ""]
        for finding in path_findings:
            lines.append(f"### {finding.id} - {finding.title}")
            lines.append("")
            lines.append(finding.message)
            lines.append("")
            lines.append(f"Path: {finding.evidence}")
            lines.append("")
            lines.append(f"Fix: {finding.rule.fix}")
            lines.append("")

    for severity in ("error", "warn", "info"):
        group = [f for f in report.findings if f.severity == severity and not f.id.startswith("PATH")]
        if not group:
            continue
        lines.append(f"## {severity} ({len(group)})")
        lines.append("")
        for finding in group:
            lines.append(f"### {finding.id} - {finding.title}")
            lines.append("")
            lines.append(finding.message)
            lines.append("")
            lines.append(f"Evidence: `{finding.evidence}`")
            lines.append("")
            lines.append(f"Why it matters: {finding.rule.rationale}")
            lines.append("")
            lines.append(f"Fix: {finding.rule.fix}")
            lines.append("")

    if report.identities:
        lines += ["## Identities", "", "| Identity | Capabilities |", "|---|---|"]
        for row in report.identities:
            caps = ", ".join(f"`{c}`" for c in row["capabilities"]) or "-"
            lines.append(f"| `{row['identity']}` | {caps} |")
        lines.append("")

    if report.cluster.warnings:
        lines += ["## Export warnings", ""]
        for warning in report.cluster.warnings:
            lines.append(f"- {warning}")
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def render(fmt: str, report: Report) -> str:
    if fmt == "json":
        return json.dumps(as_dict(report), indent=2) + "\n"
    if fmt == "markdown":
        return as_markdown(report)
    return as_text(report)


def capability_table(fmt: str = "text") -> str:
    from .capabilities import CAPABILITIES
    from .catalog import RULES

    rows = []
    for capability in CAPABILITIES:
        rule = RULES[capability.id]
        rows.append(
            {
                "id": capability.id,
                "scope": capability.scope,
                "severity": rule.severity,
                "title": rule.title,
                "leads_to": capability.leads_to,
            }
        )
    if fmt == "json":
        return json.dumps(rows, indent=2) + "\n"
    lines = [f"{'ID':<7} {'SCOPE':<10} {'SEVERITY':<8} LEADS TO"]
    for row in sorted(rows, key=lambda r: (-SEVERITY_RANK[r["severity"]], r["id"])):
        lines.append(
            f"{row['id']:<7} {row['scope']:<10} {row['severity']:<8} {row['leads_to']}"
        )
    return "\n".join(lines) + "\n"
