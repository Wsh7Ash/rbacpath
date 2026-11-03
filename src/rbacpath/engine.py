"""Assemble one report from one export."""

from __future__ import annotations

from dataclasses import dataclass, field

from . import capabilities, paths, workloads
from .catalog import SEVERITY_RANK, Finding, Summary, summarise
from .model import Cluster


@dataclass
class Report:
    cluster: Cluster
    findings: list[Finding] = field(default_factory=list)
    identities: list[dict] = field(default_factory=list)
    capabilities_by_identity: dict[str, set[str]] = field(default_factory=dict)
    summary: Summary | None = None

    def by_severity(self, severity: str) -> list[Finding]:
        return [finding for finding in self.findings if finding.severity == severity]

    def path_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.id.startswith("PATH")]

    def capability_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.id.startswith("CAP")]

    def workload_findings(self) -> list[Finding]:
        return [finding for finding in self.findings if finding.id.startswith("W")]


def _sort_key(finding: Finding):
    return (-SEVERITY_RANK[finding.severity], finding.id, finding.identity or "", finding.location or "")


def audit(cluster: Cluster) -> Report:
    capability_findings, by_identity = capabilities.evaluate(cluster)
    path_findings = paths.evaluate(cluster, by_identity, capability_findings)
    workload_findings = workloads.evaluate(cluster)

    findings = [*path_findings, *capability_findings, *workload_findings]
    findings.sort(key=_sort_key)

    return Report(
        cluster=cluster,
        findings=findings,
        identities=capabilities.ranked_identities(cluster, by_identity),
        capabilities_by_identity=by_identity,
        summary=summarise(findings),
    )
