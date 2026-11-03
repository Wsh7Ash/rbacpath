"""Escalation paths.

A path is a composition: two capabilities that individually look survivable, but
which together hand over something much larger. Paths are evaluated over the
capability set already computed for each identity, so a path can never claim
something the capability pass did not confirm — the evidence is the same Match
descriptions.
"""

from __future__ import annotations

from dataclasses import dataclass

from .catalog import Finding
from .model import Cluster


@dataclass(frozen=True)
class PathRule:
    id: str
    alternatives: tuple[frozenset[str], ...]
    leads_to: str


PATH_RULES: tuple[PathRule, ...] = (
    PathRule(
        "PATH001",
        (frozenset({"CAP007"}), frozenset({"CAP006"}), frozenset({"CAP008"})),
        "any role it can bind, including cluster-admin",
    ),
    PathRule("PATH002", (frozenset({"CAP009"}),), "cluster-admin, by impersonation"),
    PathRule("PATH003", (frozenset({"CAP002"}),), "every ServiceAccount token, including cluster-admin"),
    PathRule("PATH004", (frozenset({"CAP004"}), frozenset({"CAP005"})), "every secret in the affected namespaces"),
    PathRule("PATH005", (frozenset({"CAP011"}),), "command execution on every node"),
)


def evaluate(cluster: Cluster, by_identity: dict[str, set[str]], capability_findings: list[Finding]) -> list[Finding]:
    evidence_for: dict[tuple[str, str], str] = {}
    for finding in capability_findings:
        if finding.identity:
            entry = f"{finding.id} -> {finding.message}"
            if finding.evidence:
                entry += f" ({finding.evidence})"
            evidence_for[(finding.identity, finding.id)] = entry

    findings: list[Finding] = []
    for identity in sorted(by_identity):
        held = by_identity[identity]
        for rule in PATH_RULES:
            alternative = next((alt for alt in rule.alternatives if alt <= held), None)
            if alternative is None:
                continue
            steps = [evidence_for[(identity, cap_id)] for cap_id in sorted(alternative)]
            findings.append(
                Finding(
                    id=rule.id,
                    message=f"{identity} reaches {rule.leads_to}",
                    evidence=" then ".join(steps),
                    identity=identity,
                )
            )
    return findings
