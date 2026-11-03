"""Command line interface.

Exit codes: ``0`` nothing at or above the threshold, ``2`` threshold breached,
``3`` the export could not be read.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, engine, model, render
from .catalog import SEVERITY_RANK, Finding


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="rbacpath",
        description="Read a Kubernetes JSON export and report what its RBAC actually "
        "grants, including composed escalation paths. Offline; talks to no cluster.",
    )
    parser.add_argument("--version", action="version", version=f"rbacpath {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    audit = sub.add_parser("audit", help="audit an export")
    audit.add_argument("path", help="JSON export produced with kubectl get -o json")
    audit.add_argument("--format", choices=("text", "json", "markdown"), default="text")
    audit.add_argument(
        "--fail-on",
        choices=("error", "warn", "info", "none"),
        default="error",
        help="lowest severity that makes the exit code 2 (default: error)",
    )
    audit.add_argument("--out", help="write the report to this file")

    paths_cmd = sub.add_parser("paths", help="show only the escalation paths")
    paths_cmd.add_argument("path")
    paths_cmd.add_argument("--from", dest="identity", help="restrict to one identity")
    paths_cmd.add_argument("--format", choices=("text", "json"), default="text")

    caps = sub.add_parser("caps", help="list the capability catalogue")
    caps.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _threshold_breached(findings: list[Finding], fail_on: str) -> bool:
    if fail_on == "none":
        return False
    floor = SEVERITY_RANK[fail_on]
    return any(SEVERITY_RANK[f.severity] >= floor for f in findings)


def _emit(text: str, out: str | None) -> None:
    if out:
        with open(out, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(text)
        print(f"wrote {out}")
    else:
        sys.stdout.write(text)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "caps":
        sys.stdout.write(render.capability_table(args.format))
        return 0

    try:
        cluster = model.load_export(args.path)
    except model.LoadError as exc:
        sys.stderr.write(f"rbacpath: {exc}\n")
        return 3

    report = engine.audit(cluster)

    if args.command == "paths":
        findings = report.path_findings()
        if args.identity:
            findings = [f for f in findings if f.identity == args.identity]
            if not findings:
                sys.stdout.write(f"no path found for {args.identity}\n")
        if args.format == "json":
            payload = [
                {
                    "id": finding.id,
                    "severity": finding.severity,
                    "identity": finding.identity,
                    "message": finding.message,
                    "path": finding.evidence,
                }
                for finding in findings
            ]
            sys.stdout.write(json.dumps(payload, indent=2) + "\n")
        else:
            if not findings:
                sys.stdout.write("no escalation path found in this export\n")
            for finding in findings:
                sys.stdout.write(f"{finding.id}  {finding.message}\n    via {finding.evidence}\n")
        return 0

    _emit(render.render(args.format, report), args.out)
    return 2 if _threshold_breached(report.findings, args.fail_on) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
