"""Render scan results as a plain-text table, JSON, Markdown or SARIF."""

from __future__ import annotations

import hashlib
import json
import re

from aws_audit import __version__
from aws_audit.models import Severity
from aws_audit.registry import Check, all_checks
from aws_audit.runner import ScanResult


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max([len(h), *(len(r[i]) for r in rows)]) for i, h in enumerate(headers)]
    lines = ["  ".join(h.upper().ljust(w) for h, w in zip(headers, widths, strict=True)).rstrip()]
    lines.append("  ".join("-" * w for w in widths))
    lines += ["  ".join(c.ljust(w) for c, w in zip(r, widths, strict=True)).rstrip() for r in rows]
    return "\n".join(lines)


def render_checks(checks: list[Check]) -> str:
    rows = [[c.id, str(c.severity), c.scope, c.title] for c in checks]
    return _table(["check", "severity", "scope", "title"], rows)


def render_table(result: ScanResult) -> str:
    parts = []
    if result.findings:
        rows = [
            [str(f.severity), f.check_id, f.region, f.resource, f.message] for f in result.findings
        ]
        parts.append(_table(["severity", "check", "region", "resource", "message"], rows))
    else:
        parts.append("No findings.")
    if result.errors:
        parts.append("\nChecks that could not run:")
        parts += [f"  {e.check_id} [{e.region}]: {e.error}" for e in result.errors]
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "0"
    parts.append(f"\n{len(result.findings)} finding(s): {summary}; {len(result.errors)} error(s)")
    return "\n".join(parts)


def render_json(result: ScanResult) -> str:
    payload = {
        "findings": [f.to_dict() for f in result.findings],
        "errors": [
            {"check_id": e.check_id, "region": e.region, "error": e.error} for e in result.errors
        ],
    }
    return json.dumps(payload, indent=2)


def _md_cell(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ")


def render_markdown(result: ScanResult) -> str:
    """GitHub-flavoured Markdown, e.g. for $GITHUB_STEP_SUMMARY or a PR comment.

    Findings are sorted worst first so the top of the table is what matters.
    """
    findings = sorted(result.findings, key=lambda f: (-f.severity, f.check_id, f.resource))
    counts: dict[str, int] = {}
    for f in findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    summary = ", ".join(f"{n} {s}" for s, n in counts.items()) or "no findings"
    lines = ["## aws-audit results", "", f"**{len(findings)} finding(s):** {summary}", ""]
    if findings:
        lines += [
            "| Severity | Check | Region | Resource | Message |",
            "|---|---|---|---|---|",
        ]
        lines += [
            f"| {f.severity} | `{f.check_id}` | {f.region} | {_md_cell(f.resource)} "
            f"| {_md_cell(f.message)} |"
            for f in findings
        ]
    if result.errors:
        title = f"{len(result.errors)} check(s) could not run"
        lines += ["", f"<details><summary>{title}</summary>", ""]
        lines += [f"- `{e.check_id}` [{e.region}]: {_md_cell(e.error)}" for e in result.errors]
        lines += ["", "</details>"]
    return "\n".join(lines)


SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
# GitHub code scanning reads "security-severity" (0-10) to label alerts
# critical / high / medium / low, so map ours onto the middle of each band.
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
}
_SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _sarif_uri(text: str) -> str:
    """A stable, file-like path: code scanning wants a location even for cloud resources."""
    return "aws/" + re.sub(r"[^A-Za-z0-9._/-]+", "_", text).strip("_")


def render_sarif(result: ScanResult) -> str:
    """SARIF 2.1.0 for GitHub code scanning (github/codeql-action/upload-sarif).

    Each finding points at a pseudo path aws/<region>/<check>, and carries a
    fingerprint of check + region + resource, so the same problem on the same
    resource stays one alert across daily runs and closes when it is fixed.
    """
    known = {c.id: c for c in all_checks()}
    rule_ids = sorted({f.check_id for f in result.findings})
    rules = []
    for rule_id in rule_ids:
        c = known.get(rule_id)
        severity = c.severity if c else max(f.severity for f in result.findings)
        rules.append(
            {
                "id": rule_id,
                "name": rule_id.replace(".", "_").replace("-", "_"),
                "shortDescription": {"text": c.title if c else rule_id},
                "defaultConfiguration": {"level": _SARIF_LEVEL[severity]},
                "properties": {
                    "security-severity": _SECURITY_SEVERITY[severity],
                    "tags": ["security", "aws", rule_id.split(".")[0]],
                },
            }
        )
    results = []
    for f in result.findings:
        key = f"{f.check_id}|{f.region}|{f.resource}"
        results.append(
            {
                "ruleId": f.check_id,
                "ruleIndex": rule_ids.index(f.check_id),
                "level": _SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.resource}: {f.message}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": _sarif_uri(f"{f.region}/{f.check_id}")},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {"fullyQualifiedName": f.resource, "kind": "resource"}
                        ],
                    }
                ],
                "partialFingerprints": {
                    "awsAuditFinding/v1": hashlib.sha256(key.encode()).hexdigest()
                },
                "properties": {"security-severity": _SECURITY_SEVERITY[f.severity]},
            }
        )
    notifications = [
        {"level": "warning", "message": {"text": f"{e.check_id} [{e.region}]: {e.error}"}}
        for e in result.errors
    ]
    run = {
        "tool": {
            "driver": {
                "name": "aws-audit",
                "version": __version__,
                "informationUri": "https://github.com/IpshitaChaudhary/ipshita_python_aws_audit_cli",
                "rules": rules,
            }
        },
        "results": results,
        "invocations": [
            {
                "executionSuccessful": not result.errors,
                "toolExecutionNotifications": notifications,
            }
        ],
    }
    return json.dumps({"$schema": SARIF_SCHEMA, "version": "2.1.0", "runs": [run]}, indent=2)
