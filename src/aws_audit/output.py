"""Render scan results as a plain-text table, JSON or Markdown."""

from __future__ import annotations

import json

from aws_audit.registry import Check
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
