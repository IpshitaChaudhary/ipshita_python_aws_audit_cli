"""Render scan results as a plain-text table or JSON."""

from __future__ import annotations

import json

from aws_audit.registry import Check
from aws_audit.runner import ScanResult


def _table(headers: list[str], rows: list[list[str]]) -> str:
    widths = [max([len(h), *(len(r[i]) for r in rows)]) for i, h in enumerate(headers)]
    lines = ["  ".join(h.upper().ljust(w) for h, w in zip(headers, widths, strict=True))]
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
