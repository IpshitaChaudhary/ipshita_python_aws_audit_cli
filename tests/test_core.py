import json

import pytest
from botocore.exceptions import ClientError

from aws_audit import registry
from aws_audit.cli import main
from aws_audit.models import Issue, Severity
from aws_audit.output import render_json, render_markdown, render_table
from aws_audit.registry import Check
from aws_audit.runner import run_scan


def _fake(check_id, severity=Severity.MEDIUM, scope="regional", issues=(), error=None):
    def func(session, region):
        if error:
            raise error
        yield from (Issue(f"{r}-{region}", m) for r, m in issues)

    return Check(check_id, "fake", severity, scope, func)


def test_severity_parse_and_order():
    assert Severity.parse("High") is Severity.HIGH
    assert Severity.CRITICAL > Severity.LOW
    with pytest.raises(ValueError, match="unknown severity"):
        Severity.parse("urgent")


def test_duplicate_check_id_rejected(monkeypatch):
    monkeypatch.setattr(registry, "_REGISTRY", {})
    registry.check("x.one", "t", Severity.LOW)(lambda s, r: [])
    with pytest.raises(ValueError, match="duplicate"):
        registry.check("x.one", "t", Severity.LOW)(lambda s, r: [])


def test_select_checks_by_prefix_and_unknown(monkeypatch):
    fakes = {c.id: c for c in (_fake("ec2.a"), _fake("ec2.b"), _fake("s3.a"))}
    monkeypatch.setattr(registry, "_REGISTRY", fakes)
    monkeypatch.setattr(registry, "_load_builtin_checks", lambda: None)
    assert [c.id for c in registry.select_checks(["ec2"])] == ["ec2.a", "ec2.b"]
    assert [c.id for c in registry.select_checks(["s3.a"])] == ["s3.a"]
    assert len(registry.select_checks(None)) == 3
    with pytest.raises(ValueError, match="unknown check"):
        registry.select_checks(["rds"])


def test_runner_regional_global_and_errors():
    denied = ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Describe")
    checks = [
        _fake("r.one", issues=[("vol", "bad")]),
        _fake("g.one", Severity.HIGH, scope="global", issues=[("bucket", "open")]),
        _fake("r.denied", error=denied),
    ]
    result = run_scan(None, ["eu-west-1", "us-east-1"], checks)

    assert [(f.check_id, f.region) for f in result.findings] == [
        ("g.one", "global"),  # highest severity first
        ("r.one", "eu-west-1"),
        ("r.one", "us-east-1"),
    ]
    # the global check is called once, with the first region for its endpoint
    assert result.findings[0].resource == "bucket-eu-west-1"
    assert [(e.check_id, e.region) for e in result.errors] == [
        ("r.denied", "eu-west-1"),
        ("r.denied", "us-east-1"),
    ]


def test_render_table_and_json():
    result = run_scan(None, ["eu-west-1"], [_fake("r.one", issues=[("vol", "bad")])])
    table = render_table(result)
    assert "r.one" in table and "1 finding(s): 1 medium" in table
    assert json.loads(render_json(result))["findings"][0]["severity"] == "medium"


def test_render_markdown_sorts_worst_first_and_escapes_pipes():
    checks = [
        _fake("r.low", issues=[("vol", "minor")]),
        _fake("r.bad", Severity.CRITICAL, issues=[("bucket|x", "very bad")]),
    ]
    md = render_markdown(run_scan(None, ["eu-west-1"], checks))
    rows = [line for line in md.splitlines() if line.startswith("| ") and "`" in line]
    assert rows[0].startswith("| critical | `r.bad`")
    assert r"bucket\|x" in rows[0]
    assert "**2 finding(s):** 1 critical, 1 medium" in md


def test_render_markdown_empty():
    md = render_markdown(run_scan(None, ["eu-west-1"], []))
    assert "no findings" in md and "| Severity" not in md


def test_cli_list_checks_and_bad_input(capsys):
    assert main(["list-checks"]) == 0
    assert "CHECK" in capsys.readouterr().out
    assert main(["scan", "--region", "eu-west-1", "--fail-on", "urgent"]) == 2
    assert main(["scan", "--region", "eu-west-1", "--check", "nope"]) == 2
