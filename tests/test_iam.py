import datetime as dt

from conftest import REGION

from aws_audit.checks import iam as iam_checks


def _later(days):
    """Pretend the scan runs `days` days from now (keys are created 'now' in moto)."""
    return lambda: dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)


def _user_with_key(aws, name):
    iam = aws.client("iam", region_name=REGION)
    iam.create_user(UserName=name)
    return iam.create_access_key(UserName=name)["AccessKey"]["AccessKeyId"]


def test_root_mfa_reported_when_missing(aws):
    issues = list(iam_checks.root_mfa(aws, REGION))
    assert [i.resource for i in issues] == ["root"]


def test_old_access_key(aws, monkeypatch):
    key = _user_with_key(aws, "ci-deployer")
    assert list(iam_checks.old_access_keys(aws, REGION)) == []

    monkeypatch.setattr(iam_checks, "_now", _later(120))
    issues = list(iam_checks.old_access_keys(aws, REGION))
    assert [i.resource for i in issues] == [f"ci-deployer/{key[-4:]}"]
    assert "120 days old" in issues[0].message


def test_inactive_keys_are_ignored(aws, monkeypatch):
    key = _user_with_key(aws, "old-bot")
    aws.client("iam", region_name=REGION).update_access_key(
        UserName="old-bot", AccessKeyId=key, Status="Inactive"
    )
    monkeypatch.setattr(iam_checks, "_now", _later(400))
    assert list(iam_checks.old_access_keys(aws, REGION)) == []
    assert list(iam_checks.unused_access_keys(aws, REGION)) == []


def test_never_used_key(aws, monkeypatch):
    key = _user_with_key(aws, "report-bot")
    assert list(iam_checks.unused_access_keys(aws, REGION)) == []

    monkeypatch.setattr(iam_checks, "_now", _later(95))
    issues = list(iam_checks.unused_access_keys(aws, REGION))
    assert [i.resource for i in issues] == [f"report-bot/{key[-4:]}"]
    assert "never used" in issues[0].message
