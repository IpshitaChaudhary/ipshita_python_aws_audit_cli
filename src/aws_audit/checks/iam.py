"""IAM checks (account-wide, run once per scan)."""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check

KEY_MAX_AGE_DAYS = 90
KEY_UNUSED_DAYS = 90


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


@check("iam.root-mfa", "The root user has MFA enabled", Severity.CRITICAL, scope="global")
def root_mfa(session: boto3.Session, region: str) -> Iterator[Issue]:
    summary = session.client("iam", region_name=region).get_account_summary()["SummaryMap"]
    if not summary.get("AccountMFAEnabled"):
        yield Issue("root", "the root user has no MFA; anyone with the password owns the account")


def _active_keys(iam) -> Iterator[tuple[str, dict]]:
    for page in iam.get_paginator("list_users").paginate():
        for user in page["Users"]:
            keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
            for key in keys:
                if key["Status"] == "Active":
                    yield user["UserName"], key


@check(
    "iam.access-key-old",
    f"Active access keys are rotated within {KEY_MAX_AGE_DAYS} days",
    Severity.MEDIUM,
    scope="global",
)
def old_access_keys(session: boto3.Session, region: str) -> Iterator[Issue]:
    iam = session.client("iam", region_name=region)
    for user, key in _active_keys(iam):
        age = (_now() - key["CreateDate"]).days
        if age > KEY_MAX_AGE_DAYS:
            yield Issue(
                f"{user}/{key['AccessKeyId'][-4:]}",
                f"active access key is {age} days old (limit {KEY_MAX_AGE_DAYS}); rotate it",
            )


@check(
    "iam.access-key-unused",
    f"Active access keys were used in the last {KEY_UNUSED_DAYS} days",
    Severity.MEDIUM,
    scope="global",
)
def unused_access_keys(session: boto3.Session, region: str) -> Iterator[Issue]:
    iam = session.client("iam", region_name=region)
    for user, key in _active_keys(iam):
        last = iam.get_access_key_last_used(AccessKeyId=key["AccessKeyId"])["AccessKeyLastUsed"]
        used = last.get("LastUsedDate")
        if used is None:
            age = (_now() - key["CreateDate"]).days
            if age > KEY_UNUSED_DAYS:
                yield Issue(
                    f"{user}/{key['AccessKeyId'][-4:]}",
                    f"active access key never used in {age} days; deactivate or delete it",
                )
        elif (idle := (_now() - used).days) > KEY_UNUSED_DAYS:
            yield Issue(
                f"{user}/{key['AccessKeyId'][-4:]}",
                f"active access key last used {idle} days ago; deactivate or delete it",
            )
