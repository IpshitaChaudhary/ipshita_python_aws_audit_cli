"""S3 public access checks.

Block Public Access (BPA) can be set for the whole account and per bucket.
AWS applies the stricter of the two, so a setting counts as on when either
level has it on. When the account level has all four settings on, every
bucket is covered and nothing is reported. Otherwise each bucket is checked
for an effective public policy (critical) or incomplete BPA settings.
"""

from __future__ import annotations

from collections.abc import Iterator

import boto3
from botocore.exceptions import ClientError

from aws_audit.models import Issue, Severity
from aws_audit.registry import check

BPA_SETTINGS = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")
_NO_BPA = "NoSuchPublicAccessBlockConfiguration"


def _error_code(exc: ClientError) -> str:
    return exc.response.get("Error", {}).get("Code", "")


def account_bpa(session: boto3.Session, region: str) -> dict[str, bool]:
    account_id = session.client("sts", region_name=region).get_caller_identity()["Account"]
    s3control = session.client("s3control", region_name=region)
    try:
        cfg = s3control.get_public_access_block(AccountId=account_id)
    except ClientError as exc:
        if _error_code(exc) == _NO_BPA:
            return {}
        raise
    return cfg["PublicAccessBlockConfiguration"]


def _bucket_bpa(s3, bucket: str) -> dict[str, bool]:
    try:
        return s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
    except ClientError as exc:
        if _error_code(exc) == _NO_BPA:
            return {}
        raise


def _policy_is_public(s3, bucket: str) -> bool:
    try:
        status = s3.get_bucket_policy_status(Bucket=bucket)
    except ClientError as exc:
        if _error_code(exc) == "NoSuchBucketPolicy":
            return False
        raise
    return bool(status.get("PolicyStatus", {}).get("IsPublic"))


@check(
    "s3.public-access",
    "S3 buckets block public access (account or bucket level)",
    Severity.HIGH,
    scope="global",
)
def public_access(session: boto3.Session, region: str) -> Iterator[Issue]:
    account = account_bpa(session, region)
    account_full = all(account.get(k) for k in BPA_SETTINGS)
    if not account_full:
        off = [k for k in BPA_SETTINGS if not account.get(k)]
        yield Issue(
            "account/s3-block-public-access",
            f"account-level Block Public Access is not fully on (off: {', '.join(off)})",
            Severity.MEDIUM,
        )

    s3 = session.client("s3", region_name=region)
    for bucket in s3.list_buckets().get("Buckets", []):
        name = bucket["Name"]
        effective = dict(account)
        for key, value in _bucket_bpa(s3, name).items():
            effective[key] = effective.get(key) or value

        if not effective.get("RestrictPublicBuckets") and _policy_is_public(s3, name):
            yield Issue(
                name,
                "bucket policy grants public access and nothing blocks it",
                Severity.CRITICAL,
            )
        elif not account_full:
            off = [k for k in BPA_SETTINGS if not effective.get(k)]
            if off:
                yield Issue(name, f"Block Public Access is incomplete (off: {', '.join(off)})")
