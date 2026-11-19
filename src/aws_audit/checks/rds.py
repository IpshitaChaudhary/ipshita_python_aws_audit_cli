"""RDS checks."""

from __future__ import annotations

from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check


def _instances(session: boto3.Session, region: str) -> Iterator[dict]:
    rds = session.client("rds", region_name=region)
    for page in rds.get_paginator("describe_db_instances").paginate():
        yield from page["DBInstances"]


@check("rds.publicly-accessible", "RDS databases are not publicly accessible", Severity.HIGH)
def publicly_accessible(session: boto3.Session, region: str) -> Iterator[Issue]:
    for db in _instances(session, region):
        if db.get("PubliclyAccessible"):
            yield Issue(
                db["DBInstanceIdentifier"],
                f"{db['Engine']} instance has a public endpoint; only security groups stand "
                "between it and the internet",
            )


@check("rds.storage-unencrypted", "RDS storage is encrypted", Severity.HIGH)
def storage_unencrypted(session: boto3.Session, region: str) -> Iterator[Issue]:
    for db in _instances(session, region):
        if not db.get("StorageEncrypted"):
            yield Issue(
                db["DBInstanceIdentifier"],
                f"{db['Engine']} storage and its snapshots are not encrypted "
                "(encryption can only be added by restoring an encrypted copy)",
            )
