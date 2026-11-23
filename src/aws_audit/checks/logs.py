"""CloudWatch Logs checks."""

from __future__ import annotations

from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check

GIB = 1024**3


@check("logs.no-retention", "CloudWatch log groups have a retention period", Severity.LOW)
def no_retention(session: boto3.Session, region: str) -> Iterator[Issue]:
    """Log groups default to 'Never expire', so storage cost only ever grows."""
    logs = session.client("logs", region_name=region)
    for page in logs.get_paginator("describe_log_groups").paginate():
        for group in page["logGroups"]:
            if "retentionInDays" in group:
                continue
            size = group.get("storedBytes", 0) / GIB
            yield Issue(
                group["logGroupName"],
                f"logs never expire ({size:.1f} GiB stored so far); set a retention period",
            )
