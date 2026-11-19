"""Audit logging checks: CloudTrail and AWS Config."""

from __future__ import annotations

from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check


@check(
    "cloudtrail.region-not-logged", "CloudTrail records API activity in the region", Severity.HIGH
)
def cloudtrail_region_logged(session: boto3.Session, region: str) -> Iterator[Issue]:
    """A region is covered by a logging trail in that region or by a logging multi-region trail."""
    ct = session.client("cloudtrail", region_name=region)
    trails = ct.describe_trails(includeShadowTrails=True)["trailList"]
    covering = [t for t in trails if t.get("IsMultiRegionTrail") or t.get("HomeRegion") == region]
    for trail in covering:
        home = session.client("cloudtrail", region_name=trail["HomeRegion"])
        if home.get_trail_status(Name=trail["TrailARN"]).get("IsLogging"):
            return
    if not covering:
        yield Issue(
            f"cloudtrail/{region}",
            "no CloudTrail trail covers this region; API activity is not recorded",
        )
    else:
        names = ", ".join(t["Name"] for t in covering)
        yield Issue(f"cloudtrail/{region}", f"trail(s) {names} exist but none is logging")


@check("config.recorder-off", "AWS Config records resource changes in the region", Severity.MEDIUM)
def config_recorder(session: boto3.Session, region: str) -> Iterator[Issue]:
    cfg = session.client("config", region_name=region)
    statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    if not statuses:
        yield Issue(f"config/{region}", "no AWS Config recorder; resource changes are not tracked")
        return
    for st in statuses:
        if not st.get("recording"):
            yield Issue(
                f"config/{st['name']}",
                f"AWS Config recorder '{st['name']}' exists but is not recording",
            )
