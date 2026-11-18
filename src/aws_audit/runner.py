"""Runs selected checks across regions and collects findings and errors."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aws_audit.models import CheckError, Finding
from aws_audit.registry import Check

GLOBAL = "global"


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[CheckError] = field(default_factory=list)


def enabled_regions(session: boto3.Session) -> list[str]:
    """Regions this account can use (opted-out regions are skipped)."""
    ec2 = session.client("ec2", region_name=session.region_name or "us-east-1")
    regions = ec2.describe_regions(AllRegions=False)["Regions"]
    return sorted(r["RegionName"] for r in regions)


def run_scan(session: boto3.Session, regions: Iterable[str], checks: Iterable[Check]) -> ScanResult:
    regions = list(regions)
    if not regions:
        raise ValueError("at least one region is required")
    result = ScanResult()
    for chk in checks:
        targets = [GLOBAL] if chk.scope == "global" else regions
        for target in targets:
            # Global services still need a region for the API endpoint.
            api_region = regions[0] if target == GLOBAL else target
            try:
                for issue in chk.func(session, api_region):
                    result.findings.append(
                        Finding(
                            check_id=chk.id,
                            severity=issue.severity or chk.severity,
                            region=target,
                            resource=issue.resource,
                            message=issue.message,
                        )
                    )
            except (ClientError, BotoCoreError) as exc:
                result.errors.append(CheckError(chk.id, target, str(exc)))
    result.findings.sort(key=lambda f: (-f.severity, f.check_id, f.region, f.resource))
    return result
