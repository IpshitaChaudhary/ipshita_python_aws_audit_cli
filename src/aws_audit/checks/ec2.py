"""EC2 and EBS checks."""

from __future__ import annotations

from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check

# Instances in these states can still be started or are running.
_LIVE_STATES = ["pending", "running", "stopping", "stopped"]


def _name(tags: list[dict] | None) -> str:
    return next((t["Value"] for t in tags or [] if t["Key"] == "Name"), "")


def _label(resource_id: str, tags: list[dict] | None) -> str:
    name = _name(tags)
    return f"{resource_id} ({name})" if name else resource_id


@check(
    "ec2.ebs-default-encryption",
    "EBS encryption by default is enabled in the region",
    Severity.MEDIUM,
)
def ebs_default_encryption(session: boto3.Session, region: str) -> Iterator[Issue]:
    ec2 = session.client("ec2", region_name=region)
    if not ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]:
        yield Issue(
            f"ebs-defaults/{region}",
            "EBS encryption by default is off, so new volumes and snapshot copies "
            "can be created unencrypted",
        )


@check("ec2.ebs-unencrypted-volume", "EBS volumes are encrypted", Severity.HIGH)
def unencrypted_volumes(session: boto3.Session, region: str) -> Iterator[Issue]:
    ec2 = session.client("ec2", region_name=region)
    for page in ec2.get_paginator("describe_volumes").paginate():
        for vol in page["Volumes"]:
            if vol.get("Encrypted"):
                continue
            attachments = vol.get("Attachments") or []
            where = f"attached to {attachments[0]['InstanceId']}" if attachments else "not attached"
            yield Issue(
                _label(vol["VolumeId"], vol.get("Tags")),
                f"{vol['Size']} GiB {vol['VolumeType']} volume is not encrypted ({where})",
            )


@check("ec2.imdsv2-not-required", "Instances require IMDSv2 (session tokens)", Severity.HIGH)
def imdsv2_not_required(session: boto3.Session, region: str) -> Iterator[Issue]:
    ec2 = session.client("ec2", region_name=region)
    pages = ec2.get_paginator("describe_instances").paginate(
        Filters=[{"Name": "instance-state-name", "Values": _LIVE_STATES}]
    )
    for page in pages:
        for reservation in page["Reservations"]:
            for inst in reservation["Instances"]:
                opts = inst.get("MetadataOptions") or {}
                if opts.get("HttpEndpoint") == "disabled":
                    continue  # no metadata service at all, nothing to steal
                if opts.get("HttpTokens") != "required":
                    yield Issue(
                        _label(inst["InstanceId"], inst.get("Tags")),
                        "IMDSv1 is still allowed (HttpTokens is not 'required'); an SSRF bug "
                        "in the app could read the instance role's credentials",
                    )
