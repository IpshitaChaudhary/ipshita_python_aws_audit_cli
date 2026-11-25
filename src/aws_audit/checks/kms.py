"""KMS checks."""

from __future__ import annotations

from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check


@check("kms.rotation-disabled", "Customer-managed KMS keys rotate automatically", Severity.MEDIUM)
def rotation_disabled(session: boto3.Session, region: str) -> Iterator[Issue]:
    """Only keys that can rotate are checked: enabled, customer-managed,
    symmetric and created by KMS (imported and custom-store keys cannot)."""
    kms = session.client("kms", region_name=region)
    for page in kms.get_paginator("list_keys").paginate():
        for key in page["Keys"]:
            meta = kms.describe_key(KeyId=key["KeyId"])["KeyMetadata"]
            if (
                meta["KeyManager"] != "CUSTOMER"
                or meta["KeyState"] != "Enabled"
                or meta.get("KeySpec", "SYMMETRIC_DEFAULT") != "SYMMETRIC_DEFAULT"
                or meta.get("Origin", "AWS_KMS") != "AWS_KMS"
            ):
                continue
            if not kms.get_key_rotation_status(KeyId=key["KeyId"])["KeyRotationEnabled"]:
                yield Issue(
                    meta["Arn"],
                    "automatic key rotation is off; enable it (yearly, no app change needed)",
                )
