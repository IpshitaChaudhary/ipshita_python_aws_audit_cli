import json

import pytest
from conftest import REGION

from aws_audit.checks.s3 import BPA_SETTINGS, public_access
from aws_audit.models import Severity

ALL_ON = {k: True for k in BPA_SETTINGS}


@pytest.fixture
def s3(aws):
    return aws.client("s3", region_name=REGION)


def _bucket(s3, name, bpa=None, public_policy=False):
    s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": REGION})
    if bpa is not None:
        s3.put_public_access_block(Bucket=name, PublicAccessBlockConfiguration=bpa)
    if public_policy:
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{name}/*",
                }
            ],
        }
        s3.put_bucket_policy(Bucket=name, Policy=json.dumps(policy))


def _account_bpa(aws, cfg):
    account = aws.client("sts", region_name=REGION).get_caller_identity()["Account"]
    aws.client("s3control", region_name=REGION).put_public_access_block(
        AccountId=account, PublicAccessBlockConfiguration=cfg
    )


class _PolicyStatusSession:
    """moto returns an empty PolicyStatus, so report chosen buckets as public."""

    def __init__(self, session, public):
        self._session = session
        self._public = set(public)

    def client(self, service, region_name):
        client = self._session.client(service, region_name=region_name)
        if service == "s3":
            client.get_bucket_policy_status = lambda Bucket: {  # noqa: N803
                "PolicyStatus": {"IsPublic": Bucket in self._public}
            }
        return client


def _by_resource(issues):
    return {i.resource: i for i in issues}


def test_no_bpa_anywhere(aws, s3):
    _bucket(s3, "open-bucket")
    _bucket(s3, "locked-bucket", bpa=ALL_ON)
    _bucket(s3, "half-bucket", bpa={**ALL_ON, "RestrictPublicBuckets": False})

    issues = _by_resource(public_access(aws, REGION))

    assert set(issues) == {"account/s3-block-public-access", "open-bucket", "half-bucket"}
    assert issues["account/s3-block-public-access"].severity is Severity.MEDIUM
    assert "RestrictPublicBuckets" in issues["half-bucket"].message
    assert "BlockPublicAcls" not in issues["half-bucket"].message


def test_account_bpa_covers_every_bucket(aws, s3):
    _account_bpa(aws, ALL_ON)
    _bucket(s3, "open-bucket")

    assert list(public_access(aws, REGION)) == []


def test_partial_account_bpa_is_merged_with_bucket(aws, s3):
    _account_bpa(aws, {**ALL_ON, "BlockPublicAcls": False, "IgnorePublicAcls": False})
    _bucket(s3, "acl-blocked", bpa={"BlockPublicAcls": True, "IgnorePublicAcls": True})
    _bucket(s3, "default-bucket")

    issues = _by_resource(public_access(aws, REGION))

    assert set(issues) == {"account/s3-block-public-access", "default-bucket"}


def test_public_policy_is_critical_unless_restricted(aws, s3):
    _bucket(s3, "website", public_policy=True)
    _bucket(s3, "restricted", bpa={"RestrictPublicBuckets": True}, public_policy=True)
    session = _PolicyStatusSession(aws, public={"website", "restricted"})

    issues = _by_resource(public_access(session, REGION))

    assert issues["website"].severity is Severity.CRITICAL
    assert issues["restricted"].severity is None  # incomplete BPA only, not public
