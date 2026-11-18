from conftest import REGION

from aws_audit.checks.ec2 import ebs_default_encryption, imdsv2_not_required, unencrypted_volumes
from aws_audit.cli import main

AMI = "ami-12c6146b"  # one of moto's built-in images


def _instance(ec2, name):
    inst = ec2.run_instances(
        ImageId=AMI,
        MinCount=1,
        MaxCount=1,
        TagSpecifications=[{"ResourceType": "instance", "Tags": [{"Key": "Name", "Value": name}]}],
    )["Instances"][0]
    return inst["InstanceId"]


class _StubSession:
    """moto does not model MetadataOptions, so feed describe_instances pages directly."""

    def __init__(self, instances):
        self.instances = instances
        self.filters = None

    def client(self, service, region_name):
        return self

    def get_paginator(self, operation):
        return self

    def paginate(self, Filters):  # noqa: N803 - boto3 parameter name
        self.filters = Filters
        return [{"Reservations": [{"Instances": self.instances}]}]


def _meta(instance_id, name, tokens, endpoint="enabled"):
    return {
        "InstanceId": instance_id,
        "Tags": [{"Key": "Name", "Value": name}],
        "MetadataOptions": {"HttpTokens": tokens, "HttpEndpoint": endpoint},
    }


def test_ebs_default_encryption(aws):
    ec2 = aws.client("ec2", region_name=REGION)
    assert [i.resource for i in ebs_default_encryption(aws, REGION)] == [f"ebs-defaults/{REGION}"]
    ec2.enable_ebs_encryption_by_default()
    assert list(ebs_default_encryption(aws, REGION)) == []


def test_unencrypted_volumes(aws):
    ec2 = aws.client("ec2", region_name=REGION)
    plain = ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, VolumeType="gp3")
    ec2.create_volume(AvailabilityZone=f"{REGION}a", Size=8, VolumeType="gp3", Encrypted=True)

    issues = list(unencrypted_volumes(aws, REGION))

    assert [i.resource for i in issues] == [plain["VolumeId"]]
    assert "8 GiB gp3" in issues[0].message and "not attached" in issues[0].message


def test_imdsv2():
    session = _StubSession(
        [
            _meta("i-legacy", "legacy", "optional"),
            _meta("i-hardened", "hardened", "required"),
            _meta("i-noimds", "no-imds", "optional", endpoint="disabled"),
        ]
    )

    issues = list(imdsv2_not_required(session, REGION))

    assert [i.resource for i in issues] == ["i-legacy (legacy)"]
    states = session.filters[0]["Values"]
    assert "terminated" not in states and "running" in states and "stopped" in states


def test_scan_ec2_end_to_end(aws, capsys):
    ec2 = aws.client("ec2", region_name=REGION)
    _instance(ec2, "legacy")  # launched without MetadataOptions -> IMDSv1 allowed

    code = main(["scan", "--region", REGION, "--check", "ec2", "--format", "json"])

    out = capsys.readouterr().out
    assert code == 1  # high-severity IMDS finding fails the default --fail-on high
    assert '"ec2.imdsv2-not-required"' in out
    assert main(["scan", "--region", REGION, "--check", "ec2", "--fail-on", "critical"]) == 0
