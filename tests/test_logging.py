from conftest import REGION

from aws_audit.checks.logging import cloudtrail_region_logged, config_recorder

BUCKET = "audit-trail-logs"


def _bucket(aws):
    aws.client("s3", region_name=REGION).create_bucket(
        Bucket=BUCKET, CreateBucketConfiguration={"LocationConstraint": REGION}
    )


def test_no_trail(aws):
    issues = list(cloudtrail_region_logged(aws, REGION))
    assert [i.resource for i in issues] == [f"cloudtrail/{REGION}"]
    assert "no CloudTrail trail" in issues[0].message


def test_trail_not_logging_then_logging(aws):
    _bucket(aws)
    ct = aws.client("cloudtrail", region_name=REGION)
    ct.create_trail(Name="org-trail", S3BucketName=BUCKET, IsMultiRegionTrail=True)

    issues = list(cloudtrail_region_logged(aws, REGION))
    assert "none is logging" in issues[0].message

    ct.start_logging(Name="org-trail")
    assert list(cloudtrail_region_logged(aws, REGION)) == []
    # the multi-region trail also covers another region
    assert list(cloudtrail_region_logged(aws, "us-east-1")) == []


def test_config_recorder(aws):
    cfg = aws.client("config", region_name=REGION)
    assert "no AWS Config recorder" in next(config_recorder(aws, REGION)).message

    cfg.put_configuration_recorder(
        ConfigurationRecorder={
            "name": "default",
            "roleARN": "arn:aws:iam::123456789012:role/config",
        }
    )
    assert "not recording" in next(config_recorder(aws, REGION)).message

    _bucket(aws)
    cfg.put_delivery_channel(DeliveryChannel={"name": "default", "s3BucketName": BUCKET})
    cfg.start_configuration_recorder(ConfigurationRecorderName="default")
    assert list(config_recorder(aws, REGION)) == []
