from conftest import REGION

from aws_audit.checks.logs import no_retention


def test_no_retention(aws):
    logs = aws.client("logs", region_name=REGION)
    logs.create_log_group(logGroupName="/aws/lambda/old-report")
    logs.create_log_group(logGroupName="/ecs/api")
    logs.put_retention_policy(logGroupName="/ecs/api", retentionInDays=30)

    issues = list(no_retention(aws, REGION))

    assert [i.resource for i in issues] == ["/aws/lambda/old-report"]
    assert "never expire" in issues[0].message


def test_no_log_groups(aws):
    assert list(no_retention(aws, REGION)) == []
