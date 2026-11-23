import io
import json
import zipfile

from conftest import REGION

from aws_audit.checks.lambda_ import deprecated_runtime, public_url


def _role(aws):
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = aws.client("iam").create_role(
        RoleName="fn-role", AssumeRolePolicyDocument=json.dumps(trust)
    )
    return role["Role"]["Arn"]


def _zip():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", "def handler(event, context):\n    return 'ok'\n")
    return buf.getvalue()


def _fn(aws, role, name, runtime):
    aws.client("lambda", region_name=REGION).create_function(
        FunctionName=name,
        Runtime=runtime,
        Role=role,
        Handler="index.handler",
        Code={"ZipFile": _zip()},
    )


def test_deprecated_runtime(aws):
    role = _role(aws)
    _fn(aws, role, "old-report", "python3.8")
    _fn(aws, role, "new-report", "python3.12")

    issues = list(deprecated_runtime(aws, REGION))

    assert [i.resource for i in issues] == ["old-report"]
    assert "python3.8" in issues[0].message


def test_public_url_flags_auth_none_only(aws):
    role = _role(aws)
    _fn(aws, role, "webhook", "python3.12")
    _fn(aws, role, "internal", "python3.12")
    client = aws.client("lambda", region_name=REGION)
    client.create_function_url_config(FunctionName="webhook", AuthType="NONE")
    client.create_function_url_config(FunctionName="internal", AuthType="AWS_IAM")

    issues = list(public_url(aws, REGION))

    assert [i.resource for i in issues] == ["webhook"]
    assert "AuthType NONE" in issues[0].message


def test_no_functions(aws):
    assert list(deprecated_runtime(aws, REGION)) == []
    assert list(public_url(aws, REGION)) == []
