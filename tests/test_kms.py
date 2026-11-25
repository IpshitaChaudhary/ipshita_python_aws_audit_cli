from conftest import REGION

from aws_audit.checks.kms import rotation_disabled


def test_rotation_disabled(aws):
    kms = aws.client("kms", region_name=REGION)
    no_rotation = kms.create_key(Description="app data")["KeyMetadata"]
    rotated = kms.create_key(Description="rotated")["KeyMetadata"]
    kms.enable_key_rotation(KeyId=rotated["KeyId"])
    disabled = kms.create_key(Description="retired")["KeyMetadata"]
    kms.disable_key(KeyId=disabled["KeyId"])
    kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY")  # cannot rotate

    issues = list(rotation_disabled(aws, REGION))

    assert [i.resource for i in issues] == [no_rotation["Arn"]]
    assert "rotation is off" in issues[0].message


def test_no_keys(aws):
    assert list(rotation_disabled(aws, REGION)) == []
