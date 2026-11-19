from conftest import REGION

from aws_audit.checks.rds import publicly_accessible, storage_unencrypted


def _db(aws, name, public, encrypted):
    aws.client("rds", region_name=REGION).create_db_instance(
        DBInstanceIdentifier=name,
        DBInstanceClass="db.t4g.micro",
        Engine="postgres",
        AllocatedStorage=20,
        MasterUsername="admin_user",
        MasterUserPassword="not-a-real-password-1",
        PubliclyAccessible=public,
        StorageEncrypted=encrypted,
    )


def test_public_and_unencrypted(aws):
    _db(aws, "reports-db", public=True, encrypted=False)
    _db(aws, "orders-db", public=False, encrypted=True)

    public = list(publicly_accessible(aws, REGION))
    plain = list(storage_unencrypted(aws, REGION))

    assert [i.resource for i in public] == ["reports-db"]
    assert [i.resource for i in plain] == ["reports-db"]
    assert "postgres" in public[0].message


def test_no_databases(aws):
    assert list(publicly_accessible(aws, REGION)) == []
    assert list(storage_unencrypted(aws, REGION)) == []
