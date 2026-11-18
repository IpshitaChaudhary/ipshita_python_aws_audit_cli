import boto3
import pytest
from moto import mock_aws

REGION = "eu-west-1"


@pytest.fixture(autouse=True)
def fake_credentials(monkeypatch):
    """Never let a test reach a real account, even with a profile configured."""
    for key in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/nonexistent")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/nonexistent")


@pytest.fixture
def aws():
    with mock_aws():
        yield boto3.Session(region_name=REGION)
