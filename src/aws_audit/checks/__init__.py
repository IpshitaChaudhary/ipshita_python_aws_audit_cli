"""Built-in checks. Importing a module registers its checks."""

from aws_audit.checks import ec2, iam, logging, s3  # noqa: F401
