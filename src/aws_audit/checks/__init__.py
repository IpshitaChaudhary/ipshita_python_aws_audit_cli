"""Built-in checks. Importing a module registers its checks."""

from aws_audit.checks import ec2, iam, lambda_, logging, rds, s3  # noqa: F401
