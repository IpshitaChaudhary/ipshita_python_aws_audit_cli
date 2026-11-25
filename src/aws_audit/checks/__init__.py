"""Built-in checks. Importing a module registers its checks."""

from aws_audit.checks import ec2, elbv2, iam, kms, lambda_, logging, logs, rds, s3  # noqa: F401
