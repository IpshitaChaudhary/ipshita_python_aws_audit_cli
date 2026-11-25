# Changelog

## Unreleased

### Added
- `--format sarif` (SARIF 2.1.0) for GitHub code scanning, with stable per-resource fingerprints.
- `examples/github-actions-code-scanning.yml`: weekly scan uploaded with `upload-sarif`.
- `ec2.snapshot-public` (critical): EBS snapshots shared with all AWS accounts.
- `kms.rotation-disabled`: customer-managed symmetric keys without automatic rotation.

## 0.3.0 - 2026-11-23

### Added
- `ec2.sg-admin-port-open`: admin and database ports open to the internet.
- `rds.publicly-accessible`, `rds.storage-unencrypted`.
- `lambda.deprecated-runtime`, `lambda.public-url` (function and alias URLs).
- `--format markdown`: worst-first table for job summaries and PR comments.
- `examples/github-actions-scheduled-scan.yml`: daily scan over OIDC with a read-only role.
- `elbv2.http-not-redirected` (default action only) and `logs.no-retention`.
- `--skip-check ID` to leave checks out (exact id or service prefix).
- `--min-severity` to hide lower findings from the report; `--fail-on` still sees all of them.
- Dependabot (weekly, grouped) for pip and GitHub Actions.

## 0.2.0

### Added
- Logging: `cloudtrail.region-not-logged`, `config.recorder-off`.
- Unused resources: `ec2.unattached-eip`, `ec2.unattached-volume`.
- IAM: `iam.root-mfa`, `iam.access-key-old`, `iam.access-key-unused`.

## 0.1.0

### Added
- Scanner core: check registry (regional and global scope, service-prefix selection), runner that records API errors per check, table and JSON output, `--fail-on` exit codes.
- EC2: `ec2.ebs-default-encryption`, `ec2.ebs-unencrypted-volume`, `ec2.imdsv2-not-required`.
- S3: `s3.public-access`.
- CI: ruff, pytest on Python 3.10 to 3.13, CLI smoke test.
