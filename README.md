# ipshita_python_aws_audit_cli

[![ci](https://github.com/IpshitaChaudhary/ipshita_python_aws_audit_cli/actions/workflows/ci.yml/badge.svg)](https://github.com/IpshitaChaudhary/ipshita_python_aws_audit_cli/actions/workflows/ci.yml)

`aws-audit` is a small Python CLI that scans an AWS account for common hardening gaps
and prints them as a table or JSON. It only calls read-only APIs (`Describe*`, `List*`, `Get*`),
so it is safe to run against production.

## Checks

| Check | Default severity | Scope | Finds |
|---|---|---|---|
| `ec2.ebs-default-encryption` | medium | region | EBS encryption by default is off |
| `ec2.ebs-unencrypted-volume` | high | region | unencrypted EBS volumes (size, type, attached instance) |
| `ec2.imdsv2-not-required` | high | region | instances that still allow IMDSv1 |
| `s3.public-access` | high | global | Block Public Access gaps; **critical** when a bucket policy is public and not blocked |
| `ec2.unattached-eip` | low | region | Elastic IPs not attached to anything (billed while idle) |
| `ec2.unattached-volume` | low | region | EBS volumes in `available` state (billed while idle) |
| `cloudtrail.region-not-logged` | high | region | no trail, or no *logging* trail, covers the region |
| `config.recorder-off` | medium | region | AWS Config recorder missing or stopped |
| `iam.root-mfa` | critical | global | root user without MFA |
| `iam.access-key-old` | medium | global | active access keys older than 90 days |
| `iam.access-key-unused` | medium | global | active access keys unused for 90 days (or never used) |

Run `aws-audit list-checks` for the current list.

## Install

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
```

Requires Python 3.10+.

## Usage

```bash
# one region, using a named profile
aws-audit scan --profile audit --region eu-west-1

# several regions, or every enabled region
aws-audit scan --region eu-west-1 --region us-east-1
aws-audit scan --all-regions

# only some checks (exact id or service prefix)
aws-audit scan --region eu-west-1 --check ec2
aws-audit scan --region eu-west-1 --check s3.public-access

# JSON for other tools
aws-audit scan --region eu-west-1 --format json > findings.json
```

Example output (a test account with one old instance and one new bucket):

```text
SEVERITY  CHECK                       REGION     RESOURCE                        MESSAGE
--------  --------------------------  ---------  ------------------------------  ----------------------------------------------
high      ec2.ebs-unencrypted-volume  eu-west-1  vol-905b6845916b78815           8 GiB gp2 volume is not encrypted (attached to i-f28e562186df903dd)
high      ec2.imdsv2-not-required     eu-west-1  i-f28e562186df903dd (bastion)   IMDSv1 is still allowed (HttpTokens is not 'required'); ...
high      s3.public-access            global     static-site-assets              Block Public Access is incomplete (off: BlockPublicAcls, ...)
medium    ec2.ebs-default-encryption  eu-west-1  ebs-defaults/eu-west-1          EBS encryption by default is off, ...
medium    s3.public-access            global     account/s3-block-public-access  account-level Block Public Access is not fully on (off: ...)

5 finding(s): 3 high, 2 medium; 0 error(s)
```

A check that cannot run (for example `AccessDenied`) is listed under "Checks that could not run"
instead of stopping the scan.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | no finding at or above `--fail-on` (default `high`) |
| 1 | at least one finding at or above `--fail-on` |
| 2 | bad arguments, no region, or credentials/API failure before the scan |

Use `--fail-on critical` to only fail on the worst findings, or `--fail-on none` to always exit 0.

## Permissions

The AWS managed policy `SecurityAudit` covers every check. The exact calls are:
`ec2:DescribeRegions`, `ec2:DescribeVolumes`, `ec2:DescribeInstances`,
`ec2:GetEbsEncryptionByDefault`, `sts:GetCallerIdentity`, `s3:ListAllMyBuckets`,
`s3:GetAccountPublicAccessBlock`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus`,
`ec2:DescribeAddresses`, `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`,
`config:DescribeConfigurationRecorderStatus`, `iam:GetAccountSummary`, `iam:ListUsers`,
`iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`.

## Development

```bash
pytest                      # tests run against moto, never a real account
ruff check . && ruff format --check .
```

Adding a check: write a generator in `src/aws_audit/checks/<service>.py`, decorate it with
`@check("<service>.<name>", "<title>", Severity.X)`, yield `Issue(resource, message)` for each
problem, import the module in `checks/__init__.py`, and add a moto test.

## License

MIT
