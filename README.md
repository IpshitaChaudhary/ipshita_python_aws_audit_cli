# ipshita_python_aws_audit_cli

`aws-audit` is a small Python CLI that scans an AWS account for common hardening gaps
and reports them as a table or JSON. Every check is read-only (`Describe*`, `List*`, `Get*`).

> Work in progress: the core scanner is in place and checks are being added.

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
aws-audit list-checks
aws-audit scan --profile my-profile --region eu-west-1
```
