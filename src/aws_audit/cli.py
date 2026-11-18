"""Command-line entry point: `aws-audit list-checks` and `aws-audit scan`."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from aws_audit import __version__
from aws_audit.models import Severity
from aws_audit.output import render_checks, render_json, render_table
from aws_audit.registry import all_checks, select_checks
from aws_audit.runner import enabled_regions, run_scan

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aws-audit", description="Audit an AWS account for common hardening gaps."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("list-checks", help="show every available check")

    scan = sub.add_parser("scan", help="run checks against an account")
    scan.add_argument("--profile", help="AWS named profile (default: normal boto3 lookup)")
    where = scan.add_mutually_exclusive_group()
    where.add_argument(
        "--region",
        action="append",
        dest="regions",
        metavar="REGION",
        help="region to scan; repeat for more (default: the profile's region)",
    )
    where.add_argument("--all-regions", action="store_true", help="scan every enabled region")
    scan.add_argument(
        "--check",
        action="append",
        dest="checks",
        metavar="ID",
        help="check id or service prefix (e.g. ec2); repeat for more (default: all)",
    )
    scan.add_argument("--format", choices=["table", "json"], default="table")
    scan.add_argument(
        "--fail-on",
        default="high",
        metavar="SEVERITY",
        help="exit 1 if any finding is at or above this severity, or 'none' (default: high)",
    )
    return parser


def _scan(args: argparse.Namespace) -> int:
    try:
        fail_on = None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
        checks = select_checks(args.checks)
    except ValueError as exc:
        print(f"aws-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        session = boto3.Session(profile_name=args.profile)
        if args.all_regions:
            regions = enabled_regions(session)
        else:
            regions = args.regions or ([session.region_name] if session.region_name else [])
        if not regions:
            print("aws-audit: no region set; pass --region or --all-regions", file=sys.stderr)
            return EXIT_USAGE
        result = run_scan(session, regions, checks)
    except (ClientError, BotoCoreError) as exc:
        print(f"aws-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE

    print(render_json(result) if args.format == "json" else render_table(result))
    if fail_on is not None and any(f.severity >= fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "list-checks":
        print(render_checks(all_checks()))
        return EXIT_OK
    return _scan(args)


if __name__ == "__main__":
    raise SystemExit(main())
