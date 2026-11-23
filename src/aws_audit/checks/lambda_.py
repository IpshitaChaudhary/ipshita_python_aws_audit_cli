"""Lambda checks."""

from __future__ import annotations

from collections.abc import Iterator

import boto3

from aws_audit.models import Issue, Severity
from aws_audit.registry import check

# Runtimes AWS has deprecated (no more security patches). Source: the Lambda
# "Runtime deprecation policy" table. Keep this list sorted; extend it when
# AWS announces new deprecations.
DEPRECATED_RUNTIMES = frozenset(
    {
        "dotnet6",
        "dotnetcore3.1",
        "go1.x",
        "java8",
        "nodejs12.x",
        "nodejs14.x",
        "nodejs16.x",
        "nodejs18.x",
        "provided",
        "python3.7",
        "python3.8",
        "ruby2.7",
        "ruby3.2",
    }
)


def _functions(session: boto3.Session, region: str) -> Iterator[dict]:
    client = session.client("lambda", region_name=region)
    for page in client.get_paginator("list_functions").paginate():
        yield from page["Functions"]


@check("lambda.deprecated-runtime", "Lambda functions use a supported runtime", Severity.MEDIUM)
def deprecated_runtime(session: boto3.Session, region: str) -> Iterator[Issue]:
    for fn in _functions(session, region):
        runtime = fn.get("Runtime")  # container-image functions have no Runtime
        if runtime in DEPRECATED_RUNTIMES:
            yield Issue(
                fn["FunctionName"],
                f"runtime {runtime} is deprecated and no longer gets security patches",
            )


@check("lambda.public-url", "Lambda function URLs require IAM auth", Severity.HIGH)
def public_url(session: boto3.Session, region: str) -> Iterator[Issue]:
    """Checks the function's own URL ($LATEST); URLs on aliases are not covered."""
    client = session.client("lambda", region_name=region)
    for fn in _functions(session, region):
        try:
            url = client.get_function_url_config(FunctionName=fn["FunctionName"])
        except client.exceptions.ResourceNotFoundException:
            continue  # no function URL
        if url.get("AuthType") == "NONE":
            yield Issue(
                fn["FunctionName"],
                f"function URL {url['FunctionUrl']} has AuthType NONE: anyone on the "
                "internet can invoke it",
            )
