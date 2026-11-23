"""Check registry.

A check is a generator function decorated with @check. It receives a boto3
Session and a region and yields Issue objects:

    @check("ec2.example", "Short title", Severity.HIGH)
    def example(session, region):
        ec2 = session.client("ec2", region_name=region)
        ...
        yield Issue(resource_id, "what is wrong")

Global checks (scope="global", e.g. S3 or IAM) run once per scan instead of
once per region.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Literal

import boto3

from aws_audit.models import Issue, Severity

CheckFunc = Callable[[boto3.Session, str], Iterable[Issue]]
Scope = Literal["regional", "global"]

_REGISTRY: dict[str, Check] = {}


@dataclass(frozen=True)
class Check:
    id: str
    title: str
    severity: Severity
    scope: Scope
    func: CheckFunc


def check(
    check_id: str, title: str, severity: Severity, scope: Scope = "regional"
) -> Callable[[CheckFunc], CheckFunc]:
    def decorator(func: CheckFunc) -> CheckFunc:
        if check_id in _REGISTRY:
            raise ValueError(f"duplicate check id: {check_id}")
        _REGISTRY[check_id] = Check(check_id, title, severity, scope, func)
        return func

    return decorator


def _load_builtin_checks() -> None:
    importlib.import_module("aws_audit.checks")


def all_checks() -> list[Check]:
    _load_builtin_checks()
    return sorted(_REGISTRY.values(), key=lambda c: c.id)


def _matches(check_id: str, pattern: str) -> bool:
    return check_id == pattern or check_id.startswith(pattern + ".")


def select_checks(ids: Iterable[str] | None, skip: Iterable[str] | None = None) -> list[Check]:
    """Return the requested checks (all when ids is empty), minus the skipped ones.

    An id can be exact ("ec2.imdsv2-not-required") or a service prefix ("ec2").
    Unknown ids in either list are an error, so a typo never silently runs or
    skips the wrong thing.
    """
    checks = all_checks()
    wanted = [i.strip() for i in ids or [] if i.strip()]
    skipped = [i.strip() for i in skip or [] if i.strip()]
    unknown = [w for w in wanted + skipped if not any(_matches(c.id, w) for c in checks)]
    if unknown:
        raise ValueError(f"unknown check(s): {', '.join(unknown)}")
    if wanted:
        checks = [c for c in checks if any(_matches(c.id, w) for w in wanted)]
    return [c for c in checks if not any(_matches(c.id, s) for s in skipped)]
