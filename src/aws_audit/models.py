"""Data types shared by checks, the runner and the output layer."""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Severity(enum.IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.strip().upper()]
        except KeyError:
            names = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (expected one of: {names})") from None

    def __str__(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Issue:
    """What a check yields: one problem on one resource.

    The runner turns it into a Finding by adding the check id and region.
    `severity` overrides the check's default when one resource is worse
    than the usual case (for example a bucket that is actually public).
    """

    resource: str
    message: str
    severity: Severity | None = None


@dataclass(frozen=True)
class Finding:
    check_id: str
    severity: Severity
    region: str
    resource: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {
            "check_id": self.check_id,
            "severity": str(self.severity),
            "region": self.region,
            "resource": self.resource,
            "message": self.message,
        }


@dataclass(frozen=True)
class CheckError:
    """A check that could not run, e.g. AccessDenied. Reported, never hidden."""

    check_id: str
    region: str
    error: str
