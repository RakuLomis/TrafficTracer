"""Stable serializable models for Complete environment diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class DiagnosticSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"


@dataclass(frozen=True)
class DiagnosticCheck:
    code: str
    ok: bool
    severity: DiagnosticSeverity
    message: str
    remediation: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "code": self.code,
            "ok": self.ok,
            "severity": self.severity.value,
            "message": self.message,
            "remediation": self.remediation,
            "details": dict(self.details),
        }


@dataclass(frozen=True)
class DiagnosticReport:
    checks: tuple[DiagnosticCheck, ...]

    @property
    def ok(self) -> bool:
        return not any(
            not check.ok and check.severity is DiagnosticSeverity.ERROR
            for check in self.checks
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "checks": [check.to_dict() for check in self.checks],
        }
