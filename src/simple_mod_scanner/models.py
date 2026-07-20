from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

    @property
    def rank(self) -> int:
        return {
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }[self]


class Verdict(str, Enum):
    CLEAN = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS = "MALICIOUS"
    ERROR = "ERROR"


@dataclass(slots=True)
class Finding:
    severity: Severity
    rule_id: str
    path: str
    detail: str
    line: int | None = None
    snippet: str | None = None

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass(slots=True)
class ScanResult:
    zip_path: Path
    member_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None

    @property
    def verdict(self) -> Verdict:
        if self.error:
            return Verdict.ERROR
        if any(f.severity == Severity.CRITICAL for f in self.findings):
            return Verdict.MALICIOUS
        if any(f.severity in (Severity.HIGH, Severity.MEDIUM) for f in self.findings):
            return Verdict.SUSPICIOUS
        return Verdict.CLEAN

    def to_dict(self) -> dict[str, Any]:
        return {
            "zip_path": str(self.zip_path),
            "member_count": self.member_count,
            "verdict": self.verdict.value,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
        }
