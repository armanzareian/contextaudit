from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}


def normalize_severity(value: str) -> str:
    severity = value.lower()
    if severity not in SEVERITY_RANK:
        allowed = ", ".join(SEVERITIES)
        raise ValueError(f"severity must be one of: {allowed}")
    return severity


def severity_meets(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK[normalize_severity(severity)] >= SEVERITY_RANK[normalize_severity(threshold)]


@dataclass(frozen=True)
class ContextChunk:
    chunk_id: str
    source: str
    text: str
    trusted: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.chunk_id:
            raise ValueError("chunk_id is required")
        if not self.source:
            raise ValueError("source is required")
        if not self.text:
            raise ValueError("text is required")


@dataclass(frozen=True)
class Policy:
    fail_on: str = "high"
    max_chunk_chars: int = 4000

    def __post_init__(self) -> None:
        object.__setattr__(self, "fail_on", normalize_severity(self.fail_on))
        if self.max_chunk_chars < 1:
            raise ValueError("max_chunk_chars must be positive")

    def to_dict(self) -> dict[str, Any]:
        return {"fail_on": self.fail_on, "max_chunk_chars": self.max_chunk_chars}


@dataclass(frozen=True)
class Issue:
    chunk_id: str
    source: str
    detector: str
    severity: str
    message: str
    evidence: str

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", normalize_severity(self.severity))

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "source": self.source,
            "detector": self.detector,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
        }


@dataclass(frozen=True)
class ScanReport:
    score: int
    issues: list[Issue]
    summary: dict[str, int]
    policy: Policy

    @property
    def max_severity(self) -> str:
        if not self.issues:
            return "none"
        return max(self.issues, key=lambda issue: SEVERITY_RANK[issue.severity]).severity

    @property
    def exit_code(self) -> int:
        return 1 if any(severity_meets(issue.severity, self.policy.fail_on) for issue in self.issues) else 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "issue_count": len(self.issues),
            "max_severity": self.max_severity,
            "summary": self.summary,
            "policy": self.policy.to_dict(),
            "exit_code": self.exit_code,
            "issues": [issue.to_dict() for issue in self.issues],
        }
