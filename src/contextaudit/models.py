from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITIES)}
DETECTORS = (
    "instruction_override",
    "untrusted_instruction",
    "sensitive_data",
    "oversize_chunk",
    "duplicate_text",
    "missing_citation",
    "weak_sentence_support",
    "uncited_risky_context",
)
PATTERN_DETECTORS = ("instruction_override", "untrusted_instruction", "sensitive_data")


def normalize_severity(value: str) -> str:
    severity = value.lower()
    if severity not in SEVERITY_RANK:
        allowed = ", ".join(SEVERITIES)
        raise ValueError(f"severity must be one of: {allowed}")
    return severity


def severity_meets(severity: str, threshold: str) -> bool:
    return SEVERITY_RANK[normalize_severity(severity)] >= SEVERITY_RANK[
        normalize_severity(threshold)
    ]


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
    disabled_detectors: tuple[str, ...] = ()
    severity_overrides: dict[str, str] = field(default_factory=dict)
    allowlisted_sources: tuple[str, ...] = ()
    detector_patterns: dict[str, tuple[str, ...]] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "fail_on", normalize_severity(self.fail_on))
        if self.max_chunk_chars < 1:
            raise ValueError("max_chunk_chars must be positive")
        object.__setattr__(
            self,
            "disabled_detectors",
            _normalize_detector_tuple(self.disabled_detectors, allowed=DETECTORS),
        )
        object.__setattr__(
            self,
            "severity_overrides",
            _normalize_severity_overrides(self.severity_overrides),
        )
        object.__setattr__(
            self,
            "allowlisted_sources",
            _normalize_string_tuple(self.allowlisted_sources, "allowlisted source"),
        )
        object.__setattr__(
            self,
            "detector_patterns",
            _normalize_detector_patterns(self.detector_patterns),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "fail_on": self.fail_on,
            "max_chunk_chars": self.max_chunk_chars,
            "disabled_detectors": list(self.disabled_detectors),
            "severity_overrides": self.severity_overrides,
            "allowlisted_sources": list(self.allowlisted_sources),
            "detector_patterns": {
                detector: list(patterns) for detector, patterns in self.detector_patterns.items()
            },
        }


@dataclass(frozen=True)
class Issue:
    chunk_id: str
    source: str
    detector: str
    severity: str
    message: str
    evidence: str
    fingerprint: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "severity", normalize_severity(self.severity))
        _validate_detector(self.detector, allowed=DETECTORS)
        if not self.fingerprint:
            object.__setattr__(self, "fingerprint", _issue_fingerprint(self))

    def to_dict(self) -> dict[str, Any]:
        return {
            "chunk_id": self.chunk_id,
            "source": self.source,
            "detector": self.detector,
            "severity": self.severity,
            "message": self.message,
            "evidence": self.evidence,
            "fingerprint": self.fingerprint,
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
        return (
            1
            if any(severity_meets(issue.severity, self.policy.fail_on) for issue in self.issues)
            else 0
        )

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


def _normalize_detector_tuple(
    values: Sequence[str],
    *,
    allowed: tuple[str, ...],
) -> tuple[str, ...]:
    normalized = _normalize_string_tuple(values, "detector")
    for value in normalized:
        _validate_detector(value, allowed=allowed)
    return tuple(dict.fromkeys(normalized))


def _normalize_severity_overrides(values: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(values, dict):
        raise ValueError("severity_overrides must be an object")
    normalized: dict[str, str] = {}
    for detector, severity in values.items():
        _validate_detector(detector, allowed=DETECTORS)
        if not isinstance(severity, str):
            raise ValueError("severity override must be a string")
        normalized[detector] = normalize_severity(severity)
    return dict(sorted(normalized.items()))


def _normalize_detector_patterns(values: Mapping[str, Sequence[str]]) -> dict[str, tuple[str, ...]]:
    if not isinstance(values, dict):
        raise ValueError("detector_patterns must be an object")
    normalized: dict[str, tuple[str, ...]] = {}
    for detector, patterns in values.items():
        _validate_detector(detector, allowed=PATTERN_DETECTORS)
        normalized_patterns = _normalize_string_tuple(patterns, "detector pattern")
        for pattern in normalized_patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"invalid regex for {detector}: {exc}") from exc
        normalized[detector] = normalized_patterns
    return dict(sorted(normalized.items()))


def _normalize_string_tuple(values: Sequence[str], label: str) -> tuple[str, ...]:
    if isinstance(values, str) or not isinstance(values, Sequence):
        raise ValueError(f"{label}s must be an array")
    normalized: list[str] = []
    for value in values:
        if not isinstance(value, str) or not value:
            raise ValueError(f"{label} must be a non-empty string")
        normalized.append(value)
    return tuple(normalized)


def _validate_detector(detector: str, *, allowed: tuple[str, ...]) -> None:
    if detector not in allowed:
        allowed_text = ", ".join(allowed)
        raise ValueError(f"unknown detector {detector!r}; expected one of: {allowed_text}")


def _issue_fingerprint(issue: Issue) -> str:
    payload = {
        "chunk_id": issue.chunk_id,
        "detector": issue.detector,
        "evidence": issue.evidence,
        "source": issue.source,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()[:16]
