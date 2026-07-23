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
MAX_DETECTOR_PATTERN_CHARS = 240
BACKREFERENCE_PATTERN = re.compile(
    r"\\[1-9][0-9]*|\\g<[^>]+>|\\k<[^>]+>|\(\?P=[^)]+\)"
)


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
    suppressed_issue_count: int = 0

    def __post_init__(self) -> None:
        if self.suppressed_issue_count < 0:
            raise ValueError("suppressed_issue_count must be non-negative")

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
            "suppressed_issue_count": self.suppressed_issue_count,
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
            _validate_safe_detector_pattern(detector, pattern)
            try:
                re.compile(pattern, re.I)
            except re.error as exc:
                raise ValueError(f"invalid regex for {detector}: {exc}") from exc
        normalized[detector] = normalized_patterns
    return dict(sorted(normalized.items()))


def _validate_safe_detector_pattern(detector: str, pattern: str) -> None:
    if len(pattern) > MAX_DETECTOR_PATTERN_CHARS:
        raise ValueError(
            f"regex for {detector} is too long; max {MAX_DETECTOR_PATTERN_CHARS} characters"
        )
    if BACKREFERENCE_PATTERN.search(pattern):
        raise ValueError(f"unsafe regex for {detector}: backreferences are not supported")
    if _has_nested_repeat(pattern):
        raise ValueError(
            f"unsafe regex for {detector}: nested repeated groups are not supported"
        )


def _has_nested_repeat(pattern: str) -> bool:
    group_repeat_stack: list[bool] = []
    in_character_class = False
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "\\":
            index += 2
            continue
        if in_character_class:
            if char == "]":
                in_character_class = False
            index += 1
            continue
        if char == "[":
            in_character_class = True
            index += 1
            continue
        if char == "(":
            group_repeat_stack.append(False)
            index = _after_group_prefix(pattern, index)
            continue
        if char == ")":
            if not group_repeat_stack:
                index += 1
                continue
            group_contains_repeat = group_repeat_stack.pop()
            group_is_repeated = _repeat_token_at(pattern, index + 1)
            if group_contains_repeat and group_is_repeated:
                return True
            if group_repeat_stack and (group_contains_repeat or group_is_repeated):
                group_repeat_stack[-1] = True
            index += 1
            continue
        if _repeat_token_at(pattern, index):
            if group_repeat_stack:
                group_repeat_stack[-1] = True
            if char == "{":
                index = pattern.find("}", index) + 1
                continue
        index += 1
    return False


def _after_group_prefix(pattern: str, start: int) -> int:
    prefix_start = start + 1
    if prefix_start >= len(pattern) or pattern[prefix_start] != "?":
        return start + 1
    if pattern.startswith("?P<", prefix_start):
        name_end = pattern.find(">", prefix_start + 3)
        return name_end + 1 if name_end != -1 else start + 1
    for prefix in ("?:", "?=", "?!", "?>", "?<=", "?<!"):
        if pattern.startswith(prefix, prefix_start):
            return prefix_start + len(prefix)
    flag_end = _inline_flag_prefix_end(pattern, prefix_start + 1)
    return flag_end if flag_end is not None else start + 1


def _inline_flag_prefix_end(pattern: str, start: int) -> int | None:
    index = start
    while index < len(pattern) and pattern[index] in "aiLmsux-":
        index += 1
    if index > start and index < len(pattern) and pattern[index] == ":":
        return index + 1
    return None


def _repeat_token_at(pattern: str, index: int) -> bool:
    if index >= len(pattern):
        return False
    char = pattern[index]
    if char in "*+?":
        return True
    return char == "{" and _is_braced_repeat(pattern, index)


def _is_braced_repeat(pattern: str, index: int) -> bool:
    end = pattern.find("}", index + 1)
    if end == -1:
        return False
    body = pattern[index + 1 : end]
    if not body:
        return False
    if "," in body:
        left, right = body.split(",", 1)
        return left.isdigit() and (right.isdigit() or right == "")
    return body.isdigit()


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
