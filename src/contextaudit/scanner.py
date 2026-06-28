from __future__ import annotations

import re
from collections import Counter

from contextaudit.models import ContextChunk, Issue, Policy, SEVERITY_RANK, ScanReport

INSTRUCTION_OVERRIDE_PATTERNS = [
    re.compile(r"\bignore\s+(?:all\s+)?(?:previous|prior|system|developer)\s+instructions?\b", re.I),
    re.compile(r"\b(?:reveal|disclose|print|show)\s+(?:hidden|private|system|developer)\b", re.I),
    re.compile(r"\b(?:system|developer)\s+(?:message|instructions?)\b", re.I),
]
SENSITIVE_PATTERNS = [
    re.compile(r"\b(?:password|passcode|api[_ -]?key|secret|token)\b\s*[:=]\s*\S+", re.I),
]
UNTRUSTED_AUTHORITY_PATTERN = re.compile(
    r"\b(?:ignore|reveal|disclose|must|should|system|developer|instruction|tool)\b",
    re.I,
)
PENALTY_BY_SEVERITY = {"low": 5, "medium": 15, "high": 30, "critical": 60}
DETECTOR_ORDER = {
    "instruction_override": 0,
    "untrusted_instruction": 1,
    "sensitive_data": 2,
    "oversize_chunk": 3,
    "duplicate_text": 4,
}


def scan_context(chunks: list[ContextChunk], policy: Policy | None = None) -> ScanReport:
    active_policy = policy or Policy()
    issues: list[Issue] = []

    for chunk in chunks:
        issues.extend(_detect_instruction_override(chunk))
        issues.extend(_detect_sensitive_data(chunk))
        issues.extend(_detect_untrusted_instruction(chunk))
        issues.extend(_detect_oversize_chunk(chunk, active_policy))
    issues.extend(_detect_duplicates(chunks))

    ordered_issues = sorted(
        issues,
        key=lambda issue: (
            -SEVERITY_RANK[issue.severity],
            DETECTOR_ORDER.get(issue.detector, 99),
            issue.chunk_id,
            issue.source,
        ),
    )
    summary = dict(
        sorted(
            Counter(issue.detector for issue in ordered_issues).items(),
            key=lambda item: (DETECTOR_ORDER.get(item[0], 99), item[0]),
        )
    )
    score = max(0, 100 - sum(PENALTY_BY_SEVERITY[issue.severity] for issue in ordered_issues))
    return ScanReport(score=score, issues=ordered_issues, summary=summary, policy=active_policy)


def _detect_instruction_override(chunk: ContextChunk) -> list[Issue]:
    for pattern in INSTRUCTION_OVERRIDE_PATTERNS:
        match = pattern.search(chunk.text)
        if match:
            return [
                Issue(
                    chunk_id=chunk.chunk_id,
                    source=chunk.source,
                    detector="instruction_override",
                    severity="high",
                    message="Instruction-like text may try to override model or system behavior.",
                    evidence=_evidence(chunk.text, match.start(), match.end()),
                )
            ]
    return []


def _detect_sensitive_data(chunk: ContextChunk) -> list[Issue]:
    for pattern in SENSITIVE_PATTERNS:
        match = pattern.search(chunk.text)
        if match:
            return [
                Issue(
                    chunk_id=chunk.chunk_id,
                    source=chunk.source,
                    detector="sensitive_data",
                    severity="high",
                    message="Sensitive-looking key or credential text appears in context.",
                    evidence=_evidence(chunk.text, match.start(), match.end()),
                )
            ]
    return []


def _detect_untrusted_instruction(chunk: ContextChunk) -> list[Issue]:
    if chunk.trusted:
        return []
    match = UNTRUSTED_AUTHORITY_PATTERN.search(chunk.text)
    if not match:
        return []
    return [
        Issue(
            chunk_id=chunk.chunk_id,
            source=chunk.source,
            detector="untrusted_instruction",
            severity="high",
            message="Untrusted context contains instruction or authority-like language.",
            evidence=_evidence(chunk.text, match.start(), match.end()),
        )
    ]


def _detect_oversize_chunk(chunk: ContextChunk, policy: Policy) -> list[Issue]:
    if len(chunk.text) <= policy.max_chunk_chars:
        return []
    return [
        Issue(
            chunk_id=chunk.chunk_id,
            source=chunk.source,
            detector="oversize_chunk",
            severity="medium",
            message=f"Chunk has {len(chunk.text)} characters; policy allows {policy.max_chunk_chars}.",
            evidence=f"{len(chunk.text)} characters",
        )
    ]


def _detect_duplicates(chunks: list[ContextChunk]) -> list[Issue]:
    seen: dict[str, ContextChunk] = {}
    issues: list[Issue] = []
    for chunk in chunks:
        normalized = _normalize_text(chunk.text)
        first = seen.get(normalized)
        if first is None:
            seen[normalized] = chunk
            continue
        issues.append(
            Issue(
                chunk_id=chunk.chunk_id,
                source=chunk.source,
                detector="duplicate_text",
                severity="low",
                message=f"Chunk text duplicates {first.chunk_id}; repeated evidence can crowd context.",
                evidence=f"duplicates {first.chunk_id}",
            )
        )
    return issues


def _normalize_text(text: str) -> str:
    return " ".join(text.lower().split())


def _evidence(text: str, start: int, end: int) -> str:
    left = max(0, start - 32)
    right = min(len(text), end + 32)
    evidence = text[left:right].strip()
    return " ".join(evidence.split())
