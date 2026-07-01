from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, replace

from contextaudit.models import (
    DETECTORS,
    ContextChunk,
    Issue,
    Policy,
    SEVERITY_RANK,
    ScanReport,
)
from contextaudit.scanner import PENALTY_BY_SEVERITY, scan_context

TOKEN_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*")
SENTENCE_BOUNDARY_PATTERN = re.compile(r"(?<=[.!?])\s+")
CITATION_MARKER_PATTERN = re.compile(r"\[[^\]]+\]")
DETECTOR_ORDER = {detector: index for index, detector in enumerate(DETECTORS)}
MIN_SUPPORT_RATIO = 0.45
MIN_SUPPORT_TERMS = 2
RISK_OVERLAP_TERMS = 3
STOPWORDS = {
    "about",
    "after",
    "again",
    "also",
    "among",
    "and",
    "are",
    "because",
    "been",
    "before",
    "being",
    "but",
    "can",
    "could",
    "does",
    "for",
    "from",
    "has",
    "have",
    "into",
    "its",
    "may",
    "more",
    "must",
    "not",
    "only",
    "our",
    "should",
    "than",
    "that",
    "the",
    "their",
    "them",
    "then",
    "there",
    "these",
    "they",
    "this",
    "those",
    "through",
    "was",
    "were",
    "with",
    "within",
    "would",
    "your",
}


@dataclass(frozen=True)
class AnswerCandidate:
    answer: str
    citations: tuple[str, ...] = ()

    def __post_init__(self) -> None:
        if not isinstance(self.answer, str) or not self.answer:
            raise ValueError("answer is required")
        citations = _normalize_citations(self.citations)
        object.__setattr__(self, "citations", citations)


def audit_answer(
    chunks: list[ContextChunk],
    candidate: AnswerCandidate,
    policy: Policy | None = None,
) -> ScanReport:
    active_policy = policy or Policy()
    chunk_by_id = {chunk.chunk_id: chunk for chunk in chunks}
    issues: list[Issue] = []

    if _detector_enabled(active_policy, "missing_citation"):
        issues.extend(_detect_missing_citations(candidate, chunk_by_id))

    existing_citations = tuple(
        citation for citation in candidate.citations if citation in chunk_by_id
    )
    if _detector_enabled(active_policy, "weak_sentence_support"):
        issues.extend(_detect_weak_sentence_support(candidate, chunk_by_id, existing_citations))

    if _detector_enabled(active_policy, "uncited_risky_context"):
        issues.extend(_detect_uncited_risky_context(chunks, candidate, active_policy))

    policy_issues = [_apply_policy(issue, active_policy) for issue in issues]
    ordered_issues = sorted(
        policy_issues,
        key=lambda issue: (
            -SEVERITY_RANK[issue.severity],
            DETECTOR_ORDER.get(issue.detector, 99),
            issue.chunk_id,
            issue.source,
            issue.fingerprint,
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


def _detect_missing_citations(
    candidate: AnswerCandidate,
    chunk_by_id: dict[str, ContextChunk],
) -> list[Issue]:
    issues: list[Issue] = []
    for citation in candidate.citations:
        if citation in chunk_by_id:
            continue
        issues.append(
            Issue(
                chunk_id=citation,
                source="answer.citations",
                detector="missing_citation",
                severity="high",
                message="Citation does not match any context chunk ID.",
                evidence=citation,
            )
        )
    return issues


def _detect_weak_sentence_support(
    candidate: AnswerCandidate,
    chunk_by_id: dict[str, ContextChunk],
    citations: tuple[str, ...],
) -> list[Issue]:
    support_tokens = _tokens(" ".join(chunk_by_id[citation].text for citation in citations))
    issues: list[Issue] = []
    for index, sentence in enumerate(_sentences(candidate.answer), start=1):
        sentence_tokens = _tokens(_strip_citation_markers(sentence))
        if not sentence_tokens:
            continue
        if _has_lexical_support(sentence_tokens, support_tokens):
            continue
        issues.append(
            Issue(
                chunk_id=f"answer:sentence:{index}",
                source="answer",
                detector="weak_sentence_support",
                severity="medium",
                message="Answer sentence has weak lexical support from cited context.",
                evidence=_evidence_sentence(sentence),
            )
        )
    return issues


def _detect_uncited_risky_context(
    chunks: list[ContextChunk],
    candidate: AnswerCandidate,
    policy: Policy,
) -> list[Issue]:
    cited_ids = set(candidate.citations)
    answer_tokens = _tokens(candidate.answer)
    if not answer_tokens:
        return []

    risky_ids = {
        issue.chunk_id
        for issue in scan_context(chunks, policy).issues
        if issue.severity in {"high", "critical"} and issue.chunk_id not in cited_ids
    }
    issues: list[Issue] = []
    for chunk in chunks:
        if chunk.chunk_id not in risky_ids:
            continue
        overlap = sorted(answer_tokens & _tokens(chunk.text))
        if len(overlap) < RISK_OVERLAP_TERMS:
            continue
        issues.append(
            Issue(
                chunk_id=chunk.chunk_id,
                source=chunk.source,
                detector="uncited_risky_context",
                severity="medium",
                message="Answer overlaps with high-risk context that was not cited.",
                evidence="shared terms: " + ", ".join(overlap[:6]),
            )
        )
    return issues


def _normalize_citations(citations: Sequence[str]) -> tuple[str, ...]:
    if isinstance(citations, str) or not isinstance(citations, Sequence):
        raise ValueError("citations must be an array")
    normalized: list[str] = []
    for citation in citations:
        if not isinstance(citation, str) or not citation:
            raise ValueError("citations must contain non-empty strings")
        normalized.append(citation)
    return tuple(dict.fromkeys(normalized))


def _detector_enabled(policy: Policy, detector: str) -> bool:
    return detector not in policy.disabled_detectors


def _apply_policy(issue: Issue, policy: Policy) -> Issue:
    severity = policy.severity_overrides.get(issue.detector)
    if severity is None or severity == issue.severity:
        return issue
    return replace(issue, severity=severity)


def _sentences(answer: str) -> list[str]:
    return [
        sentence.strip()
        for sentence in SENTENCE_BOUNDARY_PATTERN.split(answer)
        if sentence.strip()
    ]


def _strip_citation_markers(sentence: str) -> str:
    return CITATION_MARKER_PATTERN.sub(" ", sentence)


def _tokens(text: str) -> set[str]:
    tokens: set[str] = set()
    for match in TOKEN_PATTERN.finditer(text.lower()):
        token = match.group(0).strip("_-")
        if len(token) < 3 or token in STOPWORDS:
            continue
        tokens.add(token)
    return tokens


def _has_lexical_support(sentence_tokens: set[str], support_tokens: set[str]) -> bool:
    if not support_tokens:
        return False
    overlap = sentence_tokens & support_tokens
    required = max(MIN_SUPPORT_TERMS, round(len(sentence_tokens) * MIN_SUPPORT_RATIO))
    return len(overlap) >= required


def _evidence_sentence(sentence: str) -> str:
    compact = " ".join(sentence.split())
    if len(compact) <= 120:
        return compact
    return compact[:117].rstrip() + "..."
