from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from contextaudit.io import InputError, chunks_from_records, policy_from_mapping
from contextaudit.models import DETECTORS
from contextaudit.scanner import scan_context


@dataclass(frozen=True)
class DetectorMetrics:
    true_positives: int
    false_positives: int
    false_negatives: int

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return 1.0 if denominator == 0 else self.true_positives / denominator

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return 1.0 if denominator == 0 else self.true_positives / denominator

    @property
    def f1(self) -> float:
        denominator = self.precision + self.recall
        return 1.0 if denominator == 0 else 2 * self.precision * self.recall / denominator

    def to_dict(self) -> dict[str, float | int]:
        return {
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


@dataclass(frozen=True)
class FingerprintMismatch:
    case: str
    chunk_id: str
    detector: str
    expected: str
    actual: str | None

    def to_dict(self) -> dict[str, str | None]:
        return {
            "case": self.case,
            "chunk_id": self.chunk_id,
            "detector": self.detector,
            "expected": self.expected,
            "actual": self.actual,
        }


@dataclass(frozen=True)
class FingerprintMetrics:
    checked: int = 0
    matched: int = 0
    mismatches: tuple[FingerprintMismatch, ...] = ()

    @property
    def mismatched(self) -> int:
        return len(self.mismatches)

    def to_dict(self) -> dict[str, Any]:
        return {
            "checked": self.checked,
            "matched": self.matched,
            "mismatched": self.mismatched,
            "mismatches": [mismatch.to_dict() for mismatch in self.mismatches],
        }


@dataclass(frozen=True)
class EvaluationResult:
    cases: int
    true_positives: int
    false_positives: int
    false_negatives: int
    by_detector: dict[str, DetectorMetrics] = field(default_factory=dict)
    fingerprints: FingerprintMetrics = field(default_factory=FingerprintMetrics)

    @property
    def precision(self) -> float:
        return self._metrics.precision

    @property
    def recall(self) -> float:
        return self._metrics.recall

    @property
    def f1(self) -> float:
        return self._metrics.f1

    def to_dict(self) -> dict[str, Any]:
        payload = self._metrics.to_dict()
        payload["cases"] = self.cases
        payload["detectors"] = {
            detector: metrics.to_dict() for detector, metrics in self.by_detector.items()
        }
        payload["fingerprints"] = self.fingerprints.to_dict()
        payload["review"] = {"false_positive_detectors": self.false_positive_review()}
        return payload

    @property
    def _metrics(self) -> DetectorMetrics:
        return DetectorMetrics(
            true_positives=self.true_positives,
            false_positives=self.false_positives,
            false_negatives=self.false_negatives,
        )

    def false_positive_review(self) -> list[dict[str, float | int | str]]:
        review_items: list[dict[str, float | int | str]] = []
        for detector, metrics in sorted(
            self.by_detector.items(),
            key=lambda item: (-item[1].false_positives, _detector_order(item[0]), item[0]),
        ):
            if metrics.false_positives == 0:
                continue
            review_items.append(
                {
                    "detector": detector,
                    "false_positives": metrics.false_positives,
                    "precision": metrics.precision,
                    "guidance": (
                        "Review fixture evidence and source trust before changing "
                        "patterns, allowlists, or suppressions."
                    ),
                }
            )
        return review_items


def evaluate_suite(path: Path) -> EvaluationResult:
    try:
        suite = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc
    if not isinstance(suite, dict):
        raise InputError(f"{path}: suite must be an object")
    cases = suite.get("cases")
    if not isinstance(cases, list):
        raise InputError(f"{path}: cases must be an array")

    true_positives = 0
    false_positives = 0
    false_negatives = 0
    detector_counts: dict[str, dict[str, int]] = {}
    fingerprint_checked = 0
    fingerprint_matched = 0
    fingerprint_mismatches: list[FingerprintMismatch] = []
    for index, case in enumerate(cases):
        case_obj = _require_object(case, f"cases[{index}]")
        case_name = _case_name(case_obj, index)
        context_records = case_obj.get("context")
        if not isinstance(context_records, list):
            raise InputError(f"cases[{index}].context must be an array")
        chunks = chunks_from_records([_require_object(item, f"cases[{index}].context[]") for item in context_records])
        policy_record = case_obj.get("policy")
        if policy_record is not None and not isinstance(policy_record, dict):
            raise InputError(f"cases[{index}].policy must be an object")
        report = scan_context(chunks, policy_from_mapping(policy_record))

        expected_records = case_obj.get("expected", [])
        if not isinstance(expected_records, list):
            raise InputError(f"cases[{index}].expected must be an array")
        expected_objects = [
            _require_object(item, f"cases[{index}].expected[{expected_index}]")
            for expected_index, item in enumerate(expected_records)
        ]
        expected = {_issue_key(record) for record in expected_objects}
        predicted = {(issue.chunk_id, issue.detector) for issue in report.issues}
        predicted_fingerprints = {
            (issue.chunk_id, issue.detector): issue.fingerprint for issue in report.issues
        }

        matched = predicted & expected
        extra = predicted - expected
        missed = expected - predicted
        true_positives += len(matched)
        false_positives += len(extra)
        false_negatives += len(missed)
        for _, detector in matched:
            _increment_detector(detector_counts, detector, "true_positives")
        for _, detector in extra:
            _increment_detector(detector_counts, detector, "false_positives")
        for _, detector in missed:
            _increment_detector(detector_counts, detector, "false_negatives")
        for expected_index, record in enumerate(expected_objects):
            expected_fingerprint = _expected_fingerprint(
                record,
                f"cases[{index}].expected[{expected_index}].fingerprint",
            )
            if expected_fingerprint is None:
                continue
            fingerprint_checked += 1
            key = _issue_key(record)
            actual_fingerprint = predicted_fingerprints.get(key)
            if actual_fingerprint == expected_fingerprint:
                fingerprint_matched += 1
                continue
            fingerprint_mismatches.append(
                FingerprintMismatch(
                    case=case_name,
                    chunk_id=key[0],
                    detector=key[1],
                    expected=expected_fingerprint,
                    actual=actual_fingerprint,
                )
            )

    return EvaluationResult(
        cases=len(cases),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        by_detector={
            detector: DetectorMetrics(
                true_positives=counts["true_positives"],
                false_positives=counts["false_positives"],
                false_negatives=counts["false_negatives"],
            )
            for detector, counts in sorted(
                detector_counts.items(), key=lambda item: (_detector_order(item[0]), item[0])
            )
        },
        fingerprints=FingerprintMetrics(
            checked=fingerprint_checked,
            matched=fingerprint_matched,
            mismatches=tuple(fingerprint_mismatches),
        ),
    )


def render_evaluation_text(result: EvaluationResult) -> str:
    return "\n".join(
        [
            "ContextAudit evaluation",
            f"Cases: {result.cases}",
            f"True positives: {result.true_positives}",
            f"False positives: {result.false_positives}",
            f"False negatives: {result.false_negatives}",
            f"Precision: {result.precision:.2f}",
            f"Recall: {result.recall:.2f}",
            f"F1: {result.f1:.2f}",
            f"Fingerprint checks: {result.fingerprints.checked}",
            f"Fingerprint matches: {result.fingerprints.matched}",
            f"Fingerprint mismatches: {result.fingerprints.mismatched}",
            *(
                ["Fingerprint mismatch details:"]
                if result.fingerprints.mismatches
                else []
            ),
            *[
                (
                    f"{mismatch.case}: {mismatch.chunk_id}/{mismatch.detector} expected "
                    f"{mismatch.expected}, actual {mismatch.actual or 'missing'}"
                )
                for mismatch in result.fingerprints.mismatches
            ],
            "By detector:",
            *[
                (
                    f"{detector}: TP {metrics.true_positives}, FP {metrics.false_positives}, "
                    f"FN {metrics.false_negatives}, precision {metrics.precision:.2f}, "
                    f"recall {metrics.recall:.2f}, F1 {metrics.f1:.2f}"
                )
                for detector, metrics in result.by_detector.items()
            ],
            *(
                ["False-positive review:"]
                if result.false_positive_review()
                else []
            ),
            *[
                (
                    f"{item['detector']}: review {item['false_positives']} "
                    "false positive(s) against labeled fixture evidence before "
                    "changing patterns, allowlists, or suppressions."
                )
                for item in result.false_positive_review()
            ],
            "",
        ]
    )


def render_evaluation_json(result: EvaluationResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"


def _require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label}: expected object")
    return value


def _issue_key(record: dict[str, Any]) -> tuple[str, str]:
    chunk_id = record.get("chunk_id")
    detector = record.get("detector")
    if not isinstance(chunk_id, str) or not chunk_id:
        raise InputError("expected issue chunk_id to be a non-empty string")
    if not isinstance(detector, str) or not detector:
        raise InputError("expected issue detector to be a non-empty string")
    return (chunk_id, detector)


def _expected_fingerprint(record: dict[str, Any], label: str) -> str | None:
    fingerprint = record.get("fingerprint")
    if fingerprint is None:
        return None
    if not isinstance(fingerprint, str) or not fingerprint:
        raise InputError(f"{label} must be a non-empty string")
    return fingerprint


def _case_name(record: dict[str, Any], index: int) -> str:
    name = record.get("name")
    return name if isinstance(name, str) and name else f"cases[{index}]"


def _increment_detector(
    detector_counts: dict[str, dict[str, int]],
    detector: str,
    field_name: str,
) -> None:
    counts = detector_counts.setdefault(
        detector,
        {"true_positives": 0, "false_positives": 0, "false_negatives": 0},
    )
    counts[field_name] += 1


def _detector_order(detector: str) -> int:
    try:
        return DETECTORS.index(detector)
    except ValueError:
        return len(DETECTORS)
