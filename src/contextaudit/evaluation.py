from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from contextaudit.io import InputError, chunks_from_records, policy_from_mapping
from contextaudit.scanner import scan_context


@dataclass(frozen=True)
class EvaluationResult:
    cases: int
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
            "cases": self.cases,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
        }


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
    for index, case in enumerate(cases):
        case_obj = _require_object(case, f"cases[{index}]")
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
        expected = {_issue_key(_require_object(item, f"cases[{index}].expected[]")) for item in expected_records}
        predicted = {(issue.chunk_id, issue.detector) for issue in report.issues}

        true_positives += len(predicted & expected)
        false_positives += len(predicted - expected)
        false_negatives += len(expected - predicted)

    return EvaluationResult(
        cases=len(cases),
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
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
