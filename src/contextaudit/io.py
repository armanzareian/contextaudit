from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from contextaudit.answer_audit import AnswerCandidate
from contextaudit.models import ContextChunk, Policy

MAX_INPUT_BYTES = 10 * 1024 * 1024


class InputError(ValueError):
    """Raised when user-provided input cannot be audited safely."""


def _read_json(path: Path) -> Any:
    _check_size(path)
    try:
        return json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise InputError(f"{path}: invalid JSON at line {exc.lineno}: {exc.msg}") from exc


def _check_size(path: Path) -> None:
    if not path.exists():
        raise InputError(f"{path}: file does not exist")
    if path.stat().st_size > MAX_INPUT_BYTES:
        raise InputError(f"{path}: input exceeds {MAX_INPUT_BYTES} bytes")


def _object_from(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise InputError(f"{label}: expected JSON object")
    return value


def _string_field(record: dict[str, Any], field: str, label: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value:
        raise InputError(f"{label}: {field} must be a non-empty string")
    return value


def chunk_from_mapping(record: dict[str, Any], label: str) -> ContextChunk:
    metadata = record.get("metadata", {})
    if not isinstance(metadata, dict):
        raise InputError(f"{label}: metadata must be an object when present")
    trusted = record.get("trusted", True)
    if not isinstance(trusted, bool):
        raise InputError(f"{label}: trusted must be a boolean when present")
    return ContextChunk(
        chunk_id=_string_field(record, "chunk_id", label),
        source=_string_field(record, "source", label),
        text=_string_field(record, "text", label),
        trusted=trusted,
        metadata=metadata,
    )


def chunks_from_records(records: Iterable[dict[str, Any]]) -> list[ContextChunk]:
    return [chunk_from_mapping(record, f"context[{index}]") for index, record in enumerate(records)]


def load_context_jsonl(path: Path) -> list[ContextChunk]:
    _check_size(path)
    chunks: list[ContextChunk] = []
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        try:
            record = _object_from(json.loads(line), f"{path}:{line_number}")
        except json.JSONDecodeError as exc:
            raise InputError(f"{path}:{line_number}: invalid JSON: {exc.msg}") from exc
        chunks.append(chunk_from_mapping(record, f"{path}:{line_number}"))
    if not chunks:
        raise InputError(f"{path}: no context chunks found")
    return chunks


def policy_from_mapping(record: dict[str, Any] | None) -> Policy:
    if record is None:
        return Policy()
    fail_on = record.get("fail_on", "high")
    max_chunk_chars = record.get("max_chunk_chars", 4000)
    disabled_detectors = _string_list_field(record, "disabled_detectors")
    severity_overrides_record = record.get("severity_overrides", {})
    allowlisted_sources = _string_list_field(record, "allowlisted_sources")
    detector_patterns = _detector_patterns_field(record)
    if not isinstance(fail_on, str):
        raise InputError("policy.fail_on must be a string")
    if not isinstance(max_chunk_chars, int):
        raise InputError("policy.max_chunk_chars must be an integer")
    if not isinstance(severity_overrides_record, dict):
        raise InputError("policy.severity_overrides must be an object")
    severity_overrides: dict[str, str] = {}
    for detector, severity in severity_overrides_record.items():
        if not isinstance(detector, str) or not isinstance(severity, str):
            raise InputError("policy.severity_overrides must map detector names to severities")
        severity_overrides[detector] = severity
    try:
        return Policy(
            fail_on=fail_on,
            max_chunk_chars=max_chunk_chars,
            disabled_detectors=tuple(disabled_detectors),
            severity_overrides=severity_overrides,
            allowlisted_sources=tuple(allowlisted_sources),
            detector_patterns=detector_patterns,
        )
    except ValueError as exc:
        raise InputError(f"invalid policy: {exc}") from exc


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    return policy_from_mapping(_object_from(_read_json(path), str(path)))


def load_answer(path: Path) -> AnswerCandidate:
    record = _object_from(_read_json(path), str(path))
    citations = record.get("citations", [])
    if not isinstance(citations, list):
        raise InputError(f"{path}: citations must be an array")
    if not all(isinstance(citation, str) and citation for citation in citations):
        raise InputError(f"{path}: citations must contain non-empty strings")
    try:
        return AnswerCandidate(
            answer=_string_field(record, "answer", str(path)),
            citations=tuple(citations),
        )
    except ValueError as exc:
        raise InputError(f"{path}: {exc}") from exc


def _string_list_field(record: dict[str, Any], field: str) -> list[str]:
    value = record.get(field, [])
    if not isinstance(value, list):
        raise InputError(f"policy.{field} must be an array")
    if not all(isinstance(item, str) and item for item in value):
        raise InputError(f"policy.{field} must contain non-empty strings")
    return value


def _detector_patterns_field(record: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    value = record.get("detector_patterns", {})
    if not isinstance(value, dict):
        raise InputError("policy.detector_patterns must be an object")
    patterns: dict[str, tuple[str, ...]] = {}
    for detector, detector_patterns in value.items():
        if not isinstance(detector, str):
            raise InputError("policy.detector_patterns keys must be detector names")
        if not isinstance(detector_patterns, list):
            raise InputError("policy.detector_patterns values must be arrays")
        if not all(isinstance(pattern, str) and pattern for pattern in detector_patterns):
            raise InputError("policy.detector_patterns values must contain non-empty strings")
        patterns[detector] = tuple(detector_patterns)
    return patterns
