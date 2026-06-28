from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

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
    if not isinstance(fail_on, str):
        raise InputError("policy.fail_on must be a string")
    if not isinstance(max_chunk_chars, int):
        raise InputError("policy.max_chunk_chars must be an integer")
    try:
        return Policy(fail_on=fail_on, max_chunk_chars=max_chunk_chars)
    except ValueError as exc:
        raise InputError(f"invalid policy: {exc}") from exc


def load_policy(path: Path | None) -> Policy:
    if path is None:
        return Policy()
    return policy_from_mapping(_object_from(_read_json(path), str(path)))
