from __future__ import annotations

import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from contextaudit.answer_audit import AnswerCandidate
from contextaudit.models import ContextChunk, Policy

MAX_INPUT_BYTES = 10 * 1024 * 1024
CONTEXT_FORMATS = ("jsonl", "markdown", "langchain-jsonl", "llamaindex-json")
SUPPRESSION_FINGERPRINT_PATTERN = re.compile(r"^[0-9a-f]{16}$")


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


def load_context(path: Path, context_format: str = "jsonl") -> list[ContextChunk]:
    if context_format == "jsonl":
        return load_context_jsonl(path)
    if context_format == "markdown":
        return load_markdown_directory(path)
    if context_format == "langchain-jsonl":
        return load_langchain_jsonl(path)
    if context_format == "llamaindex-json":
        return load_llamaindex_json(path)
    allowed = ", ".join(CONTEXT_FORMATS)
    raise InputError(f"context format must be one of: {allowed}")


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


def load_markdown_directory(path: Path) -> list[ContextChunk]:
    if not path.exists():
        raise InputError(f"{path}: directory does not exist")
    if not path.is_dir():
        raise InputError(f"{path}: expected directory")
    chunks: list[ContextChunk] = []
    markdown_paths = sorted(
        path.rglob("*.md"),
        key=lambda item: item.relative_to(path).as_posix(),
    )
    for markdown_path in markdown_paths:
        _check_size(markdown_path)
        relative_path = markdown_path.relative_to(path).as_posix()
        label = str(markdown_path)
        front_matter, body = _split_markdown_front_matter(markdown_path.read_text(), label)
        trusted = _trusted_field(front_matter.pop("trusted", True), label)
        chunk_id = _string_value(
            front_matter.pop("chunk_id", _default_chunk_id(relative_path)),
            "chunk_id",
            label,
        )
        source = _string_value(front_matter.pop("source", relative_path), "source", label)
        metadata = {
            "adapter": "markdown",
            "path": relative_path,
            **front_matter,
        }
        chunks.append(
            chunk_from_mapping(
                {
                    "chunk_id": chunk_id,
                    "source": source,
                    "text": body.strip(),
                    "trusted": trusted,
                    "metadata": metadata,
                },
                label,
            )
        )
    if not chunks:
        raise InputError(f"{path}: no Markdown files found")
    return chunks


def load_langchain_jsonl(path: Path) -> list[ContextChunk]:
    _check_size(path)
    chunks: list[ContextChunk] = []
    for line_number, line in enumerate(path.read_text().splitlines(), start=1):
        if not line.strip():
            continue
        label = f"{path}:{line_number}"
        try:
            record = _object_from(json.loads(line), label)
        except json.JSONDecodeError as exc:
            raise InputError(f"{label}: invalid JSON: {exc.msg}") from exc
        metadata = _metadata_field(record, label)
        chunk_id = _string_value(
            metadata.get("chunk_id", f"langchain:{line_number}"),
            "metadata.chunk_id",
            label,
        )
        source = _string_value(
            metadata.get("source", metadata.get("file_path", label)),
            "metadata.source",
            label,
        )
        chunks.append(
            ContextChunk(
                chunk_id=chunk_id,
                source=source,
                text=_string_field(record, "page_content", label),
                trusted=_trusted_field(metadata.get("trusted", True), label),
                metadata={"adapter": "langchain-jsonl", **metadata},
            )
        )
    if not chunks:
        raise InputError(f"{path}: no LangChain documents found")
    return chunks


def load_llamaindex_json(path: Path) -> list[ContextChunk]:
    data = _read_json(path)
    nodes = _llamaindex_nodes(data, str(path))
    chunks: list[ContextChunk] = []
    for index, node in enumerate(nodes):
        label = f"{path}:nodes[{index}]"
        record = _object_from(node, label)
        metadata = _metadata_field(record, label)
        chunk_id = _string_value(
            _first_present(record, ("id_", "node_id", "id"), None),
            "node id",
            label,
        )
        source = _string_value(
            _first_present(
                metadata,
                ("source", "file_path", "document_id", "ref_doc_id"),
                record.get("ref_doc_id", f"{path}#{chunk_id}"),
            ),
            "source",
            label,
        )
        chunks.append(
            ContextChunk(
                chunk_id=chunk_id,
                source=source,
                text=_string_field(record, "text", label),
                trusted=_trusted_field(metadata.get("trusted", True), label),
                metadata={"adapter": "llamaindex-json", **metadata},
            )
        )
    if not chunks:
        raise InputError(f"{path}: no LlamaIndex nodes found")
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


def load_suppressions(path: Path | None) -> frozenset[str]:
    if path is None:
        return frozenset()
    record = _object_from(_read_json(path), str(path))
    value = record.get("suppressions", [])
    if not isinstance(value, list):
        raise InputError(f"{path}: suppressions must be an array")

    fingerprints: list[str] = []
    for index, entry in enumerate(value):
        label = f"{path}:suppressions[{index}]"
        if not isinstance(entry, dict):
            raise InputError(f"{label}: suppression must be an object")
        fingerprint = entry.get("fingerprint")
        if not isinstance(fingerprint, str) or not fingerprint:
            raise InputError(f"{label}: fingerprint must be a non-empty string")
        if not SUPPRESSION_FINGERPRINT_PATTERN.fullmatch(fingerprint):
            raise InputError(f"{label}: fingerprint must be a 16-character lowercase hex string")
        reason = entry.get("reason")
        if reason is not None and (not isinstance(reason, str) or not reason.strip()):
            raise InputError(f"{label}: reason must be a non-empty string when present")
        fingerprints.append(fingerprint)
    return frozenset(fingerprints)


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


def _split_markdown_front_matter(text: str, label: str) -> tuple[dict[str, Any], str]:
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return {}, text
    for end_index, line in enumerate(lines[1:], start=1):
        if line.strip() == "---":
            return _parse_front_matter(lines[1:end_index], label), "\n".join(
                lines[end_index + 1 :]
            )
    raise InputError(f"{label}: front matter is not closed")


def _parse_front_matter(lines: list[str], label: str) -> dict[str, Any]:
    values: dict[str, Any] = {}
    for offset, line in enumerate(lines, start=2):
        if not line.strip():
            continue
        if ":" not in line:
            raise InputError(f"{label}:{offset}: front matter entries must use key: value")
        key, raw_value = line.split(":", 1)
        key = key.strip()
        if not key:
            raise InputError(f"{label}:{offset}: front matter key must be non-empty")
        values[key] = _front_matter_value(raw_value.strip())
    return values


def _front_matter_value(value: str) -> Any:
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    return value.strip('"').strip("'")


def _default_chunk_id(relative_path: str) -> str:
    path = Path(relative_path)
    if path.suffix == ".md":
        path = path.with_suffix("")
    return path.as_posix()


def _string_value(value: Any, field: str, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise InputError(f"{label}: {field} must be a non-empty string")
    return value


def _trusted_field(value: Any, label: str) -> bool:
    if not isinstance(value, bool):
        raise InputError(f"{label}: trusted must be a boolean when present")
    return value


def _metadata_field(record: dict[str, Any], label: str) -> dict[str, Any]:
    metadata = record.get("metadata", {})
    if not isinstance(metadata, dict):
        raise InputError(f"{label}: metadata must be an object when present")
    return metadata


def _first_present(record: dict[str, Any], keys: tuple[str, ...], fallback: Any) -> Any:
    for key in keys:
        value = record.get(key)
        if value is not None:
            return value
    return fallback


def _llamaindex_nodes(data: Any, label: str) -> list[Any]:
    if isinstance(data, list):
        return data
    if not isinstance(data, dict):
        raise InputError(f"{label}: expected a JSON object or array of nodes")
    nodes = data.get("nodes")
    if isinstance(nodes, list):
        return nodes
    docstore = data.get("docstore")
    if isinstance(docstore, dict):
        store_data = docstore.get("data")
        if isinstance(store_data, dict):
            return list(store_data.values())
    raise InputError(f"{label}: expected nodes array or docstore.data object")
