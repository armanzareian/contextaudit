"""Offline audits for RAG and LLM context packs."""

from contextaudit.answer_audit import AnswerCandidate, audit_answer
from contextaudit.extensions import (
    ContextLoader,
    ContextScanner,
    ExtensionError,
    load_with,
    scan_with_loader,
)
from contextaudit.io import (
    load_context,
    load_langchain_jsonl,
    load_llamaindex_json,
    load_markdown_directory,
)
from contextaudit.models import ContextChunk, Issue, Policy, ScanReport
from contextaudit.scanner import scan_context

__all__ = [
    "AnswerCandidate",
    "ContextChunk",
    "ContextLoader",
    "ContextScanner",
    "ExtensionError",
    "Issue",
    "Policy",
    "ScanReport",
    "audit_answer",
    "load_context",
    "load_langchain_jsonl",
    "load_llamaindex_json",
    "load_markdown_directory",
    "load_with",
    "scan_context",
    "scan_with_loader",
]

__version__ = "0.1.0"
