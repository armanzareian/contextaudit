from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from contextaudit import __version__
from contextaudit.answer_audit import audit_answer
from contextaudit.evaluation import evaluate_suite, render_evaluation_json, render_evaluation_text
from contextaudit.io import (
    CONTEXT_FORMATS,
    InputError,
    load_answer,
    load_context,
    load_policy,
    load_suppressions,
)
from contextaudit.models import Policy, ScanReport, normalize_severity
from contextaudit.report import render_json, render_markdown_summary, render_sarif, render_text
from contextaudit.scanner import scan_context
from contextaudit.suppressions import apply_suppressions


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "audit-answer":
            return _run_audit_answer(args)
        if args.command == "eval":
            return _run_eval(args)
    except (InputError, ValueError) as exc:
        print(f"contextaudit: {exc}", file=sys.stderr)
        return 2
    parser.error("missing command")
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="contextaudit",
        description="Audit RAG and LLM context packs before they reach a model.",
    )
    parser.add_argument("--version", action="version", version=f"contextaudit {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    scan = subparsers.add_parser("scan", help="scan a context JSONL file")
    scan.add_argument("--context", type=Path, required=True, help="context input to scan")
    scan.add_argument(
        "--context-format",
        choices=CONTEXT_FORMATS,
        default="jsonl",
        help="context input format",
    )
    scan.add_argument("--policy", type=Path, help="optional JSON policy file")
    scan.add_argument("--suppressions", type=Path, help="optional JSON suppression file")
    scan.add_argument("--format", choices=("text", "json", "sarif", "markdown"), default="text")
    scan.add_argument("--fail-on", choices=("low", "medium", "high", "critical"))
    scan.add_argument("--max-chunk-chars", type=int)

    answer = subparsers.add_parser(
        "audit-answer",
        help="audit an answer JSON file against cited context chunks",
    )
    answer.add_argument("--context", type=Path, required=True, help="context input")
    answer.add_argument(
        "--context-format",
        choices=CONTEXT_FORMATS,
        default="jsonl",
        help="context input format",
    )
    answer.add_argument("--answer", type=Path, required=True, help="JSON answer candidate")
    answer.add_argument("--policy", type=Path, help="optional JSON policy file")
    answer.add_argument("--suppressions", type=Path, help="optional JSON suppression file")
    answer.add_argument("--format", choices=("text", "json", "sarif", "markdown"), default="text")
    answer.add_argument("--fail-on", choices=("low", "medium", "high", "critical"))
    answer.add_argument("--max-chunk-chars", type=int)

    evaluate = subparsers.add_parser("eval", help="evaluate detectors against a labeled suite")
    evaluate.add_argument("--suite", type=Path, required=True, help="JSON labeled suite")
    evaluate.add_argument("--format", choices=("text", "json"), default="text")
    return parser


def _run_scan(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    report = scan_context(load_context(args.context, args.context_format), policy)
    report = apply_suppressions(report, load_suppressions(args.suppressions))
    print(_render_report(report, args.format), end="")
    return report.exit_code


def _run_audit_answer(args: argparse.Namespace) -> int:
    policy = _policy_from_args(args)
    report = audit_answer(
        load_context(args.context, args.context_format),
        load_answer(args.answer),
        policy,
    )
    report = apply_suppressions(report, load_suppressions(args.suppressions))
    print(_render_report(report, args.format), end="")
    return report.exit_code


def _policy_from_args(args: argparse.Namespace) -> Policy:
    file_policy = load_policy(args.policy)
    return Policy(
        fail_on=normalize_severity(args.fail_on or file_policy.fail_on),
        max_chunk_chars=args.max_chunk_chars or file_policy.max_chunk_chars,
        disabled_detectors=file_policy.disabled_detectors,
        severity_overrides=file_policy.severity_overrides,
        allowlisted_sources=file_policy.allowlisted_sources,
        detector_patterns=file_policy.detector_patterns,
    )


def _run_eval(args: argparse.Namespace) -> int:
    result = evaluate_suite(args.suite)
    if args.format == "json":
        print(render_evaluation_json(result), end="")
    else:
        print(render_evaluation_text(result), end="")
    return 0


def _render_report(report: ScanReport, output_format: str) -> str:
    if output_format == "json":
        return render_json(report)
    if output_format == "markdown":
        return render_markdown_summary(report)
    if output_format == "sarif":
        return render_sarif(report)
    return render_text(report)
