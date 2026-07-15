from __future__ import annotations

import json

from contextaudit import __version__
from contextaudit.models import DETECTORS, Issue, ScanReport

SARIF_SCHEMA_URL = "https://json.schemastore.org/sarif-2.1.0.json"
SARIF_LEVELS = {
    "low": "note",
    "medium": "warning",
    "high": "error",
    "critical": "error",
}
DETECTOR_DESCRIPTIONS = {
    "instruction_override": (
        "Context text contains instruction-like language that may override model behavior."
    ),
    "untrusted_instruction": "Untrusted context contains instruction or authority-like language.",
    "sensitive_data": "Context text contains sensitive-looking key or credential material.",
    "oversize_chunk": "Context chunk exceeds the configured maximum character count.",
    "duplicate_text": "Context chunk duplicates text already present in the context pack.",
    "missing_citation": "Answer citation does not match a supplied context chunk ID.",
    "weak_sentence_support": "Answer sentence has weak lexical support from cited context.",
    "uncited_risky_context": "Answer overlaps with risky context that was not cited.",
}


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


def render_sarif(report: ScanReport) -> str:
    payload = {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ContextAudit",
                        "informationUri": "https://github.com/armanzareian/contextaudit",
                        "semanticVersion": __version__,
                        "rules": [_sarif_rule(detector) for detector in _detectors_in(report)],
                    }
                },
                "results": [_sarif_result(issue) for issue in report.issues],
                "properties": {
                    "score": report.score,
                    "issue_count": len(report.issues),
                    "max_severity": report.max_severity,
                    "policy": report.policy.to_dict(),
                },
            }
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def render_text(report: ScanReport) -> str:
    lines = [
        "ContextAudit report",
        f"Score: {report.score}/100",
        f"Issues: {len(report.issues)}",
        f"Max severity: {report.max_severity}",
        f"Policy: fail on {report.policy.fail_on}; max chunk chars {report.policy.max_chunk_chars}",
    ]
    if report.summary:
        lines.append("")
        lines.append("Issue summary")
        for detector, count in report.summary.items():
            lines.append(f"- {detector}: {count}")
    if report.issues:
        lines.append("")
        lines.append("Issues")
        for issue in report.issues:
            lines.append(
                f"- [{issue.severity}] {issue.detector} {issue.chunk_id} "
                f"({issue.source}) fingerprint {issue.fingerprint}: "
                f"{issue.message} Evidence: {issue.evidence}"
            )
    return "\n".join(lines) + "\n"


def _detectors_in(report: ScanReport) -> list[str]:
    present = {issue.detector for issue in report.issues}
    return [detector for detector in DETECTORS if detector in present]


def _sarif_rule(detector: str) -> dict[str, object]:
    description = DETECTOR_DESCRIPTIONS.get(detector, "ContextAudit finding.")
    return {
        "id": detector,
        "name": detector.replace("_", " "),
        "shortDescription": {"text": description},
        "fullDescription": {"text": description},
        "helpUri": "https://github.com/armanzareian/contextaudit#detectors",
    }


def _sarif_result(issue: Issue) -> dict[str, object]:
    return {
        "ruleId": issue.detector,
        "level": SARIF_LEVELS[issue.severity],
        "message": {"text": issue.message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": issue.source},
                    "region": {
                        "snippet": {"text": issue.evidence},
                    },
                },
                "logicalLocations": [
                    {
                        "name": issue.chunk_id,
                        "fullyQualifiedName": f"{issue.source}#{issue.chunk_id}",
                    }
                ],
            }
        ],
        "partialFingerprints": {"contextaudit": issue.fingerprint},
        "properties": {
            "chunk_id": issue.chunk_id,
            "source": issue.source,
            "detector": issue.detector,
            "severity": issue.severity,
            "fingerprint": issue.fingerprint,
            "evidence": issue.evidence,
        },
    }
