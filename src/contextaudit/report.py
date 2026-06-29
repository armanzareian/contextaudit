from __future__ import annotations

import json

from contextaudit.models import ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True) + "\n"


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
