from __future__ import annotations

from collections import Counter
from collections.abc import Iterable

from contextaudit.models import DETECTORS, Issue, ScanReport

PENALTY_BY_SEVERITY = {"low": 5, "medium": 15, "high": 30, "critical": 60}
DETECTOR_ORDER = {detector: index for index, detector in enumerate(DETECTORS)}


def apply_suppressions(report: ScanReport, fingerprints: Iterable[str]) -> ScanReport:
    suppression_set = frozenset(fingerprints)
    if not suppression_set:
        return report

    kept_issues = [issue for issue in report.issues if issue.fingerprint not in suppression_set]
    suppressed_count = len(report.issues) - len(kept_issues)
    if suppressed_count == 0:
        return report

    return ScanReport(
        score=_score(kept_issues),
        issues=kept_issues,
        summary=_summary(kept_issues),
        policy=report.policy,
        suppressed_issue_count=report.suppressed_issue_count + suppressed_count,
    )


def _summary(issues: list[Issue]) -> dict[str, int]:
    return dict(
        sorted(
            Counter(issue.detector for issue in issues).items(),
            key=lambda item: (DETECTOR_ORDER.get(item[0], 99), item[0]),
        )
    )


def _score(issues: list[Issue]) -> int:
    return max(0, 100 - sum(PENALTY_BY_SEVERITY[issue.severity] for issue in issues))
