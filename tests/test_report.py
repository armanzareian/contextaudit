from __future__ import annotations

import json
import unittest

from contextaudit.models import Issue, Policy, ScanReport
from contextaudit.report import render_json, render_text


class ReportTests(unittest.TestCase):
    def test_json_report_has_machine_readable_issues_and_policy(self) -> None:
        report = ScanReport(
            score=65,
            issues=[
                Issue(
                    chunk_id="c1",
                    source="kb://x",
                    detector="instruction_override",
                    severity="high",
                    message="Instruction-like text found.",
                    evidence="Ignore previous instructions",
                )
            ],
            summary={"instruction_override": 1},
            policy=Policy(fail_on="high"),
        )

        payload = json.loads(render_json(report))

        self.assertEqual(payload["score"], 65)
        self.assertEqual(payload["policy"]["fail_on"], "high")
        self.assertEqual(payload["issues"][0]["detector"], "instruction_override")
        self.assertEqual(len(payload["issues"][0]["fingerprint"]), 16)
        self.assertEqual(payload["exit_code"], 1)

    def test_text_report_summarizes_score_and_issue_locations(self) -> None:
        report = ScanReport(
            score=80,
            issues=[
                Issue(
                    chunk_id="c1",
                    source="kb://x",
                    detector="sensitive_data",
                    severity="high",
                    message="Sensitive-looking value found.",
                    evidence="password = redacted",
                )
            ],
            summary={"sensitive_data": 1},
            policy=Policy(fail_on="critical"),
        )

        text = render_text(report)

        self.assertIn("ContextAudit report", text)
        self.assertIn("Score: 80/100", text)
        self.assertIn("c1", text)
        self.assertIn("sensitive_data", text)
        self.assertIn("fingerprint", text)


if __name__ == "__main__":
    unittest.main()
