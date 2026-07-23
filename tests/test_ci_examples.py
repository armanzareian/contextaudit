from __future__ import annotations

import unittest
from pathlib import Path

from contextaudit.io import InputError, load_context_jsonl, load_policy, load_suppressions
from contextaudit.scanner import scan_context
from contextaudit.suppressions import apply_suppressions


ROOT = Path(__file__).resolve().parents[1]


class CiExamplesTests(unittest.TestCase):
    def test_github_action_example_is_read_only_and_checkout_hardened(self) -> None:
        workflow = ROOT / "examples/github-actions/contextaudit-reusable.yml"

        text = workflow.read_text()

        self.assertIn("workflow_call:", text)
        self.assertIn("contents: read", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("args=(", text)
        self.assertIn('contextaudit "${args[@]}"', text)
        self.assertIn("suppressions_path", text)
        self.assertIn("--suppressions", text)
        self.assertIn("GITHUB_STEP_SUMMARY", text)
        self.assertNotIn("contents: write", text)
        self.assertNotIn("pull-requests: write", text)

    def test_ci_policy_examples_cover_pass_fail_and_malformed_inputs(self) -> None:
        chunks = load_context_jsonl(ROOT / "examples/support-pack/context.jsonl")

        passing_policy = load_policy(ROOT / "examples/ci/pass-policy.json")
        failing_policy = load_policy(ROOT / "examples/ci/fail-policy.json")

        self.assertEqual(scan_context(chunks, passing_policy).exit_code, 0)
        self.assertEqual(scan_context(chunks, failing_policy).exit_code, 1)
        with self.assertRaisesRegex(InputError, "invalid policy"):
            load_policy(ROOT / "examples/ci/malformed-policy.json")

    def test_ci_suppression_example_accepts_known_fixture_findings(self) -> None:
        chunks = load_context_jsonl(ROOT / "examples/support-pack/context.jsonl")
        failing_policy = load_policy(ROOT / "examples/ci/fail-policy.json")
        suppressions = load_suppressions(ROOT / "examples/ci/suppressions.json")

        report = apply_suppressions(scan_context(chunks, failing_policy), suppressions)

        self.assertEqual(report.exit_code, 0)
        self.assertEqual(report.suppressed_issue_count, 3)
        self.assertEqual(len(report.issues), 2)
        self.assertEqual(report.max_severity, "medium")


if __name__ == "__main__":
    unittest.main()
