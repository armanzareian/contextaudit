from __future__ import annotations

import unittest
from pathlib import Path

from contextaudit.io import InputError, load_context_jsonl, load_policy
from contextaudit.scanner import scan_context


ROOT = Path(__file__).resolve().parents[1]


class CiExamplesTests(unittest.TestCase):
    def test_github_action_example_is_read_only_and_checkout_hardened(self) -> None:
        workflow = ROOT / "examples/github-actions/contextaudit-reusable.yml"

        text = workflow.read_text()

        self.assertIn("workflow_call:", text)
        self.assertIn("contents: read", text)
        self.assertIn("persist-credentials: false", text)
        self.assertIn("contextaudit scan", text)
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


if __name__ == "__main__":
    unittest.main()
