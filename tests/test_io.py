from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from contextaudit.io import InputError, load_answer, load_context_jsonl, load_policy


class IoTests(unittest.TestCase):
    def test_load_context_jsonl_validates_required_fields(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "context.jsonl"
            path.write_text(json.dumps({"chunk_id": "a", "source": "kb://a"}) + "\n")

            with self.assertRaisesRegex(InputError, "text"):
                load_context_jsonl(path)

    def test_load_context_jsonl_reads_trusted_default_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "context.jsonl"
            path.write_text(
                json.dumps(
                    {
                        "chunk_id": "a",
                        "source": "kb://a",
                        "text": "Refund policy",
                        "metadata": {"section": "returns"},
                    }
                )
                + "\n"
            )

            chunks = load_context_jsonl(path)

        self.assertEqual(len(chunks), 1)
        self.assertTrue(chunks[0].trusted)
        self.assertEqual(chunks[0].metadata, {"section": "returns"})

    def test_load_policy_allows_threshold_and_max_chunk_override(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.json"
            path.write_text(json.dumps({"fail_on": "medium", "max_chunk_chars": 42}))

            policy = load_policy(path)

        self.assertEqual(policy.fail_on, "medium")
        self.assertEqual(policy.max_chunk_chars, 42)

    def test_load_policy_reads_detector_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "policy.json"
            path.write_text(
                json.dumps(
                    {
                        "disabled_detectors": ["duplicate_text"],
                        "severity_overrides": {"sensitive_data": "critical"},
                        "allowlisted_sources": ["kb://trusted-*"],
                        "detector_patterns": {
                            "sensitive_data": [r"\btenant secret\b\s+[\w-]+"]
                        },
                    }
                )
            )

            policy = load_policy(path)

        self.assertEqual(policy.disabled_detectors, ("duplicate_text",))
        self.assertEqual(policy.severity_overrides, {"sensitive_data": "critical"})
        self.assertEqual(policy.allowlisted_sources, ("kb://trusted-*",))
        self.assertEqual(
            policy.detector_patterns,
            {"sensitive_data": (r"\btenant secret\b\s+[\w-]+",)},
        )

    def test_load_policy_rejects_malformed_detector_controls(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            unknown_detector = Path(tmpdir) / "unknown.json"
            unknown_detector.write_text(json.dumps({"disabled_detectors": ["unknown"]}))
            bad_override = Path(tmpdir) / "override.json"
            bad_override.write_text(
                json.dumps({"severity_overrides": {"sensitive_data": "urgent"}})
            )
            bad_pattern = Path(tmpdir) / "pattern.json"
            bad_pattern.write_text(
                json.dumps({"detector_patterns": {"sensitive_data": ["("]}})
            )

            with self.assertRaisesRegex(InputError, "unknown detector"):
                load_policy(unknown_detector)
            with self.assertRaisesRegex(InputError, "severity"):
                load_policy(bad_override)
            with self.assertRaisesRegex(InputError, "invalid regex"):
                load_policy(bad_pattern)

    def test_load_answer_reads_answer_and_citation_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "answer.json"
            path.write_text(json.dumps({"answer": "Refund details.", "citations": ["refunds"]}))

            answer = load_answer(path)

        self.assertEqual(answer.answer, "Refund details.")
        self.assertEqual(answer.citations, ("refunds",))

    def test_load_answer_rejects_malformed_citations(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "answer.json"
            path.write_text(json.dumps({"answer": "Refund details.", "citations": [""]}))

            with self.assertRaisesRegex(InputError, "citations"):
                load_answer(path)


if __name__ == "__main__":
    unittest.main()
