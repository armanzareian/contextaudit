from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from contextaudit.io import InputError, load_context_jsonl, load_policy


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


if __name__ == "__main__":
    unittest.main()
