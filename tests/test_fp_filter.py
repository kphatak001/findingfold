"""Tests for the false positive filter."""

import json
import unittest
from unittest.mock import patch

from findingfold.fp_filter import (
    filter_false_positives, _summarize_finding, _parse_llm_json, BATCH_SIZE,
)


class TestSummarizeFinding(unittest.TestCase):
    def test_extracts_key_fields(self):
        f = {
            "Id": "f-1", "Title": "Open port 22",
            "Severity": {"Label": "HIGH"}, "GeneratorId": "aws/config",
            "Workflow": {"Status": "NEW"},
            "Resources": [{"Type": "AwsEc2SecurityGroup", "Id": "sg-abc",
                           "Tags": {"env": "prod", "_findingfold_ami": "skip"}}],
        }
        s = _summarize_finding(f)
        self.assertEqual(s["id"], "f-1")
        self.assertEqual(s["severity"], "HIGH")
        # _findingfold tags should be excluded
        self.assertNotIn("_findingfold_ami", s["resources"][0].get("tags", {}))
        self.assertIn("env", s["resources"][0]["tags"])

    def test_handles_no_tags(self):
        f = {"Id": "f-2", "Title": "X", "Severity": {}, "GeneratorId": "",
             "Workflow": {}, "Resources": [{"Type": "AwsS3Bucket", "Id": "b"}]}
        s = _summarize_finding(f)
        self.assertNotIn("tags", s["resources"][0])


class TestParseLlmJson(unittest.TestCase):
    def test_plain_array(self):
        r = _parse_llm_json('[{"id": "a", "fp": true, "reason": "dev"}]')
        self.assertTrue(r[0]["fp"])

    def test_fenced_json(self):
        r = _parse_llm_json('Analysis:\n```json\n[{"id": "b", "fp": false, "reason": "real"}]\n```')
        self.assertFalse(r[0]["fp"])

    def test_raises_on_garbage(self):
        with self.assertRaises(ValueError):
            _parse_llm_json("no json here")


class TestFilterFalsePositives(unittest.TestCase):
    def _findings(self, n):
        return [{"Id": f"f-{i}", "Title": f"Finding {i}",
                 "Severity": {"Label": "MEDIUM"}, "GeneratorId": "test",
                 "Workflow": {"Status": "NEW"}, "Resources": []}
                for i in range(n)]

    @patch("findingfold.fp_filter._get_backend")
    def test_removes_fps(self, mock_get):
        # LLM says f-1 is FP, f-0 is real
        mock_get.return_value = lambda prompt: [
            {"id": "f-0", "fp": False, "reason": "real"},
            {"id": "f-1", "fp": True, "reason": "dev resource"},
        ]
        kept, removed = filter_false_positives(self._findings(2), backend="anthropic")
        self.assertEqual(len(kept), 1)
        self.assertEqual(len(removed), 1)
        self.assertEqual(kept[0]["Id"], "f-0")
        self.assertEqual(removed[0]["Id"], "f-1")

    @patch("findingfold.fp_filter._get_backend")
    def test_keeps_all_on_error(self, mock_get):
        # LLM throws — all findings should be kept (conservative)
        mock_get.return_value = lambda prompt: (_ for _ in ()).throw(RuntimeError("API down"))
        kept, removed = filter_false_positives(self._findings(3), backend="anthropic")
        self.assertEqual(len(kept), 3)
        self.assertEqual(len(removed), 0)

    @patch("findingfold.fp_filter._get_backend")
    def test_batching(self, mock_get):
        call_count = [0]
        def mock_call(prompt):
            call_count[0] += 1
            # Parse finding IDs from prompt to return matching results
            data = json.loads(prompt.split("\n\n", 1)[1])
            return [{"id": d["id"], "fp": False, "reason": "ok"} for d in data]
        mock_get.return_value = mock_call

        n = BATCH_SIZE + 5
        kept, removed = filter_false_positives(self._findings(n), backend="anthropic")
        self.assertEqual(len(kept), n)
        self.assertEqual(call_count[0], 2)  # should be 2 batches


if __name__ == "__main__":
    unittest.main()
