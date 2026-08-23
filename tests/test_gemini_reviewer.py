import json
import shutil
import tempfile
import unittest
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

from swarm.adapters import GeminiAdapter, ResourceLimits
from swarm.core import SwarmError, validate_contract


class GeminiReviewContractTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="gemini-contract-"))
        self.snapshot = self.root / "snapshot"
        self.snapshot.mkdir()
        self.schema = Path(__file__).resolve().parents[1] / "schemas/gemini-review.schema.json"
        self.job = "controlled-baseline-contract1234"
        self.commit = "a" * 40

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def payload(self):
        return {
            "job_id": self.job,
            "reviewed_commit": self.commit,
            "verdict": "APPROVE",
            "risk": "LOW",
            "blocking_findings": [],
            "non_blocking_notes": [],
            "tests_missing": [],
            "reasoning_summary": "narrow retained fixture review",
            "proposed_rules": [],
        }

    def test_dynamic_schema_binds_job_commit_and_rejects_extra_alias(self):
        adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
        schema = adapter._job_schema(self.job, self.commit)
        self.assertEqual(schema["additionalProperties"], False)
        self.assertEqual(schema["properties"]["job_id"]["const"], self.job)
        self.assertEqual(schema["properties"]["reviewed_commit"]["const"], self.commit)
        self.assertIn("tests_missing", schema["required"])
        self.assertNotIn("missing_tests", schema["required"])

    def test_invalid_reviewer_payloads_fail_closed(self):
        cases = []
        base = self.payload()
        missing_job = dict(base); missing_job.pop("job_id"); cases.append(missing_job)
        wrong_job = dict(base); wrong_job["job_id"] = "other-job"; cases.append(wrong_job)
        wrong_commit = dict(base); wrong_commit["reviewed_commit"] = "b" * 40; cases.append(wrong_commit)
        missing_fields = dict(base); missing_fields.pop("reasoning_summary"); cases.append(missing_fields)
        alias = dict(base); alias.pop("tests_missing"); alias["missing_tests"] = []; cases.append(alias)
        extra = dict(base); extra["unexpected"] = True; cases.append(extra)
        bad_verdict = dict(base); bad_verdict["verdict"] = "YES"; cases.append(bad_verdict)
        bad_risk = dict(base); bad_risk["risk"] = "NONE"; cases.append(bad_risk)
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(SwarmError):
                    validate_contract(payload, "gemini", expected_job_id=self.job, expected_commit=self.commit)

    def test_extracts_antigravity_structured_output_envelope(self):
        payload = self.payload()
        wrapped = json.dumps({"status": "SUCCESS", "response": "prose", "structured_output": payload})
        with patch("swarm.adapters.limited_run", return_value=CompletedProcess([], 0, wrapped, "")):
            adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
            self.assertEqual(adapter.run(self.snapshot, self.job, self.commit, "review evidence", formatting_retry=False), payload)

    def test_approve_with_blocking_findings_or_missing_tests_is_rejected(self):
        for key, value in (("blocking_findings", [{"finding": "block"}]), ("tests_missing", ["test"] )):
            payload = self.payload()
            payload[key] = value
            fake = self.root / "fake-output.json"
            fake.write_text(json.dumps(payload), encoding="utf-8")
            adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
            with patch("swarm.adapters.limited_run", return_value=CompletedProcess([], 0, fake.read_text(), "")):
                with self.assertRaises(SwarmError):
                    adapter.run(self.snapshot, self.job, self.commit, "review evidence", formatting_retry=False)

    def test_one_formatting_retry_preserves_invalid_payload_and_accepts_exact_response(self):
        invalid = dict(self.payload())
        invalid.pop("tests_missing")
        invalid["missing_tests"] = []
        valid = self.payload()
        calls = []

        def fake_run(command, cwd, prompt, limits, env, **kwargs):
            calls.append((command, prompt))
            response = invalid if len(calls) == 1 else valid
            return CompletedProcess(command, 0, json.dumps(response), "")

        adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
        with patch("swarm.adapters.limited_run", side_effect=fake_run):
            result = adapter.run(self.snapshot, self.job, self.commit, "review evidence")
        self.assertEqual(result, valid)
        self.assertEqual(len(adapter.last_attempts), 2)
        self.assertEqual(adapter.last_attempts[0]["validation"], "FAILED")
        self.assertIn("missing_tests", adapter.last_attempts[0]["payload"])
        self.assertEqual(adapter.last_attempts[1]["validation"], "PASSED")
        self.assertEqual(calls[0][1], "")
        self.assertIn('"tests_missing": []', calls[0][0][1])
        self.assertIn("formatting-only retry", calls[1][0][1])
        self.assertIn(self.commit, calls[1][0][1])

    def test_external_review_uses_compatible_json_envelope_and_local_validation(self):
        calls = []
        def fake_run(command, cwd, prompt, limits, env, **kwargs):
            calls.append((command, kwargs))
            return CompletedProcess(command, 0, json.dumps(self.payload()), "")
        adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy", allow_external_review=True)
        with patch("swarm.adapters.limited_run", side_effect=fake_run):
            self.assertEqual(adapter.run(self.snapshot, self.job, self.commit, "review evidence"), self.payload())
        command, kwargs = calls[0]
        self.assertTrue(command[1].startswith("--print="))
        self.assertNotIn("--prompt", command)
        self.assertIn("--agent", command)
        self.assertEqual(command[command.index("--agent") + 1], "code-review-agent")
        self.assertIn("--disable-slash-commands", command)
        self.assertNotIn("--model", command)
        self.assertIn("--output-format", command)
        self.assertEqual(command[command.index("--output-format") + 1], "json")
        self.assertNotIn("--json-schema", command)
        self.assertTrue(kwargs["use_cgroup"])
        self.assertFalse(kwargs["network_isolated"])

    def test_provider_json_envelope_response_is_parsed_and_validated(self):
        envelope = {"status": "SUCCESS", "response": json.dumps(self.payload()) + "\n"}
        with patch("swarm.adapters.limited_run", return_value=CompletedProcess([], 0, json.dumps(envelope), "")):
            adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
            self.assertEqual(adapter.run(self.snapshot, self.job, self.commit, "review evidence", formatting_retry=False), self.payload())

    def test_provider_error_envelope_is_reported_without_fake_review(self):
        envelope = {"status": "ERROR", "response": "", "error": "provider unavailable"}
        with patch("swarm.adapters.limited_run", return_value=CompletedProcess([], 0, json.dumps(envelope), "")):
            adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
            with self.assertRaisesRegex(SwarmError, "provider returned status ERROR"):
                adapter.run(self.snapshot, self.job, self.commit, "review evidence", formatting_retry=False)

    def test_provider_envelope_with_mismatched_payload_fails_local_contract(self):
        payload = self.payload(); payload["reviewed_commit"] = "b" * 40
        envelope = {"status": "SUCCESS", "response": json.dumps(payload)}
        with patch("swarm.adapters.limited_run", return_value=CompletedProcess([], 0, json.dumps(envelope), "")):
            adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
            with self.assertRaisesRegex(SwarmError, "reviewed commit mismatch"):
                adapter.run(self.snapshot, self.job, self.commit, "review evidence", formatting_retry=False)

    def test_default_review_remains_network_isolated(self):
        calls = []
        def fake_run(command, cwd, prompt, limits, env, **kwargs):
            calls.append(kwargs)
            return CompletedProcess(command, 0, json.dumps(self.payload()), "")
        adapter = GeminiAdapter(self.schema, ResourceLimits(), "fake-agy")
        with patch("swarm.adapters.limited_run", side_effect=fake_run):
            adapter.run(self.snapshot, self.job, self.commit, "review evidence")
        self.assertTrue(calls[0]["network_isolated"])


if __name__ == "__main__":
    unittest.main()
