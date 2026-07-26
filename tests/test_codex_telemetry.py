import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from swarm.adapters import CodexAdapter, CodexRunEvidence, ResourceLimits, WriterInvocationSpec
from swarm.core import SwarmError


class CodexTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="codex-telemetry-"))
        (self.root / "value.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        self.evidence_dir = self.root / "evidence"
        self.schema = Path(__file__).resolve().parents[1] / "schemas/codex-result.schema.json"
        self.spec = WriterInvocationSpec(
            "codex-telemetry-test1234", self.root, self.root, "value.py", "value.py",
            "value() returns 2", "assert value() == 2", ("value.py",),
        )

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _run(self, payload=None, stdout=""):
        def limited(command, cwd, prompt, limits, env, **kwargs):
            if payload is not None:
                Path(command[command.index("--output-last-message") + 1]).write_text(json.dumps(payload), encoding="utf-8")
            return subprocess.CompletedProcess(command, 0, stdout, "")
        adapter = CodexAdapter(self.schema, ResourceLimits(timeout_seconds=5), "/not-a-real-codex", self.evidence_dir)
        with patch("swarm.adapters.limited_run", side_effect=limited), patch("swarm.adapters._codex_version", return_value="codex-test"):
            result = adapter.run(self.spec)
        return adapter, result

    def _payload(self, changed=None):
        return {"job_id": self.spec.job_id, "status": "FIXED", "root_cause": "x", "summary": "x", "changed_files": changed or [], "tests_added_or_changed": [], "commands_run": [], "remaining_risks": [], "requires_human_approval": False}

    def test_no_edit_response_is_preserved_and_persisted_before_cleanup(self):
        adapter, result = self._run(self._payload())
        adapter.record_actual_paths([])
        evidence = json.loads((self.evidence_dir / f"{self.spec.job_id}.json").read_text())
        self.assertEqual(result["changed_files"], [])
        self.assertEqual(evidence["claimed_changed_files"], [])
        self.assertEqual(evidence["actual_normalized_changed_paths"], [])
        self.assertIn('"changed_files": []', evidence["sanitized_final_response"])
        self.assertTrue(Path(evidence["persisted_path"]).is_file())

    def test_write_denial_is_preserved_without_unrestricted_output(self):
        stdout = json.dumps({"type": "item.completed", "item": {"type": "error", "message": "Permission denied writing token=SECRET_VALUE"}}) + "\n"
        adapter, _ = self._run(self._payload(), stdout)
        evidence = json.loads((self.evidence_dir / f"{self.spec.job_id}.json").read_text())
        self.assertTrue(evidence["sandbox_write_denials"])
        self.assertNotIn("SECRET_VALUE", json.dumps(evidence))
        self.assertEqual(adapter.last_evidence.tool_commands, [])

    def test_secret_like_prompt_values_are_redacted(self):
        adapter, _ = self._run(self._payload())
        adapter.last_evidence.sanitized_prompt = "api_key=[REDACTED]"
        adapter.persist_evidence()
        evidence = json.loads((self.evidence_dir / f"{self.spec.job_id}.json").read_text())
        self.assertNotIn("SECRET_VALUE", json.dumps(evidence))
        self.assertIn("[REDACTED]", evidence["sanitized_prompt"])

    def test_missing_final_response_is_explicitly_recorded(self):
        def limited(command, cwd, prompt, limits, env, **kwargs):
            return subprocess.CompletedProcess(command, 0, "", "")
        adapter = CodexAdapter(self.schema, ResourceLimits(timeout_seconds=5), "/not-a-real-codex", self.evidence_dir)
        with patch("swarm.adapters.limited_run", side_effect=limited), patch("swarm.adapters._codex_version", return_value="codex-test"), self.assertRaises(SwarmError):
            adapter.run(self.spec)
        evidence = json.loads((self.evidence_dir / f"{self.spec.job_id}.json").read_text())
        self.assertEqual(evidence["schema_validation"], "MISSING_FINAL_RESPONSE")
        self.assertEqual(evidence["sanitized_final_response"], "[MISSING_FINAL_RESPONSE]")

    def test_telemetry_persistence_failure_blocks_processing(self):
        adapter = CodexAdapter(self.schema, ResourceLimits(timeout_seconds=5), "/not-a-real-codex", self.evidence_dir)
        with patch.object(adapter, "persist_evidence", side_effect=SwarmError("telemetry persistence failed")):
            with self.assertRaises(SwarmError):
                adapter.last_evidence = CodexRunEvidence("job", "v", [], str(self.root), [], "h", "p", str(self.root / "value.py"))
                adapter.persist_evidence()

    def test_telemetry_evidence_directory_symlink_is_rejected(self):
        real = self.root / "real-evidence"
        real.mkdir()
        linked = self.root / "linked-evidence"
        linked.symlink_to(real, target_is_directory=True)
        adapter = CodexAdapter(self.schema, ResourceLimits(timeout_seconds=5), "/not-a-real-codex", linked)
        adapter.last_evidence = CodexRunEvidence("job", "v", [], str(self.root), [], "h", "p", str(self.root / "value.py"))
        with self.assertRaises(SwarmError):
            adapter.persist_evidence()


if __name__ == "__main__":
    unittest.main()
