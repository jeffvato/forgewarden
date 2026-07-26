import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from swarm import claude_adapter as claude


class ClaudeAdapterTests(unittest.TestCase):
    def test_default_is_sonnet_and_models_are_narrowly_allowlisted(self):
        self.assertEqual(claude.DEFAULT_MODEL, "sonnet")
        self.assertEqual(claude.ALLOWED_MODELS, {"sonnet", "opus", "haiku"})
        self.assertEqual(claude.resolve_model("sonnet"), "claude-sonnet-4-6")
        self.assertEqual(claude.resolve_model("opus"), "claude-opus-4-5")
        self.assertEqual(claude.resolve_model("haiku"), "claude-haiku-4-5-20251001")

    def test_context_is_required_bounded_and_redacted(self):
        with self.assertRaises(ValueError):
            claude.sanitize_context(" ")
        result = claude.sanitize_context("token=secret password=hunter2 /home/jeff/.credentials.json")
        self.assertNotIn("secret", result)
        self.assertNotIn("hunter2", result)
        self.assertNotIn(".credentials.json", result)
        self.assertLessEqual(len(result.encode()), claude.MAX_CONTEXT_BYTES)

    def test_schema_binds_job_and_model(self):
        job = "claude-" + "a" * 24
        value = claude.schema(job, "sonnet")
        self.assertEqual(value["properties"]["job_id"]["const"], job)
        self.assertEqual(value["properties"]["model"]["const"], "sonnet")
        self.assertFalse(value["additionalProperties"])

    def test_fake_cli_receives_only_read_only_contract(self):
        job = "claude-" + "b" * 24
        with TemporaryDirectory() as temp:
            root = Path(temp)
            proof = root / "proof.json"
            fake = root / "fake-claude.py"
            payload = {"job_id": job, "model": "claude-sonnet-4-6", "findings": [], "recommendations": [], "limitations": []}
            fake.write_text(
                "#!/home/jeff/anaconda3/bin/python3\n"
                "import json, os, sys\n"
                f"proof = {str(proof)!r}\n"
                f"payload = {payload!r}\n"
                "args = sys.argv[1:]\n"
                "required = ['--model', 'claude-sonnet-4-6', '--output-format', 'json', '--json-schema', '--tools', '', '--permission-mode', 'plan', '--no-session-persistence', '--max-turns', '3', '--strict-mcp-config', '--disable-slash-commands', '--no-chrome']\n"
                "if any(item not in args for item in required): sys.exit(9)\n"
                "json.dump({'args': args, 'env_names': sorted(os.environ)}, open(proof, 'w'))\n"
                "print(json.dumps({'result': json.dumps(payload)}))\n",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            with patch.object(claude, "CLAUDE", fake):
                result = claude.run_claude(job, "token=do-not-send password=do-not-send", model="sonnet")
            self.assertEqual(result["job_id"], job)
            observed = json.loads(proof.read_text(encoding="utf-8"))
            self.assertNotIn("do-not-send", observed["args"][1])
            self.assertEqual(observed["env_names"], sorted(claude.minimal_environment()))
            schema_text = observed["args"][observed["args"].index("--json-schema") + 1]
            self.assertEqual(json.loads(schema_text)["properties"]["job_id"]["const"], job)
            self.assertNotIn("--dangerously-skip-permissions", observed["args"])
            self.assertNotIn("Bash", observed["args"])
            self.assertNotIn("Edit", observed["args"])
            self.assertNotIn("Write", observed["args"])
            self.assertIn("--strict-mcp-config", observed["args"])
            self.assertIn("--disable-slash-commands", observed["args"])
            self.assertIn("--no-chrome", observed["args"])

    def test_invalid_model_and_wrong_result_fail_closed(self):
        job = "claude-" + "c" * 24
        with self.assertRaises(ValueError):
            claude.run_claude(job, "context", model="sonnet-5")
        payload = {"job_id": job, "model": "claude-opus-4-5", "findings": [], "recommendations": [], "limitations": []}
        with self.assertRaises(claude.ClaudeAdapterError):
            claude.validate_result(payload, job, "sonnet")

    def test_process_failure_is_reported_without_writing_evidence(self):
        job = "claude-" + "d" * 24
        completed = subprocess.CompletedProcess([], 7, "", "provider failure")
        with patch.object(claude, "CLAUDE", Path("/home/jeff/.local/bin/claude")), patch.object(claude.subprocess, "run", return_value=completed):
            with self.assertRaises(claude.ClaudeAdapterError):
                claude.run_claude(job, "sanitized context")


if __name__ == "__main__":
    unittest.main()
