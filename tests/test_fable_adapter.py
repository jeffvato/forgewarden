import json
import subprocess
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from swarm import fable_adapter as f


class FableAdapterTests(unittest.TestCase):
    def test_dynamic_schema_binds_job_and_is_strict(self):
        schema = f._schema("fable-" + "a" * 24)
        self.assertEqual(schema["properties"]["job_id"]["const"], "fable-" + "a" * 24)
        self.assertFalse(schema["additionalProperties"])

    def test_minimal_environment_has_no_credentials(self):
        env = f._minimal_env()
        self.assertEqual(set(env), {"HOME", "PATH", "LANG", "LC_ALL", "NO_COLOR", "PYTHONNOUSERSITE"})
        self.assertFalse(any("KEY" in key or "TOKEN" in key or "SECRET" in key for key in env))

    def test_context_redacts_secret_like_values(self):
        value = f._sanitize_context("token=abc123 password=hunter2 and /home/jeff/.credentials.json")
        self.assertNotIn("abc123", value)
        self.assertNotIn("hunter2", value)
        self.assertNotIn(".credentials.json", value)

    def test_budget_reservation_blocks_overage(self):
        with TemporaryDirectory() as temp:
            ledger = Path(temp) / "budget.json"
            with patch.object(f, "LEDGER", ledger):
                f._write_ledger({"version": 1, "hard_budget_usd": 100.0, "spent_usd": 70.0, "invocations": []})
                with self.assertRaises(f.FableAdapterError):
                    f._reserve(f.FableInvocation("fable-" + "b" * 24, target_usd=35.0))

    def test_budget_reservation_accounts_for_outstanding_reservations(self):
        with TemporaryDirectory() as temp:
            ledger = Path(temp) / "budget.json"
            with patch.object(f, "LEDGER", ledger):
                f._write_ledger({"version": 1, "hard_budget_usd": 100.0, "spent_usd": 0.0, "reserved_usd": 70.0, "invocations": []})
                with self.assertRaises(f.FableAdapterError):
                    f._reserve(f.FableInvocation("fable-" + "b" * 24, target_usd=35.0))

    def test_non_finite_budget_values_fail_closed(self):
        with TemporaryDirectory() as temp:
            ledger = Path(temp) / "budget.json"
            with patch.object(f, "LEDGER", ledger):
                f._write_ledger({"version": 1, "hard_budget_usd": 100.0, "spent_usd": 0.0, "invocations": []})
                with self.assertRaises(f.FableAdapterError):
                    f._reserve(f.FableInvocation("fable-" + "b" * 24, target_usd=float("nan")))

    def test_extract_and_validate_structured_result(self):
        job = "fable-" + "c" * 24
        inv = f.FableInvocation(job)
        payload = {"job_id": job, "model": f.MODEL, "total_cost_usd": 1.0, "findings": [], "hypotheses": [], "tests": [], "safe_correction_plan": "No change; gather lifecycle evidence.", "limitations": []}
        self.assertEqual(f._extract_result({"result": json.dumps(payload)}), payload)
        f._validate(payload, inv)
        payload["job_id"] = "fable-" + "d" * 24
        with self.assertRaises(f.FableAdapterError):
            f._validate(payload, inv)

    def test_subprocess_contract_is_read_only_and_fixed(self):
        job = "fable-" + "e" * 24
        inv = f.FableInvocation(job, target_usd=35.0)
        payload = {"job_id": job, "model": f.MODEL, "total_cost_usd": 0.0, "findings": [], "hypotheses": [], "tests": [], "safe_correction_plan": "Evidence only.", "limitations": []}
        completed = subprocess.CompletedProcess([], 0, json.dumps({"result": json.dumps(payload)}), "")
        with TemporaryDirectory() as temp:
            ledger = Path(temp) / "budget.json"
            evidence = Path(temp) / "evidence"
            with patch.object(f, "LEDGER", ledger), patch.object(f, "EVIDENCE_DIR", evidence), patch.object(f.subprocess, "run", return_value=completed) as run:
                self.assertEqual(f.run_fable(inv, context="sanitized context")["job_id"], job)
            args, kwargs = run.call_args
            self.assertEqual(args[0][0], str(f.CLAUDE))
            self.assertIn("claude-fable-5", args[0])
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["cwd"], f.PROJECT_ROOT)
            self.assertEqual(kwargs["env"], f._minimal_env())
            self.assertEqual(kwargs["timeout"], 300)
            self.assertTrue((evidence / f"{job}.json").is_file())

    def test_real_fake_cli_receives_exact_read_only_contract(self):
        job = "fable-" + "f" * 24
        inv = f.FableInvocation(job, target_usd=35.0)
        with TemporaryDirectory() as temp:
            root = Path(temp)
            proof = root / "proof.json"
            fake = root / "fake-claude.py"
            payload = {
                "job_id": job,
                "model": f.MODEL,
                "total_cost_usd": 2.75,
                "findings": [],
                "hypotheses": [],
                "tests": [],
                "safe_correction_plan": "Read-only evidence collection only.",
                "limitations": [],
            }
            fake.write_text(
                "#!/home/jeff/anaconda3/bin/python3\n"
                "import json, os, sys\n"
                f"proof = {str(proof)!r}\n"
                f"payload = {payload!r}\n"
                "args = sys.argv[1:]\n"
                "required = ['--model', 'claude-fable-5', '--output-format', 'json', '--json-schema', '--tools', '', '--permission-mode', 'plan', '--no-session-persistence', '--max-budget-usd', '35.0']\n"
                "if any(item not in args for item in required): sys.exit(9)\n"
                "json.dump({'argv': args, 'env_names': sorted(os.environ), 'payload': payload}, open(proof, 'w'))\n"
                "print(json.dumps({'result': json.dumps(payload)}))\n",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            with patch.object(f, "CLAUDE", fake), patch.object(f, "LEDGER", root / "budget.json"), patch.object(f, "EVIDENCE_DIR", root / "evidence"):
                result = f.run_fable(inv, context="token=do-not-send password=do-not-send")
            self.assertEqual(result["job_id"], job)
            observed = json.loads(proof.read_text(encoding="utf-8"))
            self.assertIn(f"job {job}", observed["argv"][1])
            self.assertNotIn("do-not-send", observed["argv"][1])
            self.assertEqual(observed["env_names"], sorted(f._minimal_env()))
            schema = json.loads(observed["argv"][observed["argv"].index("--json-schema") + 1])
            self.assertEqual(schema["properties"]["job_id"]["const"], job)
            self.assertFalse(schema["additionalProperties"])
            self.assertIn("claude-fable-5", observed["argv"])
            self.assertNotIn("--dangerously-skip-permissions", observed["argv"])
            self.assertNotIn("Bash", observed["argv"])
            self.assertNotIn("Edit", observed["argv"])
            self.assertNotIn("Write", observed["argv"])
            ledger = json.loads((root / "budget.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["spent_usd"], 2.75)
            self.assertEqual(ledger["reserved_usd"], 0.0)

    def test_real_fake_cli_wrong_job_or_model_fails_closed(self):
        with TemporaryDirectory() as temp:
            root = Path(temp)
            fake = root / "fake-claude.py"
            fake.write_text(
                "#!/home/jeff/anaconda3/bin/python3\n"
                "import json, sys\n"
                "payload = {'job_id': 'fable-' + '0'*24, 'model': 'wrong-model', 'total_cost_usd': 1.0, 'findings': [], 'hypotheses': [], 'tests': [], 'safe_correction_plan': 'x', 'limitations': []}\n"
                "print(json.dumps({'result': json.dumps(payload)}))\n",
                encoding="utf-8",
            )
            fake.chmod(0o700)
            job = "fable-" + "1" * 24
            with patch.object(f, "CLAUDE", fake), patch.object(f, "LEDGER", root / "budget.json"), patch.object(f, "EVIDENCE_DIR", root / "evidence"):
                with self.assertRaises(f.FableAdapterError):
                    f.run_fable(f.FableInvocation(job), context="sanitized context")
            ledger = json.loads((root / "budget.json").read_text(encoding="utf-8"))
            self.assertEqual(ledger["reserved_usd"], 0.0)
            self.assertEqual(ledger["spent_usd"], 0.0)


if __name__ == "__main__":
    unittest.main()
