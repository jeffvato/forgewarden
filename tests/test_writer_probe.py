import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from swarm.writer_probe import PROBE_FILES, TEST_COMMAND, run_writer_probe
from swarm.adapters import _minimal_test_environment


FIXTURE = Path(__file__).parent / "fixtures" / "codex_writer_probe"


def _bus_available():
    uid = os.getuid()
    return (
        shutil.which("systemd-run") is not None
        and (Path("/run/user") / str(uid) / "bus").is_socket()
        and subprocess.run(["systemctl", "--user", "show-environment"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False).returncode == 0
    )


@unittest.skipUnless(_bus_available(), "user systemd bus is unavailable in this execution context")
class WriterProbeProcessTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="writer-probe-tests-"))

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def _fake(self, mode="success"):
        path = self.root / f"fake-{mode}"
        extra = "pathlib.Path('unauthorized.py').write_text('x = 1\\n')\n" if mode == "unauthorized" else ""
        if mode == "cache":
            extra += "pathlib.Path('__pycache__').mkdir(); pathlib.Path('__pycache__/bad.pyc').write_bytes(b'bad')\n"
        claimed = "['test_value.py']" if mode == "claimed-mismatch" else "['value.py']"
        path.write_text(
            "#!/usr/bin/env python3\n"
            "import json, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "assert not pathlib.Path('.git').exists()\n"
            "prompt = args[-1]\n"
            "job_id = prompt.split('canonical job ID is ', 1)[1].split('.', 1)[0]\n"
            "pathlib.Path('value.py').write_text('def value():\\n    return 2\\n')\n"
            + extra
            + f"out = pathlib.Path(args[args.index('--output-last-message') + 1])\n"
            + f"out.write_text(json.dumps({{'job_id': job_id, 'status': 'FIXED', 'root_cause': 'fixture', 'summary': 'fixture', 'changed_files': {claimed}, 'tests_added_or_changed': [], 'commands_run': [{{'command': 'pytest', 'exit_code': 0}}], 'remaining_risks': [], 'requires_human_approval': False}}))\n",
            encoding="utf-8",
        )
        path.chmod(0o700)
        return path

    def test_fixture_integrity_and_seeded_assertion_failure(self):
        for name in PROBE_FILES:
            text = (FIXTURE / name).read_text(encoding="utf-8")
            self.assertNotIn("\\n", text)
            compile(text, name, "exec")
        disposable_fixture = self.root / "fixture"
        shutil.copytree(FIXTURE, disposable_fixture, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache"))
        external_cache = self.root / "fixture-pycache"
        import_env = _minimal_test_environment({"PYTHONDONTWRITEBYTECODE": "0", "PYTHONPYCACHEPREFIX": str(external_cache)})
        imported = subprocess.run(["/home/jeff/anaconda3/bin/python3", "-c", "import value"], cwd=disposable_fixture, env=import_env, text=True, capture_output=True, check=False)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertTrue(any(external_cache.rglob("*.pyc")))
        self.assertFalse(any(disposable_fixture.rglob("__pycache__")))
        collected = subprocess.run([*TEST_COMMAND, "--collect-only"], cwd=disposable_fixture, env=_minimal_test_environment({"PYTHONPYCACHEPREFIX": str(external_cache)}), text=True, capture_output=True, check=False)
        self.assertEqual(collected.returncode, 0, collected.stderr)
        seeded = subprocess.run(TEST_COMMAND, cwd=disposable_fixture, env=_minimal_test_environment({"PYTHONPYCACHEPREFIX": str(external_cache)}), text=True, capture_output=True, check=False)
        self.assertNotEqual(seeded.returncode, 0)
        self.assertIn("AssertionError", seeded.stdout + seeded.stderr)
        self.assertNotIn("SyntaxError", seeded.stdout + seeded.stderr)
        self.assertNotIn("ImportError", seeded.stdout + seeded.stderr)
        self.assertFalse((disposable_fixture / ".pytest_cache").exists())

    def test_orchestrator_detects_edit_and_creates_exact_commit_without_hooks(self):
        audit = self.root / "audit.jsonl"
        result = run_writer_probe(self.root, FIXTURE, audit, str(self._fake()))
        self.assertEqual(result["result"], "SUCCEEDED")
        self.assertEqual(result["actual_changed_files"], ["value.py"])
        self.assertEqual(result["staged_files"], ["value.py"])
        self.assertEqual(result["committed_diff"], ["value.py"])
        self.assertFalse(result["hook_ran"])
        self.assertTrue(result["git_metadata_during_codex"] == "unavailable")
        self.assertEqual(json.loads(audit.read_text()) ["kill_switch_final"], "ENGAGED")

    def test_unauthorized_edit_blocks_commit(self):
        result = run_writer_probe(self.root, FIXTURE, self.root / "audit-unauthorized.jsonl", str(self._fake("unauthorized")))
        self.assertEqual(result["result"], "FAILED")
        self.assertIn("unauthorized.py", result["actual_changed_files"])
        self.assertNotIn("repair_commit", result)

    def test_claimed_actual_mismatch_blocks_commit(self):
        result = run_writer_probe(self.root, FIXTURE, self.root / "audit-mismatch.jsonl", str(self._fake("claimed-mismatch")))
        self.assertEqual(result["result"], "FAILED")
        self.assertEqual(result["claimed_changed_files"], ["test_value.py"])
        self.assertEqual(result["actual_changed_files"], ["value.py"])
        self.assertNotIn("repair_commit", result)

    def test_cache_artifact_blocks_commit(self):
        result = run_writer_probe(self.root, FIXTURE, self.root / "audit-cache.jsonl", str(self._fake("cache")))
        self.assertEqual(result["result"], "FAILED")
        self.assertIn("__pycache__/bad.pyc", result["actual_changed_files"])
        self.assertNotIn("repair_commit", result)
