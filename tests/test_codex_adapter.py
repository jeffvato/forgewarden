import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from swarm.adapters import CodexAdapter, ResourceLimits, _codex_environment
from swarm.core import SwarmError, validate_contract


def _user_bus_available() -> bool:
    uid = os.getuid()
    return (
        shutil.which("systemd-run") is not None
        and (Path("/run/user") / str(uid) / "bus").is_socket()
        and subprocess.run(
            ["systemctl", "--user", "show-environment"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
        ).returncode == 0
    )


@unittest.skipUnless(_user_bus_available(), "user systemd bus is unavailable in this execution context")
class CodexAdapterProcessTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="codex-adapter-fixture-"))
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        (self.repo / "value.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        (self.repo / "test_value.py").write_text("from value import value\n\ndef test_value():\n    assert value() == 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "base"], cwd=self.repo, check=True)
        self.fake = self.root / "fake-codex"
        self.fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "assert args[:4] == ['--ask-for-approval', 'never', 'exec', '--ephemeral']\n"
            "assert args[args.index('--sandbox') + 1] == 'workspace-write'\n"
            "assert args[args.index('--cd') + 1] == os.getcwd()\n"
            "prompt = args[-1]\n"
            "assert prompt.startswith('RETURN JOB_ID EXACTLY AS SUPPLIED: codex-writer-test1234.')\n"
            "job_id = prompt.split(': ', 1)[1].split('.', 1)[0]\n"
            "output = pathlib.Path(args[args.index('--output-last-message') + 1])\n"
            "pathlib.Path('value.py').write_text('def value():\\n    return 2\\n')\n"
            "pathlib.Path('.swarm/fake-capture.json').write_text(json.dumps({'args': args, 'cwd': os.getcwd(), 'prompt': prompt, 'schema': json.loads(pathlib.Path(args[args.index('--output-schema') + 1]).read_text()), 'env_names': sorted(os.environ)}))\n"
            "output.write_text(json.dumps({'job_id':job_id,'status':'FIXED','root_cause':'fixture defect','summary':'fixed fixture','changed_files':['value.py'],'tests_added_or_changed':[],'commands_run':[{'command':'pytest','exit_code':0}],'remaining_risks':[],'requires_human_approval':False}))\n",
            encoding="utf-8",
        )
        self.fake.chmod(0o700)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_process_adapter_contract_and_edit_detection(self):
        before = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        schema = Path(__file__).resolve().parents[1] / "schemas/codex-result.schema.json"
        adapter = CodexAdapter(schema, ResourceLimits(timeout_seconds=30), str(self.fake))
        result = adapter.run(self.repo, "codex-writer-test1234", "repair only value.py; return the required JSON")
        self.assertEqual(result["status"], "FIXED")
        self.assertEqual(adapter.last_invocation["exit_code"], 0)
        self.assertEqual(adapter.last_invocation["argv"][0:4], [str(self.fake), "--ask-for-approval", "never", "exec"])
        self.assertEqual(adapter.last_invocation["working_directory"], str(self.repo))
        self.assertIn("final_response", adapter.last_invocation)
        self.assertEqual((self.repo / "value.py").read_text(), "def value():\n    return 2\n")
        changed = subprocess.check_output(["git", "diff", "--name-only", before], cwd=self.repo, text=True).splitlines()
        self.assertEqual(changed, ["value.py"])
        capture = json.loads((self.repo / ".swarm/fake-capture.json").read_text())
        self.assertEqual(capture["cwd"], str(self.repo))
        self.assertIn("RETURN JOB_ID EXACTLY AS SUPPLIED: codex-writer-test1234.", capture["prompt"])
        self.assertEqual(capture["schema"]["properties"]["job_id"]["const"], "codex-writer-test1234")
        self.assertEqual(capture["args"][:4], ["--ask-for-approval", "never", "exec", "--ephemeral"])
        self.assertEqual(capture["args"][capture["args"].index("--sandbox") + 1], "workspace-write")
        self.assertNotIn("DATABASE_URL", capture["env_names"])
        self.assertNotIn("HTTP_PROXY", capture["env_names"])
        self.assertIn("SWARM_NETWORK_BLOCKED", capture["env_names"])
        codex_env = _codex_environment()
        self.assertEqual(set(codex_env) - {"PATH", "HOME", "LANG", "LC_ALL", "TERM", "CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "SWARM_NETWORK_BLOCKED"}, set())


class CodexJobIdContractTests(unittest.TestCase):
    def _payload(self, job_id):
        return {"job_id": job_id, "status": "FIXED", "root_cause": "x", "summary": "x", "changed_files": [], "tests_added_or_changed": [], "commands_run": [], "remaining_risks": [], "requires_human_approval": False}

    def test_exact_id_passes(self):
        validate_contract(self._payload("codex-writer-test1234"), "codex", expected_job_id="codex-writer-test1234")

    def test_shortened_case_changed_and_boundary_ids_fail(self):
        expected = "codex-writer-test1234"
        for actual in ("writer-test1234", "CODEX-WRITER-TEST1234", "x" + expected, expected + "x"):
            with self.subTest(actual=actual), self.assertRaises(SwarmError):
                validate_contract(self._payload(actual), "codex", expected_job_id=expected)

    def test_response_for_another_job_fails(self):
        with self.assertRaises(SwarmError):
            validate_contract(self._payload("codex-writer-other1234"), "codex", expected_job_id="codex-writer-test1234")
