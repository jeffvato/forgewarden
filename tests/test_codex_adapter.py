import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from swarm.adapters import CodexAdapter, ResourceLimits, WriterInvocationSpec, _codex_environment
from swarm.core import SwarmError, validate_contract
from swarm.paths import runtime_root


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
            "assert args[:2] == ['exec', '--approve-for-me']\n"
            "assert '--sandbox' not in args\n"
            "assert args[args.index('--cd') + 1] == os.getcwd()\n"
            "prompt = args[-1]\n"
            "assert prompt.startswith('RETURN JOB_ID EXACTLY AS SUPPLIED: codex-writer-test1234.')\n"
            "job_id = prompt.split(': ', 1)[1].split('.', 1)[0]\n"
            "output = pathlib.Path(args[args.index('--output-last-message') + 1])\n"
            "pathlib.Path('value.py').write_text('def value():\\n    return 2\\n')\n"
            "pathlib.Path('.swarm/fake-capture.json').write_text(json.dumps({'args': args, 'cwd': os.getcwd(), 'prompt': prompt, 'schema': json.loads(pathlib.Path(args[args.index('--output-schema') + 1]).read_text()), 'env_names': sorted(os.environ), 'pycache': os.environ.get('PYTHONPYCACHEPREFIX'), 'pytest_opts': os.environ.get('PYTEST_ADDOPTS')}))\n"
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
        spec = WriterInvocationSpec("codex-writer-test1234", self.repo, self.repo, "value.py", "value.py", "value() returns 2", "assert value() == 2", ("value.py",))
        result = adapter.run(spec)
        self.assertEqual(result["status"], "FIXED")
        self.assertEqual(adapter.last_invocation["exit_code"], 0)
        self.assertEqual(adapter.last_invocation["argv"][0:4], [str(self.fake), "exec", "--approve-for-me", "--skip-git-repo-check"])
        self.assertEqual(adapter.last_invocation["working_directory"], str(self.repo))
        self.assertIn("final_response", adapter.last_invocation)
        self.assertEqual((self.repo / "value.py").read_text(), "def value():\n    return 2\n")
        changed = subprocess.check_output(["git", "diff", "--name-only", before], cwd=self.repo, text=True).splitlines()
        self.assertEqual(changed, ["value.py"])
        capture = json.loads((self.repo / ".swarm/fake-capture.json").read_text())
        self.assertEqual(capture["cwd"], str(self.repo))
        self.assertIn("RETURN JOB_ID EXACTLY AS SUPPLIED: codex-writer-test1234.", capture["prompt"])
        self.assertEqual(capture["schema"]["properties"]["job_id"]["const"], "codex-writer-test1234")
        self.assertEqual(capture["args"][:2], ["exec", "--approve-for-me"])
        self.assertNotIn("--sandbox", capture["args"])
        self.assertNotIn("DATABASE_URL", capture["env_names"])
        self.assertNotIn("HTTP_PROXY", capture["env_names"])
        self.assertIn("SWARM_NETWORK_BLOCKED", capture["env_names"])
        self.assertIn("PYTHONDONTWRITEBYTECODE", capture["env_names"])
        self.assertIn("PYTHONPYCACHEPREFIX", capture["env_names"])
        self.assertIn("PYTEST_ADDOPTS", capture["env_names"])
        self.assertTrue(capture["pycache"].startswith(str(runtime_root() / "python-cache") + "/"))
        self.assertEqual(capture["pytest_opts"], "-p no:cacheprovider")
        self.assertFalse(adapter.last_cache_directory.exists())
        codex_env = _codex_environment()
        self.assertEqual(set(codex_env) - {"PATH", "HOME", "LANG", "LC_ALL", "TERM", "CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "PYTHONDONTWRITEBYTECODE", "PYTHONNOUSERSITE", "PYTEST_ADDOPTS", "SWARM_NETWORK_BLOCKED"}, set())


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

    def test_external_cache_cleanup_on_failure_and_timeout(self):
        for mode in ("failure", "timeout"):
            with self.subTest(mode=mode):
                root = Path(tempfile.mkdtemp(prefix=f"codex-cache-{mode}-"))
                fake = root / "fake"
                action = "raise SystemExit(7)" if mode == "failure" else "import time; time.sleep(3)"
                fake.write_text(f"#!/usr/bin/env python3\n{action}\n", encoding="utf-8")
                fake.chmod(0o700)
                (root / "value.py").write_text("def value():\n    return 1\n", encoding="utf-8")
                adapter = CodexAdapter(Path(__file__).resolve().parents[1] / "schemas/codex-result.schema.json", ResourceLimits(timeout_seconds=1), str(fake))
                with self.assertRaises(Exception):
                    spec = WriterInvocationSpec("codex-writer-cache1234", root, root, "value.py", "value.py", "probe", "assert true", ("value.py",))
                    adapter.run(spec)
                self.assertIsNotNone(adapter.last_cache_directory)
                self.assertFalse(adapter.last_cache_directory.exists())
                shutil.rmtree(root, ignore_errors=True)

    def test_agent_replaced_final_response_with_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "value.py"
            target.write_text("def value():\n    return 1\n", encoding="utf-8")
            outside = root / "outside.json"
            payload = self._payload("codex-writer-symlink1234")
            outside.write_text(json.dumps(payload), encoding="utf-8")

            def replace_output(command, cwd, prompt, limits, env, **kwargs):
                output = Path(command[command.index("--output-last-message") + 1])
                output.unlink()
                output.symlink_to(outside)
                return subprocess.CompletedProcess(command, 0, "", "")

            adapter = CodexAdapter(
                Path(__file__).resolve().parents[1] / "schemas/codex-result.schema.json",
                ResourceLimits(timeout_seconds=5),
                "/bin/true",
            )
            spec = WriterInvocationSpec(
                "codex-writer-symlink1234", root, root, "value.py", "value.py",
                "value returns 2", "assert value() == 2", ("value.py",),
            )
            with patch("swarm.adapters.runtime_root", return_value=root / "runtime"), patch("swarm.adapters.limited_run", side_effect=replace_output):
                with self.assertRaises(SwarmError):
                    adapter.run(spec)
            self.assertEqual(outside.read_text(encoding="utf-8"), json.dumps(payload))
