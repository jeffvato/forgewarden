import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from swarm.adapters import CodexAdapter, ResourceLimits, _codex_environment


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
            "assert args[-1] == 'repair only value.py; return the required JSON'\n"
            "output = pathlib.Path(args[args.index('--output-last-message') + 1])\n"
            "pathlib.Path('value.py').write_text('def value():\\n    return 2\\n')\n"
            "pathlib.Path('.swarm/fake-capture.json').write_text(json.dumps({'args': args, 'cwd': os.getcwd(), 'prompt': args[-1], 'env_names': sorted(os.environ)}))\n"
            "output.write_text(json.dumps({'job_id':'fake-job','status':'FIXED','root_cause':'fixture defect','summary':'fixed fixture','changed_files':['value.py'],'tests_added_or_changed':[],'commands_run':[{'command':'pytest','exit_code':0}],'remaining_risks':[],'requires_human_approval':False}))\n",
            encoding="utf-8",
        )
        self.fake.chmod(0o700)

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_process_adapter_contract_and_edit_detection(self):
        before = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=self.repo, text=True).strip()
        schema = Path(__file__).resolve().parents[1] / "schemas/codex-result.schema.json"
        adapter = CodexAdapter(schema, ResourceLimits(timeout_seconds=30), str(self.fake))
        result = adapter.run(self.repo, "fake-job", "repair only value.py; return the required JSON")
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
        self.assertEqual(capture["prompt"], "repair only value.py; return the required JSON")
        self.assertEqual(capture["args"][:4], ["--ask-for-approval", "never", "exec", "--ephemeral"])
        self.assertEqual(capture["args"][capture["args"].index("--sandbox") + 1], "workspace-write")
        self.assertNotIn("DATABASE_URL", capture["env_names"])
        self.assertNotIn("HTTP_PROXY", capture["env_names"])
        self.assertIn("SWARM_NETWORK_BLOCKED", capture["env_names"])
        codex_env = _codex_environment()
        self.assertEqual(set(codex_env) - {"PATH", "HOME", "LANG", "LC_ALL", "TERM", "CODEX_HOME", "OPENAI_API_KEY", "OPENAI_BASE_URL", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "SWARM_NETWORK_BLOCKED"}, set())
