import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from swarm.adapters import CodexAdapter, ResourceLimits, WriterInvocationSpec, normalize_changed_paths
from swarm.baseline import enforce_diff_gate
from swarm.core import SwarmError


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


def _commit(repo: Path, message: str = "base") -> str:
    subprocess.run(["git", "add", "--", "."], cwd=repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", message],
        cwd=repo,
        check=True,
    )
    return subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=repo, text=True).strip()


class WriterWiringValidationTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="writer-wiring-"))
        self.repo = self.root / "repo"
        (self.repo / "csv-processor/app/ai").mkdir(parents=True)
        (self.repo / "csv-processor/tests/swarm_regressions").mkdir(parents=True)
        (self.repo / "csv-processor/app/ai/deadline.py").write_text(
            "def remaining_seconds():\n    return 1.0\n", encoding="utf-8"
        )
        (self.repo / "csv-processor/tests/swarm_regressions/test_deadline_contract.py").write_text(
            "from app.ai.deadline import remaining_seconds\n\n"
            "def test_deadline_contract():\n    assert remaining_seconds() >= 0\n",
            encoding="utf-8",
        )
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        self.base = _commit(self.repo)
        self.target = self.repo / "csv-processor/app/ai/deadline.py"
        self.spec = WriterInvocationSpec(
            "codex-writer-wiring1234",
            self.repo,
            self.repo / "csv-processor",
            "app/ai/deadline.py",
            "csv-processor/app/ai/deadline.py",
            "remaining_seconds() returns non-negative remaining monotonic time",
            "assert remaining_seconds() >= 0",
            ("csv-processor/app/ai/deadline.py",),
        )

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def test_spec_maps_cwd_target_to_git_target(self):
        self.assertEqual(self.spec.target(), self.target.resolve())
        self.assertIn(str(self.repo / "csv-processor"), self.spec.prompt())
        self.assertIn("app/ai/deadline.py", self.spec.prompt())
        self.assertIn("csv-processor/app/ai/deadline.py", self.spec.prompt())
        self.assertIn("Do not modify or create tests", self.spec.prompt())
        self.assertIn("Do not write Git metadata", self.spec.prompt())

    def test_fake_cli_process_receives_production_wiring_and_orchestrator_commits(self):
        fake = self.root / "fake-codex"
        fake.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "args = sys.argv[1:]\n"
            "assert args[args.index('--cd') + 1] == os.getcwd()\n"
            "assert args[-1].startswith('RETURN JOB_ID EXACTLY AS SUPPLIED: codex-writer-wiring1234.')\n"
            "assert pathlib.Path('app/ai/deadline.py').is_file()\n"
            "pathlib.Path('app/ai/deadline.py').write_text('def remaining_seconds():\\n    return 0.0\\n')\n"
            "schema = json.loads(pathlib.Path(args[args.index('--output-schema') + 1]).read_text())\n"
            "assert schema['properties']['job_id']['const'] == 'codex-writer-wiring1234'\n"
            "pathlib.Path(args[args.index('--output-last-message') + 1]).write_text(json.dumps({\n"
            "'job_id':'codex-writer-wiring1234','status':'FIXED','root_cause':'fixture',\n"
            "'summary':'fixed','changed_files':['app/ai/deadline.py'],'tests_added_or_changed':[],\n"
            "'commands_run':[{'command':'pytest','exit_code':0}], 'remaining_risks':[],\n"
            "'requires_human_approval':False}))\n",
            encoding="utf-8",
        )
        fake.chmod(0o700)
        schema = Path(__file__).resolve().parents[1] / "schemas/codex-result.schema.json"
        adapter = CodexAdapter(schema, ResourceLimits(timeout_seconds=30), str(fake))
        def run_without_host_cgroup(command, cwd, prompt, limits, env, **kwargs):
            child_env = kwargs["environment_builder"](env)
            return subprocess.run(command, cwd=cwd, input=prompt, text=True, capture_output=True, env=child_env, check=False)
        with patch("swarm.adapters.limited_run", side_effect=run_without_host_cgroup):
            result = adapter.run(self.spec)
        self.assertEqual(result["changed_files"], ["app/ai/deadline.py"])
        self.assertEqual(normalize_changed_paths(self.spec, result["changed_files"]), ["csv-processor/app/ai/deadline.py"])
        deterministic = subprocess.run(
            ["/home/jeff/anaconda3/bin/python3", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/swarm_regressions/test_deadline_contract.py"],
            cwd=self.repo / "csv-processor",
            env={"PATH": os.environ["PATH"], "PYTHONDONTWRITEBYTECODE": "1", "PYTEST_ADDOPTS": "-p no:cacheprovider"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(deterministic.returncode, 0, deterministic.stdout + deterministic.stderr)
        gate = enforce_diff_gate(self.repo, self.base, {"csv-processor/tests/swarm_regressions/test_deadline_contract.py": hashlib.sha256((self.repo / "csv-processor/tests/swarm_regressions/test_deadline_contract.py").read_bytes()).hexdigest()})
        self.assertEqual(gate["changed_files"], ["csv-processor/app/ai/deadline.py"])
        subprocess.run(["git", "add", "--", "csv-processor/app/ai/deadline.py"], cwd=self.repo, check=True)
        staged = subprocess.check_output(["git", "diff", "--cached", "--name-only"], cwd=self.repo, text=True).splitlines()
        self.assertEqual(staged, ["csv-processor/app/ai/deadline.py"])
        subprocess.run(
            ["git", "-c", "core.hooksPath=/dev/null", "-c", "commit.gpgSign=false", "-c", "user.name=Hermes Swarm", "-c", "user.email=hermes-swarm@localhost", "commit", "-qm", "wiring probe"],
            cwd=self.repo,
            check=True,
        )
        committed = subprocess.check_output(["git", "show", "--format=", "--name-only", "HEAD"], cwd=self.repo, text=True).splitlines()
        self.assertEqual(committed, ["csv-processor/app/ai/deadline.py"])

    def test_wrong_cwd_short_target_is_rejected(self):
        bad = WriterInvocationSpec(self.spec.job_id, self.repo, self.repo, "app/ai/deadline.py", self.spec.git_relative_target, "x", "y", self.spec.writable_git_paths)
        with self.assertRaises(SwarmError):
            bad.target()

    def test_full_git_root_path_returned_from_cwd_is_rejected(self):
        with self.assertRaises(SwarmError):
            normalize_changed_paths(self.spec, [str(self.target)])

    def test_nonexistent_target_and_seed_hash_mismatch_are_rejected(self):
        missing = WriterInvocationSpec(self.spec.job_id, self.repo, self.repo / "csv-processor", "missing.py", self.spec.git_relative_target, "x", "y", self.spec.writable_git_paths)
        with self.assertRaises(SwarmError):
            missing.target()
        with self.assertRaises(SwarmError):
            self.spec.target("0" * 64)

    def test_traversal_and_symlink_paths_are_rejected(self):
        with self.assertRaises(SwarmError):
            normalize_changed_paths(self.spec, ["../app/ai/deadline.py"])
        link = self.repo / "csv-processor/app/ai/link.py"
        link.symlink_to(self.target)
        symlink_spec = WriterInvocationSpec(self.spec.job_id, self.repo, self.repo / "csv-processor", "app/ai/link.py", "csv-processor/app/ai/deadline.py", "x", "y", self.spec.writable_git_paths)
        with self.assertRaises(SwarmError):
            symlink_spec.target()


if __name__ == "__main__":
    unittest.main()
