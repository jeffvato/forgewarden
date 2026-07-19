import subprocess
import tempfile
import unittest
from subprocess import CompletedProcess
from pathlib import Path
from unittest.mock import patch

from swarm.baseline import _deadline_test_command, _run_deadline_preflight, enforce_diff_gate, scan_baseline_tree, scan_git_blobs
from swarm.core import SwarmError, run_command


class BaselineDiffGateTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="baseline-gate-"))
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main"], cwd=self.repo, check=True)
        (self.repo / "csv-processor/app/ai").mkdir(parents=True)
        (self.repo / "csv-processor/tests/swarm_regressions").mkdir(parents=True)
        (self.repo / "csv-processor/app/ai/deadline.py").write_text("VALUE = 1\n", encoding="utf-8")
        (self.repo / "csv-processor/tests/existing.py").write_text("def test_existing():\n    assert 1 == 1\n", encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.test", "commit", "-qm", "base"], cwd=self.repo, check=True)
        self.base = run_command(["git", "rev-parse", "HEAD"], self.repo).stdout.strip()
        self.hashes = {"csv-processor/tests/existing.py": ""}
        import hashlib
        self.hashes["csv-processor/tests/existing.py"] = hashlib.sha256((self.repo / "csv-processor/tests/existing.py").read_bytes()).hexdigest()

    def commit(self, path: str, content: str):
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.test", "commit", "-qm", "change"], cwd=self.repo, check=True)

    def test_allowed_deadline_change_passes(self):
        self.commit("csv-processor/app/ai/deadline.py", "VALUE = 2\n")
        result = enforce_diff_gate(self.repo, self.base, self.hashes)
        self.assertEqual(result["changed_files"], ["csv-processor/app/ai/deadline.py"])

    def test_existing_test_mutation_is_rejected(self):
        self.commit("csv-processor/tests/existing.py", "def test_existing():\n    assert 2 == 2\n")
        with self.assertRaises(SwarmError):
            enforce_diff_gate(self.repo, self.base, self.hashes)

    def test_out_of_scope_and_rename_are_rejected(self):
        self.commit("csv-processor/app/other.py", "VALUE = 2\n")
        with self.assertRaises(SwarmError):
            enforce_diff_gate(self.repo, self.base, self.hashes)

    def test_new_test_integrity_bypass_is_rejected(self):
        self.commit("csv-processor/tests/swarm_regressions/test_bad.py", "import pytest\npytest.skip('bypass')\n")
        with self.assertRaises(SwarmError):
            enforce_diff_gate(self.repo, self.base, self.hashes)

    def test_symlink_and_secret_scan_are_rejected(self):
        link = self.repo / "csv-processor/tests/swarm_regressions/link.py"
        link.symlink_to("../existing.py")
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "-c", "user.name=test", "-c", "user.email=test@example.test", "commit", "-qm", "symlink"], cwd=self.repo, check=True)
        with self.assertRaises(SwarmError):
            enforce_diff_gate(self.repo, self.base, self.hashes)

        secret = self.root / "secret-tree"
        secret.mkdir()
        (secret / "private.pem").write_text("not read into output", encoding="utf-8")
        self.assertTrue(scan_baseline_tree(secret)["findings"])

    def test_git_blob_scan_covers_committed_content(self):
        scan = scan_git_blobs(self.repo)
        self.assertGreaterEqual(scan["blobs_scanned"], 2)
        self.assertEqual(scan["findings"], [])

    def _preflight_tree(self):
        root = self.root / "preflight"
        (root / "csv-processor/app/ai").mkdir(parents=True)
        (root / "csv-processor/tests/swarm_regressions").mkdir(parents=True)
        (root / "csv-processor/app/ai/deadline.py").write_text(
            "import time\ndeadline = time.monotonic() + 0.1\n\ndef f():\n    return max(0.0, deadline - time.monotonic())\n", encoding="utf-8"
        )
        (root / "csv-processor/tests/swarm_regressions/test_deadline_contract.py").write_text(
            "from app.ai.deadline import f\n\n\ndef test_contract():\n    assert f() <= 0.5\n", encoding="utf-8"
        )
        return root

    def test_preflight_uses_resolved_path_and_identical_argument_arrays(self):
        root = self._preflight_tree()
        limits = object()
        passing = CompletedProcess(["pytest"], 0, "2 passed", "")
        failing = CompletedProcess(["pytest"], 1, "AssertionError", "")
        with patch("swarm.baseline.limited_run", side_effect=[passing, failing]) as runner:
            working_directory, path, command, evidence = _run_deadline_preflight(root, limits)
        self.assertEqual(working_directory, root / "csv-processor")
        self.assertTrue(path.is_file())
        self.assertEqual(evidence["baseline_exit_code"], 0)
        self.assertEqual(evidence["seeded_defect_exit_code"], 1)
        self.assertEqual(runner.call_args_list[0].args[0], runner.call_args_list[1].args[0])
        self.assertIsInstance(command, list)
        self.assertEqual(evidence["test_path"], str(path))
        self.assertTrue(str(path).startswith(str(root.resolve())))

    def test_preflight_failure_prevents_second_phase_and_codex(self):
        root = self._preflight_tree()
        failed = CompletedProcess(["pytest"], 1, "baseline assertion failure", "")
        with patch("swarm.baseline.limited_run", return_value=failed) as runner, patch("swarm.baseline._introduce_deadline_defect") as defect:
            with self.assertRaises(SwarmError):
                _run_deadline_preflight(root, object())
        self.assertEqual(runner.call_count, 1)
        defect.assert_not_called()

    def test_preflight_rejects_non_assertion_seed_failure(self):
        root = self._preflight_tree()
        passing = CompletedProcess(["pytest"], 0, "2 passed", "")
        wrong_failure = CompletedProcess(["pytest"], 1, "no tests ran", "")
        with patch("swarm.baseline.limited_run", side_effect=[passing, wrong_failure]):
            with self.assertRaises(SwarmError):
                _run_deadline_preflight(root, object())

    def test_preflight_rejects_symlinked_test_path(self):
        root = self._preflight_tree()
        test_path = root / "csv-processor/tests/swarm_regressions/test_deadline_contract.py"
        test_path.unlink()
        test_path.symlink_to("/tmp/outside-deadline-test.py")
        with self.assertRaises(SwarmError):
            _deadline_test_command(root)

    def test_process_level_preflight_uses_real_pytest_environment(self):
        root = self._preflight_tree()
        limits = type("Limits", (), {"cpu_seconds": 45, "memory_bytes": 2_147_483_648, "timeout_seconds": 60, "max_log_bytes": 256_000})()
        working_directory, path, command, evidence = _run_deadline_preflight(root, limits, use_cgroup=False)
        self.assertEqual(working_directory, root / "csv-processor")
        self.assertEqual(path, (root / "csv-processor/tests/swarm_regressions/test_deadline_contract.py").resolve())
        self.assertEqual(command[1:7], ["-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/swarm_regressions/test_deadline_contract.py"])
        self.assertEqual(evidence["baseline_exit_code"], 0)
        self.assertEqual(evidence["seeded_defect_exit_code"], 1)
        self.assertFalse(any(root.rglob("__pycache__")))
        self.assertFalse(any(root.rglob(".pytest_cache")))


if __name__ == "__main__":
    unittest.main()
