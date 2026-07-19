import subprocess
import tempfile
import unittest
from pathlib import Path

from swarm.baseline import enforce_diff_gate, scan_baseline_tree, scan_git_blobs
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


if __name__ == "__main__":
    unittest.main()
