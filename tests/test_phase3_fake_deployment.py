import hashlib
import tempfile
from pathlib import Path
from unittest import TestCase

from swarm.core import SwarmError
from swarm.phase3_fake_deployment import FakeDeploymentAdapter, FakeDeploymentRequest


class Phase3FakeDeploymentTests(TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="phase3-fixture-")
        self.root = Path(self.temp.name)
        (self.root / ".forgewarden-disposable-fixture").write_text("forgewarden-synthetic-fixture-v1\n", encoding="utf-8")
        (self.root / "service-state.txt").write_text("old-state\n", encoding="utf-8")
        self.request = FakeDeploymentRequest("phase3-job-1", "forgewarden-synthetic-fixture-v1", "a" * 40, hashlib.sha256(b"evidence").hexdigest(), "b" * 32)
        self.approval = {"mode": "FAKE_DEPLOYMENT_SIMULATION", "approval_id": self.request.approval_id, "job_id": self.request.job_id, "service": self.request.service, "approved_commit": self.request.approved_commit, "evidence_sha256": self.request.evidence_sha256, "decision": "APPROVED", "one_time": True, "consumed": False, "deployment": "DISABLED"}

    def tearDown(self):
        self.temp.cleanup()

    def test_success_requires_exact_approval_and_creates_backup(self):
        result = FakeDeploymentAdapter(self.root).execute(self.request, self.approval, lambda path: path.read_text().find("a" * 40) >= 0)
        self.assertEqual(result["state"], "SIMULATED_SUCCEEDED")
        self.assertEqual(result["deployment"], "DISABLED")
        self.assertTrue(Path(result["backup"]).is_file())

    def test_health_failure_rolls_back(self):
        result = FakeDeploymentAdapter(self.root).execute(self.request, self.approval, lambda path: False)
        self.assertEqual(result["state"], "ROLLED_BACK")
        self.assertEqual((self.root / "service-state.txt").read_text(), "old-state\n")

    def test_replay_is_rejected(self):
        adapter = FakeDeploymentAdapter(self.root)
        adapter.execute(self.request, self.approval, lambda path: True)
        with self.assertRaisesRegex(SwarmError, "replay"):
            adapter.execute(self.request, self.approval, lambda path: True)

    def test_commit_and_service_mismatches_fail_closed_without_mutation(self):
        bad = FakeDeploymentRequest(self.request.job_id, "other-service", self.request.approved_commit, self.request.evidence_sha256, self.request.approval_id)
        with self.assertRaises(SwarmError):
            FakeDeploymentAdapter(self.root).execute(bad, self.approval, lambda path: True)
        self.assertEqual((self.root / "service-state.txt").read_text(), "old-state\n")

    def test_symlinked_target_is_rejected(self):
        target = self.root / "service-state.txt"
        target.unlink()
        target.symlink_to("outside.txt")
        with self.assertRaisesRegex(SwarmError, "symlink"):
            FakeDeploymentAdapter(self.root).execute(self.request, self.approval, lambda path: True)

    def test_health_timeout_rolls_back(self):
        result = FakeDeploymentAdapter(self.root).execute(self.request, self.approval, lambda path: (_ for _ in ()).throw(TimeoutError()))
        self.assertEqual(result["reason"], "health_check_timeout")
        self.assertEqual((self.root / "service-state.txt").read_text(), "old-state\n")

    def test_audit_failure_rolls_back(self):
        def fail_audit(event, result):
            raise OSError("synthetic audit failure")
        result = FakeDeploymentAdapter(self.root).execute(self.request, self.approval, lambda path: True, fail_audit)
        self.assertEqual(result["reason"], "audit_or_health_failure")
        self.assertEqual((self.root / "service-state.txt").read_text(), "old-state\n")

    def test_non_hex_commit_and_evidence_fail_closed(self):
        bad_commit = FakeDeploymentRequest(self.request.job_id, self.request.service, "z" * 40, self.request.evidence_sha256, self.request.approval_id)
        with self.assertRaisesRegex(SwarmError, "outside the fixed contract"):
            FakeDeploymentAdapter(self.root).execute(bad_commit, self.approval, lambda path: True)
        bad_evidence = FakeDeploymentRequest(self.request.job_id, self.request.service, self.request.approved_commit, "z" * 64, self.request.approval_id)
        with self.assertRaisesRegex(SwarmError, "outside the fixed contract"):
            FakeDeploymentAdapter(self.root).execute(bad_evidence, self.approval, lambda path: True)


if __name__ == "__main__":
    import unittest
    unittest.main()
