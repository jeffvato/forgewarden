import json
import shutil
import tempfile
import unittest
from pathlib import Path

from swarm.core import SwarmError
from swarm.gemini_recovery import _prior_invalid_payload, recover_gemini_review


class GeminiRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_prior_invalid_payload_rejects_symlinked_audit(self):
        outside = self.tmp_path / "outside.jsonl"
        outside.write_text(json.dumps({"job_id": "job-1", "missing_tests": ["x"]}) + "\n", encoding="utf-8")
        audit = self.tmp_path / "audit.jsonl"
        audit.symlink_to(outside)

        with self.assertRaises(SwarmError):
            _prior_invalid_payload(audit, "job-1", "a" * 40)

    def test_recover_gemini_review_rejects_symlinked_markers(self):
        repository = self.tmp_path / "repo"
        repository.mkdir()
        audit_dir = self.tmp_path / "audit"
        audit_dir.mkdir()
        runtime_root = self.tmp_path / "runtime"
        runtime_root.mkdir()

        outside = self.tmp_path / "outside_marker"
        outside.touch()

        # Case 1: Symlinked kill switch
        kill_switch = runtime_root / "KILL_SWITCH"
        kill_switch.symlink_to(outside)

        with self.assertRaisesRegex(SwarmError, "refusing symlink Gemini recovery kill switch"):
            recover_gemini_review(
                root=self.tmp_path,
                repository=repository,
                runtime_root=runtime_root,
                audit_dir=audit_dir,
                job_id="job-1",
                repair_commit="a" * 40,
            )

        # Clean up symlink for case 2
        kill_switch.unlink()
        # Create valid kill switch
        kill_switch.touch()

        # Case 2: Symlinked deployment enabled marker
        deployment_marker = runtime_root / "DEPLOYMENT_ENABLED"
        deployment_marker.symlink_to(outside)

        with self.assertRaisesRegex(SwarmError, "refusing symlink Gemini recovery deployment marker"):
            recover_gemini_review(
                root=self.tmp_path,
                repository=repository,
                runtime_root=runtime_root,
                audit_dir=audit_dir,
                job_id="job-1",
                repair_commit="a" * 40,
            )
