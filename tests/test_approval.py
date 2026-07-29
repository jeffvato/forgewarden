import json
import shutil
import tempfile
import unittest
from pathlib import Path

import jsonschema

from swarm.approval import create_approval_record, verify_approval

ROOT = Path(__file__).resolve().parents[1]
RECORD_SCHEMA = ROOT / "schemas" / "approval-record.schema.json"
VERIFY_SCHEMA = ROOT / "schemas" / "approval-verification.schema.json"


class ApprovalTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp()
        self.tmp_path = Path(self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_approval_binds_exact_evidence_and_consumes_once(self):
        evidence = self.tmp_path / "evidence.json"
        evidence.write_text('{"mutation_allowed": false}\n', encoding="utf-8")
        approval = self.tmp_path / "approvals" / "approval.json"

        record = create_approval_record(
            evidence, approval, job_id="job-1", reviewer="Jeff", decision="APPROVED"
        )
        jsonschema.validate(record, json.loads(RECORD_SCHEMA.read_text(encoding="utf-8")))

        result = verify_approval(approval, evidence, expected_job_id="job-1", consume=True)

        jsonschema.validate(result, json.loads(VERIFY_SCHEMA.read_text(encoding="utf-8")))
        self.assertTrue(result["verified"])
        self.assertTrue(result["consumed"])
        self.assertTrue(result["replay_protected"])
        with self.assertRaisesRegex(ValueError, "consumed|replay"):
            verify_approval(approval, evidence, expected_job_id="job-1", consume=True)

    def test_approval_rejects_evidence_replacement_and_wrong_job(self):
        evidence = self.tmp_path / "evidence.json"
        evidence.write_text("original\n", encoding="utf-8")
        approval = self.tmp_path / "approval.json"
        create_approval_record(evidence, approval, job_id="job-2", reviewer="reviewer", decision="APPROVED")
        evidence.write_text("replacement\n", encoding="utf-8")

        with self.assertRaisesRegex(ValueError, "hash"):
            verify_approval(approval, evidence, expected_job_id="job-2")
        evidence.write_text("original\n", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "job ID"):
            verify_approval(approval, evidence, expected_job_id="job-other")

    def test_rejected_approval_cannot_verify(self):
        evidence = self.tmp_path / "evidence.json"
        evidence.write_text("evidence\n", encoding="utf-8")
        approval = self.tmp_path / "approval.json"
        create_approval_record(evidence, approval, job_id="job-3", reviewer="reviewer", decision="REJECTED")

        with self.assertRaisesRegex(ValueError, "not APPROVED"):
            verify_approval(approval, evidence, expected_job_id="job-3")
