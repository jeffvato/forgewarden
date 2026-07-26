import json
from pathlib import Path

import jsonschema
import pytest

from swarm.approval import create_approval_record, verify_approval


ROOT = Path(__file__).resolve().parents[1]
RECORD_SCHEMA = ROOT / "schemas" / "approval-record.schema.json"
VERIFY_SCHEMA = ROOT / "schemas" / "approval-verification.schema.json"


def test_approval_binds_exact_evidence_and_consumes_once(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text('{"mutation_allowed": false}\n', encoding="utf-8")
    approval = tmp_path / "approvals" / "approval.json"

    record = create_approval_record(
        evidence, approval, job_id="job-1", reviewer="Jeff", decision="APPROVED"
    )
    jsonschema.validate(record, json.loads(RECORD_SCHEMA.read_text(encoding="utf-8")))

    result = verify_approval(approval, evidence, expected_job_id="job-1", consume=True)

    jsonschema.validate(result, json.loads(VERIFY_SCHEMA.read_text(encoding="utf-8")))
    assert result["verified"] is True
    assert result["consumed"] is True
    assert result["replay_protected"] is True
    with pytest.raises(ValueError, match="consumed|replay"):
        verify_approval(approval, evidence, expected_job_id="job-1", consume=True)


def test_approval_rejects_evidence_replacement_and_wrong_job(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text("original\n", encoding="utf-8")
    approval = tmp_path / "approval.json"
    create_approval_record(evidence, approval, job_id="job-2", reviewer="reviewer", decision="APPROVED")
    evidence.write_text("replacement\n", encoding="utf-8")

    with pytest.raises(ValueError, match="hash"):
        verify_approval(approval, evidence, expected_job_id="job-2")
    evidence.write_text("original\n", encoding="utf-8")
    with pytest.raises(ValueError, match="job ID"):
        verify_approval(approval, evidence, expected_job_id="job-other")


def test_rejected_approval_cannot_verify(tmp_path):
    evidence = tmp_path / "evidence.json"
    evidence.write_text("evidence\n", encoding="utf-8")
    approval = tmp_path / "approval.json"
    create_approval_record(evidence, approval, job_id="job-3", reviewer="reviewer", decision="REJECTED")

    with pytest.raises(ValueError, match="not APPROVED"):
        verify_approval(approval, evidence, expected_job_id="job-3")
