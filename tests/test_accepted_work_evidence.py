from __future__ import annotations

import json
from pathlib import Path

import pytest

from swarm.accepted_work_evidence import AcceptedEvidenceError, build_accepted_evidence, read_accepted_evidence, write_accepted_evidence


JOB = "phase2a-fwq000800000000000000000"
SHA = "a" * 40


def _review():
    return {"reviewed_commit": SHA, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "tests_missing": [], "reasoning_summary": "not persisted"}


def _bundle(**changes):
    values = dict(job_id=JOB, candidate_commit=SHA, accepted_commit=SHA, expected_job_id=JOB, expected_candidate_commit=SHA, changed_files=["swarm/accepted_work_evidence.py"], deterministic_validation=["pytest focused: passed"], claude_review=_review(), gemini_review=_review())
    values.update(changes)
    return build_accepted_evidence(**values)


def test_build_round_trip_is_redacted_and_hash_bound(tmp_path):
    bundle = _bundle()
    assert bundle["policy"] == {"mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "ENGAGED", "mutation_allowed": False}
    assert "reasoning_summary" not in json.dumps(bundle)
    path = tmp_path / "evidence" / "accepted.json"
    write_accepted_evidence(path, bundle, expected_job_id=JOB, expected_candidate_commit=SHA)
    assert read_accepted_evidence(path, expected_job_id=JOB, expected_candidate_commit=SHA) == bundle
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(path.parent.stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize("field,value", [("candidate_commit", "b" * 40), ("accepted_commit", "b" * 40), ("job_id", "phase2a-wrong")])
def test_binding_mismatch_fails_closed(field, value):
    changes = {field: value}
    with pytest.raises(AcceptedEvidenceError):
        _bundle(**changes)


@pytest.mark.parametrize("field,value", [("expected_job_id", "phase2a-other"), ("expected_candidate_commit", "b" * 40)])
def test_explicit_expected_binding_mismatch_fails_closed(field, value):
    with pytest.raises(AcceptedEvidenceError):
        _bundle(**{field: value})


def test_unapproved_or_missing_test_review_fails_closed():
    review = _review(); review["verdict"] = "REJECT"
    with pytest.raises(AcceptedEvidenceError):
        _bundle(claude_review=review)
    review = _review(); review["tests_missing"] = ["missing test"]
    with pytest.raises(AcceptedEvidenceError):
        _bundle(gemini_review=review)


def test_unsafe_policy_and_secret_like_metadata_fail_closed():
    with pytest.raises(AcceptedEvidenceError):
        _bundle(deterministic_validation=["token=secret-value"])
    bundle = _bundle()
    bundle["policy"]["kill_switch"] = "CLEARED"
    with pytest.raises(AcceptedEvidenceError):
        write_accepted_evidence(Path("/tmp/unused"), bundle, expected_job_id=JOB, expected_candidate_commit=SHA)


def test_tamper_replay_and_symlink_fail_closed(tmp_path):
    path = tmp_path / "accepted.json"
    bundle = _bundle(previous_event_sha256="c" * 64)
    write_accepted_evidence(path, bundle, expected_job_id=JOB, expected_candidate_commit=SHA)
    with pytest.raises(AcceptedEvidenceError):
        write_accepted_evidence(path, bundle, expected_job_id=JOB, expected_candidate_commit=SHA)
    data = json.loads(path.read_text())
    data["changed_files"] = ["swarm/other.py"]
    path.write_text(json.dumps(data))
    with pytest.raises(AcceptedEvidenceError):
        read_accepted_evidence(path, expected_job_id=JOB, expected_candidate_commit=SHA)
    outside = tmp_path / "outside.json"; outside.write_text("{}")
    link = tmp_path / "link.json"; link.symlink_to(outside)
    with pytest.raises(AcceptedEvidenceError):
        write_accepted_evidence(link, bundle, expected_job_id=JOB, expected_candidate_commit=SHA)
