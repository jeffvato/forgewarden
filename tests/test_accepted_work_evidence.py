from __future__ import annotations

import json
from pathlib import Path

import pytest

from swarm.accepted_work_evidence import AcceptedEvidenceError, append_accepted_evidence, build_accepted_evidence, read_accepted_evidence, write_accepted_evidence
from swarm.evidence import EvidenceLedger


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


@pytest.mark.parametrize("expected", [("phase2a-other00000000000000000000", SHA), (JOB, "b" * 40)])
def test_immutable_boundaries_reject_mismatched_job_or_candidate(tmp_path, expected):
    path = tmp_path / "accepted.json"
    bundle = _bundle()
    write_accepted_evidence(path, bundle, expected_job_id=JOB, expected_candidate_commit=SHA)
    with pytest.raises(AcceptedEvidenceError):
        read_accepted_evidence(path, expected_job_id=expected[0], expected_candidate_commit=expected[1])


def _append(bundle=None, ledger=None, **changes):
    value = bundle or _bundle()
    target = ledger or EvidenceLedger("tenant-a", lambda *_args: None)
    arguments = dict(
        expected_job_id=JOB, expected_candidate_commit=SHA,
        tenant_id="tenant-a", actor_id="harness-controller",
        occurred_at="2026-09-10T23:00:00Z", ledger=target,
        correlation_id="fw-corr/tenant-a/fwq-0008",
    )
    arguments.update(changes)
    return append_accepted_evidence(value, **arguments)


def test_accepted_bundle_adapts_to_exact_payload_digest_and_chain():
    writes = []
    ledger = EvidenceLedger("tenant-a", lambda envelope, digest: writes.append((envelope, digest)))
    first = _append(ledger=ledger)
    assert first.envelope.subject_ref == f"fw-task/{JOB}"
    assert first.envelope.actor_ref == "fw-id/harness-controller"
    assert first.envelope.previous_record_sha256 is None
    assert first.envelope.payload_sha256 == __import__("hashlib").sha256(
        json.dumps(_bundle(), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    ).hexdigest()
    second_bundle = _bundle(previous_event_sha256="c" * 64)
    second = _append(bundle=second_bundle, ledger=ledger)
    assert second.envelope.previous_record_sha256 == first.record_sha256
    assert len(writes) == 2


def test_accepted_adapter_denies_replay_cross_tenant_and_durability_failure():
    ledger = EvidenceLedger("tenant-a", lambda *_args: None)
    _append(ledger=ledger)
    with pytest.raises(AcceptedEvidenceError, match="admission"):
        _append(ledger=ledger)
    with pytest.raises(AcceptedEvidenceError, match="tenant"):
        _append(ledger=EvidenceLedger("tenant-b", lambda *_args: None))
    failing = EvidenceLedger("tenant-a", lambda *_args: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(AcceptedEvidenceError, match="admission"):
        _append(ledger=failing)
    assert failing.tenant_snapshot("tenant-a") == ()


def test_accepted_adapter_revalidates_commit_review_policy_and_metadata_bindings():
    tampered = _bundle()
    tampered["accepted_commit"] = "b" * 40
    with pytest.raises(AcceptedEvidenceError):
        _append(bundle=tampered)
    for changes in (
        {"expected_candidate_commit": "b" * 40},
        {"occurred_at": "2026-09-10"},
        {"classification": "SECRET"},
        {"correlation_id": "fw-corr/tenant-b/fwq-0008"},
        {"evidence_references": ("fw-evid/tenant-b/review/1",)},
    ):
        with pytest.raises(AcceptedEvidenceError):
            _append(**changes)


def test_accepted_adapter_persists_no_bundle_or_provider_prose():
    record = _append()
    rendered = repr(record.envelope)
    assert "pytest focused" not in rendered
    assert "reasoning_summary" not in rendered
    assert not hasattr(record.envelope, "payload")
    assert record.envelope.authority_granted is False
