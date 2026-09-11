"""Integrated FW-EVID lifecycle proof using only local DRY_RUN fixtures."""
import json

import pytest

from swarm.accepted_work_evidence import append_accepted_evidence, build_accepted_evidence
from swarm.core import AuditLog
from swarm.evidence import CanonicalAuditEvidenceStore, EvidenceContractError, EvidenceLedger
from swarm.harness_evidence import HarnessLifecycleEvidence, append_harness_evidence


TENANT = "tenant-proof"
JOB = "phase2a-evidenceproof00000000000"
SHA = "a" * 40


def lifecycle(event="validation_completed", timestamp="2026-09-11T00:00:00Z"):
    return HarnessLifecycleEvidence(
        1, event, TENANT, "FWQ-0200", "FW-EVID-006", "harness-controller",
        "codex-cli", "openai", "gpt-approved", "b" * 64,
        ("source.write",), ("bounded_source_edit",), ("deployment",),
        ("tests/test_evidence_lifecycle.py",), ("pytest",), ("PASSED",),
        ("CLAUDE:APPROVED:LOW",), "PASSED", "ACCEPTED", timestamp, SHA, (),
    )


def accepted_bundle(previous=None):
    review = {"reviewed_commit": SHA, "verdict": "APPROVE", "risk": "LOW", "blocking_findings": [], "tests_missing": []}
    return build_accepted_evidence(
        job_id=JOB, candidate_commit=SHA, accepted_commit=SHA,
        changed_files=["tests/test_evidence_lifecycle.py"],
        deterministic_validation=["focused passed"], claude_review=review,
        gemini_review=review, previous_event_sha256=previous,
        expected_job_id=JOB, expected_candidate_commit=SHA,
    )


def test_integrated_evidence_lifecycle_persists_recovers_and_continues(tmp_path):
    audit = AuditLog(tmp_path / "canonical.jsonl")
    store = CanonicalAuditEvidenceStore(audit)
    ledger = EvidenceLedger(TENANT, store)
    harness_record = append_harness_evidence(
        lifecycle(), ledger=ledger,
        correlation_id=f"fw-corr/{TENANT}/fwq-0200",
    )
    accepted_record = append_accepted_evidence(
        accepted_bundle(), expected_job_id=JOB, expected_candidate_commit=SHA,
        tenant_id=TENANT, actor_id="harness-controller",
        occurred_at="2026-09-11T00:00:01Z", ledger=ledger,
        correlation_id=f"fw-corr/{TENANT}/fwq-0200",
        evidence_references=(harness_record.envelope.evidence_id,),
    )
    recovered = CanonicalAuditEvidenceStore(AuditLog(audit.path)).recover(TENANT)
    assert recovered.tenant_snapshot(TENANT) == (harness_record, accepted_record)
    continued = append_harness_evidence(
        lifecycle("task_checkpointed", "2026-09-11T00:00:02Z"), ledger=recovered,
        correlation_id=f"fw-corr/{TENANT}/fwq-0200",
        evidence_references=(accepted_record.envelope.evidence_id,),
    )
    assert continued.envelope.previous_record_sha256 == accepted_record.record_sha256
    assert len(CanonicalAuditEvidenceStore(AuditLog(audit.path)).recover(TENANT).tenant_snapshot(TENANT)) == 3


def test_integrated_evidence_lifecycle_denies_replay_tamper_and_cross_tenant(tmp_path):
    audit = AuditLog(tmp_path / "canonical.jsonl")
    ledger = EvidenceLedger(TENANT, CanonicalAuditEvidenceStore(audit))
    fact = lifecycle()
    append_harness_evidence(fact, ledger=ledger)
    with pytest.raises(Exception, match="admission"):
        append_harness_evidence(fact, ledger=ledger)
    with pytest.raises(Exception, match="tenant"):
        append_accepted_evidence(
            accepted_bundle(), expected_job_id=JOB, expected_candidate_commit=SHA,
            tenant_id="tenant-other", actor_id="harness-controller",
            occurred_at="2026-09-11T00:00:01Z", ledger=ledger,
        )
    rows = [json.loads(line) for line in audit.path.read_text().splitlines()]
    rows[0]["record_sha256"] = "0" * 64
    audit.path.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
    with pytest.raises(EvidenceContractError, match="digest"):
        CanonicalAuditEvidenceStore(AuditLog(audit.path)).recover(TENANT)


def test_integrated_evidence_lifecycle_retains_hashes_without_authority(tmp_path):
    audit = AuditLog(tmp_path / "canonical.jsonl")
    record = append_harness_evidence(
        lifecycle(), ledger=EvidenceLedger(TENANT, CanonicalAuditEvidenceStore(audit)),
    )
    persisted = audit.path.read_text()
    assert "CLAUDE:APPROVED:LOW" not in persisted
    assert "bounded_source_edit" not in persisted
    assert record.envelope.authority_granted is False
    assert record.envelope.mode == "DRY_RUN" and record.envelope.deployment == "DISABLED"
