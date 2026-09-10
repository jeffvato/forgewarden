from dataclasses import FrozenInstanceError, asdict
from threading import Event, Thread

import pytest

from swarm.evidence import (
    EvidenceContractError, EvidenceEnvelope, EvidenceLedger,
    evidence_record_sha256, validate_evidence_envelope,
)


def envelope(**changes):
    value = {
        "schema_version": "1", "evidence_id": "fw-evid/tenant-a/task/0001",
        "tenant_id": "tenant-a", "event_type": "task_accepted",
        "actor_ref": "fw-id/harness-controller", "actor_tenant_id": "tenant-a",
        "subject_ref": "fw-task/fwq-9001", "subject_tenant_id": "tenant-a",
        "occurred_at": "2026-09-10T21:30:00Z", "classification": "INTERNAL",
        "payload_schema_id": "fw-schema/harness-lifecycle/1", "payload_sha256": "a" * 64,
        "previous_record_sha256": None, "correlation_id": "fw-corr/tenant-a/fwq-9001",
        "evidence_references": ("fw-evid/tenant-a/review/0001",),
        "mode": "DRY_RUN", "deployment": "DISABLED", "authority_granted": False,
    }
    value.update(changes)
    return value


def test_canonical_evidence_envelope_is_exact_immutable_and_payload_free():
    value = validate_evidence_envelope(envelope())
    assert isinstance(value, EvidenceEnvelope) and asdict(value) == envelope()
    assert not hasattr(value, "payload")
    with pytest.raises(FrozenInstanceError):
        value.classification = "PUBLIC"
    assert not any(hasattr(value, name) for name in (
        "append", "store", "sign", "export", "authorize", "issue_ticket", "deploy", "execute",
    ))


@pytest.mark.parametrize("change,match", [
    ({"schema_version": "2"}, "schema version"),
    ({"evidence_id": "fw-evid/tenant-b/task/0001"}, "tenant mismatch"),
    ({"actor_tenant_id": "tenant-b"}, "actor or subject tenant"),
    ({"subject_tenant_id": "tenant-b"}, "actor or subject tenant"),
    ({"occurred_at": "2026-02-30T21:30:00Z"}, "occurred_at"),
    ({"occurred_at": "2026-09-10T21:30:00+00:00"}, "canonical UTC"),
    ({"classification": "SECRET"}, "classification"),
    ({"payload_sha256": "a" * 63}, "payload_sha256"),
    ({"previous_record_sha256": "b" * 63}, "previous_record"),
    ({"correlation_id": "fw-corr/tenant-b/fwq-9001"}, "tenant mismatch"),
    ({"evidence_references": ("fw-evid/tenant-b/review/0001",)}, "tenant mismatch"),
    ({"evidence_references": ("fw-evid/tenant-a/z/1", "fw-evid/tenant-a/a/1")}, "sorted tuple"),
    ({"evidence_references": ("fw-evid/tenant-a/a/1",) * 2}, "unique"),
    ({"mode": "LIVE"}, "cannot grant authority"),
    ({"deployment": "ENABLED"}, "cannot grant authority"),
    ({"authority_granted": True}, "cannot grant authority"),
])
def test_invalid_or_cross_tenant_evidence_metadata_fails_closed(change, match):
    with pytest.raises(EvidenceContractError, match=match):
        validate_evidence_envelope(envelope(**change))


@pytest.mark.parametrize("field,value", [
    ("event_type", "Bearer abcdefghijklmnop"),
    ("payload_schema_id", "fw-schema/api_key=abcdefghijk"),
    ("actor_ref", "fw-id/sk-abcdefghijk"),
])
def test_secret_shaped_metadata_is_rejected(field, value):
    with pytest.raises(EvidenceContractError, match="secret-bearing"):
        validate_evidence_envelope(envelope(**{field: value}))


def test_unknown_raw_payload_and_mutable_reference_input_are_rejected():
    with pytest.raises(EvidenceContractError, match="field set"):
        validate_evidence_envelope(envelope() | {"payload": {"secret": "value"}})
    with pytest.raises(EvidenceContractError, match="sorted tuple"):
        validate_evidence_envelope(envelope(evidence_references=["fw-evid/tenant-a/review/0001"]))


def test_optional_and_reference_count_boundaries_are_explicit():
    minimal = validate_evidence_envelope(envelope(
        correlation_id=None, previous_record_sha256=None, evidence_references=(),
    ))
    assert minimal.correlation_id is None and minimal.evidence_references == ()
    references = tuple(f"fw-evid/tenant-a/reference/{index:03d}" for index in range(128))
    assert len(validate_evidence_envelope(envelope(evidence_references=references)).evidence_references) == 128
    with pytest.raises(EvidenceContractError, match="bounded"):
        validate_evidence_envelope(envelope(evidence_references=references + ("fw-evid/tenant-a/reference/128",)))


@pytest.mark.parametrize("change", [
    {"tenant_id": "t" * 129},
    {"evidence_id": "fw-evid/tenant-a/" + "x" * 240},
    {"event_type": " "},
    {"actor_ref": " fw-id/actor"},
])
def test_length_and_whitespace_boundaries_fail_closed(change):
    with pytest.raises(EvidenceContractError, match="invalid"):
        validate_evidence_envelope(envelope(**change))


def test_tenant_ledger_appends_exact_chain_after_durability():
    writes = []
    ledger = EvidenceLedger("tenant-a", lambda item, digest: writes.append((item, digest)))
    first = validate_evidence_envelope(envelope())
    first_record = ledger.append(first)
    second = validate_evidence_envelope(envelope(
        evidence_id="fw-evid/tenant-a/task/0002", payload_sha256="b" * 64,
        previous_record_sha256=first_record.record_sha256,
    ))
    second_record = ledger.append(second)
    assert first_record.record_sha256 == evidence_record_sha256(first)
    assert ledger.tenant_snapshot("tenant-a") == (first_record, second_record)
    assert writes == [(first, first_record.record_sha256), (second, second_record.record_sha256)]
    with pytest.raises(FrozenInstanceError):
        first_record.record_sha256 = "c" * 64


def test_ledger_denies_replay_forks_cross_tenant_and_invalid_input():
    ledger = EvidenceLedger("tenant-a", lambda *_args: None)
    first = validate_evidence_envelope(envelope())
    accepted = ledger.append(first)
    with pytest.raises(EvidenceContractError, match="previous-record"):
        ledger.append(validate_evidence_envelope(envelope(evidence_id="fw-evid/tenant-a/task/0002")))
    with pytest.raises(EvidenceContractError, match="duplicate or replay"):
        ledger.append(validate_evidence_envelope(envelope(previous_record_sha256=accepted.record_sha256)))
    with pytest.raises(EvidenceContractError, match="tenant mismatch"):
        ledger.append(validate_evidence_envelope(envelope(
            tenant_id="tenant-b", evidence_id="fw-evid/tenant-b/task/0001",
            actor_tenant_id="tenant-b", subject_tenant_id="tenant-b",
            correlation_id="fw-corr/tenant-b/fwq-9001",
            evidence_references=("fw-evid/tenant-b/review/0001",),
            previous_record_sha256=accepted.record_sha256,
        )))
    with pytest.raises(EvidenceContractError, match="validated"):
        ledger.append(envelope())
    with pytest.raises(EvidenceContractError, match="tenant mismatch"):
        ledger.tenant_snapshot("tenant-b")
    assert ledger.tenant_snapshot("tenant-a") == (accepted,)


def test_durability_failure_and_reentrant_or_concurrent_append_leave_no_state():
    failed = EvidenceLedger("tenant-a", lambda *_args: (_ for _ in ()).throw(OSError("offline")))
    first = validate_evidence_envelope(envelope())
    with pytest.raises(EvidenceContractError, match="durability write failed"):
        failed.append(first)
    assert failed.tenant_snapshot("tenant-a") == ()

    entered = Event()
    release = Event()
    ledger = None
    reentrant_errors = []

    def sink(item, _digest):
        try:
            ledger.append(item)
        except EvidenceContractError as exc:
            reentrant_errors.append(str(exc))
        entered.set()
        assert release.wait(2)

    ledger = EvidenceLedger("tenant-a", sink)
    worker = Thread(target=lambda: ledger.append(first))
    worker.start()
    assert entered.wait(2)
    with pytest.raises(EvidenceContractError, match="already pending"):
        ledger.append(first)
    release.set()
    worker.join(2)
    assert not worker.is_alive()
    assert reentrant_errors == ["Evidence append is already pending"]
    assert len(ledger.tenant_snapshot("tenant-a")) == 1


def test_ledger_and_sink_receive_no_raw_payload_or_authority_methods():
    captured = []
    ledger = EvidenceLedger("tenant-a", lambda item, digest: captured.append((item, digest)))
    record = ledger.append(validate_evidence_envelope(envelope()))
    assert captured == [(record.envelope, record.record_sha256)]
    assert not hasattr(record.envelope, "payload")
    assert not any(hasattr(ledger, name) for name in (
        "sign", "export", "authorize", "issue_ticket", "deploy", "execute", "rollback",
    ))
