from dataclasses import FrozenInstanceError, asdict

import pytest

from swarm.evidence import EvidenceContractError, EvidenceEnvelope, validate_evidence_envelope


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
