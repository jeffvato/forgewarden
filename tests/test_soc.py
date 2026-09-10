from dataclasses import FrozenInstanceError

import pytest

from swarm.soc import MAX_INCIDENT_REFS, SOCIncidentDenied, project_soc_incident


def incident(**changes):
    value = {
        "incident_id": "incident-1", "tenant_id": "tenant-a",
        "title": "Fixture incident", "severity": "HIGH", "status": "OPEN",
        "created_at_epoch": 100, "updated_at_epoch": 110,
        "affected_refs": ["asset/device-a"],
        "normalized_event_refs": ["event/event-1"],
        "evidence_refs": ["evidence/record-1"], "disposition": "NONE",
    }
    value.update(changes)
    return value


def test_incident_projection_is_immutable_reference_only_and_evidence_first():
    calls = []
    result = project_soc_incident(incident(), tenant_id="tenant-a", now_epoch=120, audit=lambda *args: calls.append(args))
    assert result.normalized_event_refs == ("event/event-1",)
    assert result.evidence_refs == ("evidence/record-1",)
    assert result.mode == "DRY_RUN" and result.action == "RECORD_ONLY"
    assert calls[0][0] == "soc_incident_projected"
    assert calls[0][1]["response_executed"] is False and calls[0][1]["deployment"] == "DISABLED"
    assert "title" not in calls[0][1]
    with pytest.raises(FrozenInstanceError):
        result.status = "CLOSED"


@pytest.mark.parametrize("field,values", [
    ("severity", ("LOW", "MEDIUM", "HIGH", "CRITICAL")),
    ("status", ("OPEN", "TRIAGED", "INVESTIGATING")),
])
def test_supported_active_states_are_exact(field, values):
    for value in values:
        assert project_soc_incident(incident(**{field: value}), tenant_id="tenant-a", now_epoch=120, audit=lambda *_args: None)


@pytest.mark.parametrize("status,disposition", [
    ("RESOLVED", "TRUE_POSITIVE"), ("CLOSED", "FALSE_POSITIVE"),
    ("CLOSED", "MITIGATED"), ("CLOSED", "ACCEPTED_RISK"),
])
def test_terminal_state_requires_an_explicit_disposition(status, disposition):
    result = project_soc_incident(incident(status=status, disposition=disposition), tenant_id="tenant-a", now_epoch=120, audit=lambda *_args: None)
    assert result.status == status and result.disposition == disposition


@pytest.mark.parametrize("change,reason", [
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"severity": "high"}, "INCIDENT_STATE_INVALID"),
    ({"status": "RESPONDING"}, "INCIDENT_STATE_INVALID"),
    ({"status": "OPEN", "disposition": "MITIGATED"}, "INCIDENT_DISPOSITION_INVALID"),
    ({"status": "CLOSED", "disposition": "NONE"}, "INCIDENT_DISPOSITION_INVALID"),
    ({"created_at_epoch": 111, "updated_at_epoch": 110}, "TIME_INVALID"),
    ({"extra": "value"}, "INCIDENT_SCHEMA_INVALID"),
])
def test_invalid_cross_tenant_or_unsupported_incident_facts_deny(change, reason):
    with pytest.raises(SOCIncidentDenied, match=reason):
        project_soc_incident(incident(**change), tenant_id="tenant-a", now_epoch=120, audit=lambda *_args: None)


@pytest.mark.parametrize("field", ["affected_refs", "normalized_event_refs", "evidence_refs"])
def test_reference_lists_are_required_unique_and_bounded(field):
    for invalid, reason in (([], "INVALID"), (["same", "same"], "DUPLICATE"), ([str(i) for i in range(MAX_INCIDENT_REFS + 1)], "INVALID")):
        with pytest.raises(SOCIncidentDenied, match=reason):
            project_soc_incident(incident(**{field: invalid}), tenant_id="tenant-a", now_epoch=120, audit=lambda *_args: None)


def test_evidence_failure_returns_no_projection():
    with pytest.raises(SOCIncidentDenied, match="EVIDENCE_WRITE_FAILED"):
        project_soc_incident(
            incident(), tenant_id="tenant-a", now_epoch=120,
            audit=lambda *_args: (_ for _ in ()).throw(OSError("offline")),
        )
