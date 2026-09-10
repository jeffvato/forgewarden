from dataclasses import FrozenInstanceError

import pytest

from swarm.soc import MAX_INCIDENT_REFS, MAX_STORY_INCIDENTS, MAX_TIMELINE_ENTRIES, SOCIncidentDenied, project_attack_story, project_incident_timeline, project_soc_dry_run_lifecycle, project_soc_incident, propose_response_playbook


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


def projected(**changes):
    return project_soc_incident(incident(**changes), tenant_id="tenant-a", now_epoch=200, audit=lambda *_args: None)


def test_attack_story_correlates_exact_shared_references_deterministically():
    calls = []
    first = projected(incident_id="incident-b", severity="MEDIUM", created_at_epoch=100, updated_at_epoch=120)
    second = projected(
        incident_id="incident-a", severity="CRITICAL", created_at_epoch=90,
        updated_at_epoch=130, affected_refs=["asset/device-a", "identity/user-a"],
        normalized_event_refs=["event/event-1", "event/event-2"],
        evidence_refs=["evidence/record-2"],
    )
    story = project_attack_story((first, second), story_id="story-1", tenant_id="tenant-a", audit=lambda *args: calls.append(args))
    assert story.incident_ids == ("incident-a", "incident-b")
    assert story.shared_affected_refs == ("asset/device-a",)
    assert story.shared_normalized_event_refs == ("event/event-1",)
    assert story.severity == "CRITICAL" and story.first_seen_epoch == 90 and story.last_seen_epoch == 130
    assert story.mode == "DRY_RUN" and story.action == "CORRELATE_ONLY"
    assert calls[0][0] == "soc_attack_story_projected" and calls[0][1]["response_executed"] is False
    assert "title" not in calls[0][1] and "evidence_refs" not in calls[0][1]


def test_attack_story_accepts_shared_event_without_shared_asset():
    first = projected(incident_id="incident-a", affected_refs=["asset/a"])
    second = projected(incident_id="incident-b", affected_refs=["asset/b"], evidence_refs=["evidence/record-2"])
    assert project_attack_story((first, second), story_id="story-1", tenant_id="tenant-a", audit=lambda *_args: None).shared_affected_refs == ()


def test_attack_story_denies_uncorrelated_duplicate_and_cross_tenant_incidents():
    first = projected(incident_id="incident-a", affected_refs=["asset/a"], normalized_event_refs=["event/a"])
    second = projected(incident_id="incident-b", affected_refs=["asset/b"], normalized_event_refs=["event/b"], evidence_refs=["evidence/record-2"])
    with pytest.raises(SOCIncidentDenied, match="STORY_NOT_CORRELATED"):
        project_attack_story((first, second), story_id="story-1", tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="STORY_INCIDENT_DUPLICATE"):
        project_attack_story((first, first), story_id="story-1", tenant_id="tenant-a", audit=lambda *_args: None)
    foreign = project_soc_incident(incident(incident_id="foreign", tenant_id="tenant-b"), tenant_id="tenant-b", now_epoch=200, audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="STORY_TENANT_MISMATCH"):
        project_attack_story((first, foreign), story_id="story-1", tenant_id="tenant-a", audit=lambda *_args: None)


def test_attack_story_revalidates_authority_bounds_and_evidence():
    first = projected(incident_id="incident-a")
    second = projected(incident_id="incident-b", evidence_refs=["evidence/record-2"])
    from dataclasses import replace
    with pytest.raises(SOCIncidentDenied, match="STORY_AUTHORITY_INVALID"):
        project_attack_story((first, replace(second, mode="LIVE")), story_id="story-1", tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="STORY_INPUT_INVALID"):
        project_attack_story(tuple(first for _ in range(MAX_STORY_INCIDENTS + 1)), story_id="story-1", tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="EVIDENCE_WRITE_FAILED"):
        project_attack_story(
            (first, second), story_id="story-1", tenant_id="tenant-a",
            audit=lambda *_args: (_ for _ in ()).throw(OSError("offline")),
        )


def timeline_entry(entry_id="entry-1", **changes):
    value = {
        "entry_id": entry_id, "tenant_id": "tenant-a", "incident_id": "incident-1",
        "occurred_at_epoch": 105, "entry_type": "DETECTION",
        "actor_ref": "actor/sensor", "source_ref": "event/event-1",
        "evidence_ref": "evidence/record-1",
    }
    value.update(changes)
    return value


def test_incident_timeline_is_immutable_deterministically_ordered_and_evidence_first():
    calls = []
    active = projected(updated_at_epoch=130)
    entries = (
        timeline_entry("entry-b", occurred_at_epoch=120, entry_type="REVIEW", actor_ref="actor/reviewer", source_ref="review/review-1", evidence_ref="evidence/review-1"),
        timeline_entry("entry-a", occurred_at_epoch=105),
        timeline_entry("entry-c", occurred_at_epoch=120, entry_type="APPROVAL", actor_ref="actor/approver", source_ref="approval/approval-1", evidence_ref="evidence/approval-1"),
    )
    timeline = project_incident_timeline(active, entries, tenant_id="tenant-a", audit=lambda *args: calls.append(args))
    assert tuple(item.entry_id for item in timeline.entries) == ("entry-a", "entry-b", "entry-c")
    assert timeline.mode == "DRY_RUN" and timeline.action == "PROJECT_ONLY"
    assert calls[0][0] == "soc_incident_timeline_projected"
    assert calls[0][1]["response_executed"] is False and "title" not in calls[0][1]


def test_terminal_incident_requires_one_final_disposition_entry():
    closed = projected(status="CLOSED", disposition="MITIGATED", updated_at_epoch=130)
    result = project_incident_timeline(closed, (
        timeline_entry("entry-a", occurred_at_epoch=105),
        timeline_entry("entry-z", occurred_at_epoch=130, entry_type="DISPOSITION", actor_ref="actor/analyst", source_ref="disposition/MITIGATED", evidence_ref="evidence/disposition-1"),
    ), tenant_id="tenant-a", audit=lambda *_args: None)
    assert result.entries[-1].entry_type == "DISPOSITION"


@pytest.mark.parametrize("entries,reason", [
    ((timeline_entry(), timeline_entry()), "TIMELINE_ENTRY_DUPLICATE"),
    ((timeline_entry(tenant_id="tenant-b"),), "TIMELINE_BINDING_MISMATCH"),
    ((timeline_entry(incident_id="incident-other"),), "TIMELINE_BINDING_MISMATCH"),
    ((timeline_entry(entry_type="EXECUTE"),), "TIMELINE_ENTRY_INVALID"),
    ((timeline_entry(occurred_at_epoch=99),), "TIMELINE_ENTRY_INVALID"),
    ((timeline_entry(extra="value"),), "TIMELINE_ENTRY_INVALID"),
])
def test_incident_timeline_denies_invalid_duplicate_or_cross_tenant_entries(entries, reason):
    with pytest.raises(SOCIncidentDenied, match=reason):
        project_incident_timeline(projected(), entries, tenant_id="tenant-a", audit=lambda *_args: None)


def test_incident_timeline_denies_terminal_order_active_disposition_and_excess():
    closed = projected(status="CLOSED", disposition="MITIGATED", updated_at_epoch=130)
    with pytest.raises(SOCIncidentDenied, match="TIMELINE_DISPOSITION_INVALID"):
        project_incident_timeline(closed, (timeline_entry(),), tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="TIMELINE_DISPOSITION_INVALID"):
        project_incident_timeline(projected(), (timeline_entry(entry_type="DISPOSITION"),), tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="TIMELINE_INPUT_INVALID"):
        project_incident_timeline(projected(), tuple(timeline_entry(str(index)) for index in range(MAX_TIMELINE_ENTRIES + 1)), tenant_id="tenant-a", audit=lambda *_args: None)


def test_incident_timeline_revalidates_incident_authority_and_evidence_failure():
    from dataclasses import replace
    with pytest.raises(SOCIncidentDenied, match="STORY_AUTHORITY_INVALID"):
        project_incident_timeline(replace(projected(), action="RESPOND"), (timeline_entry(),), tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="EVIDENCE_WRITE_FAILED"):
        project_incident_timeline(
            projected(), (timeline_entry(),), tenant_id="tenant-a",
            audit=lambda *_args: (_ for _ in ()).throw(OSError("offline")),
        )


def playbook_step(step_id="step-1", **changes):
    value = {
        "step_id": step_id, "tenant_id": "tenant-a", "incident_id": "incident-1",
        "action_class": "ANALYZE", "capability": "telemetry.read",
        "resource_ref": "asset/device-a", "depends_on": [],
        "policy_decision_ref": "policy/decision-1", "approval_ref": None,
        "action_ticket_ref": None, "checkpoint_ref": None, "rollback_ref": None,
    }
    value.update(changes)
    return value


def mutating_step(step_id="step-2", **changes):
    value = playbook_step(
        step_id, action_class="ISOLATE_ENDPOINT", capability="endpoint.isolate.request",
        depends_on=["step-1"], approval_ref="approval/one",
        action_ticket_ref="ticket/one", checkpoint_ref="checkpoint/one",
        rollback_ref="rollback/one",
    )
    value.update(changes)
    return value


def test_playbook_proposal_orders_dependencies_and_remains_inert_evidence_first():
    calls = []
    proposal = propose_response_playbook(
        projected(), (mutating_step(), playbook_step()), playbook_id="playbook-1",
        tenant_id="tenant-a", audit=lambda *args: calls.append(args),
    )
    assert tuple(step.step_id for step in proposal.steps) == ("step-1", "step-2")
    assert proposal.mode == "DRY_RUN" and proposal.deployment == "DISABLED"
    assert proposal.kill_switch == "ENGAGED" and not proposal.authority_expanded
    assert proposal.action == "PROPOSE_ONLY"
    assert calls[0][0] == "soc_response_playbook_proposed" and calls[0][1]["response_executed"] is False


@pytest.mark.parametrize("change,reason", [
    ({"action_class": "DEPLOY"}, "PLAYBOOK_ACTION_UNSUPPORTED"),
    ({"tenant_id": "tenant-b"}, "PLAYBOOK_BINDING_MISMATCH"),
    ({"incident_id": "incident-other"}, "PLAYBOOK_BINDING_MISMATCH"),
    ({"extra": "value"}, "PLAYBOOK_STEP_INVALID"),
])
def test_playbook_denies_unsupported_malformed_or_cross_tenant_steps(change, reason):
    with pytest.raises(SOCIncidentDenied, match=reason):
        propose_response_playbook(projected(), (playbook_step(**change),), playbook_id="playbook-1", tenant_id="tenant-a", audit=lambda *_args: None)


def test_playbook_mutation_requires_all_authority_and_recovery_references():
    for field in ("approval_ref", "action_ticket_ref", "checkpoint_ref", "rollback_ref"):
        with pytest.raises(SOCIncidentDenied, match="PLAYBOOK_MUTATION_AUTHORITY_MISSING"):
            propose_response_playbook(projected(), (mutating_step(depends_on=[], **{field: None}),), playbook_id="playbook-1", tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="PLAYBOOK_READ_ONLY_AUTHORITY_INVALID"):
        propose_response_playbook(projected(), (playbook_step(action_ticket_ref="ticket/forbidden"),), playbook_id="playbook-1", tenant_id="tenant-a", audit=lambda *_args: None)


def test_playbook_denies_duplicate_unknown_and_cyclic_dependencies():
    with pytest.raises(SOCIncidentDenied, match="PLAYBOOK_STEP_DUPLICATE"):
        propose_response_playbook(projected(), (playbook_step(), playbook_step()), playbook_id="playbook-1", tenant_id="tenant-a", audit=lambda *_args: None)
    with pytest.raises(SOCIncidentDenied, match="PLAYBOOK_DEPENDENCY_UNKNOWN"):
        propose_response_playbook(projected(), (playbook_step(depends_on=["missing"]),), playbook_id="playbook-1", tenant_id="tenant-a", audit=lambda *_args: None)
    cycle = (playbook_step("step-1", depends_on=["step-2"]), playbook_step("step-2", depends_on=["step-1"]))
    with pytest.raises(SOCIncidentDenied, match="PLAYBOOK_DEPENDENCY_CYCLE"):
        propose_response_playbook(projected(), cycle, playbook_id="playbook-1", tenant_id="tenant-a", audit=lambda *_args: None)


def test_playbook_evidence_failure_returns_no_proposal():
    with pytest.raises(SOCIncidentDenied, match="EVIDENCE_WRITE_FAILED"):
        propose_response_playbook(
            projected(), (playbook_step(),), playbook_id="playbook-1", tenant_id="tenant-a",
            audit=lambda *_args: (_ for _ in ()).throw(OSError("offline")),
        )


def lifecycle(audit, **changes):
    values = {
        "records": (
            incident(),
            incident(incident_id="incident-2", evidence_refs=["evidence/record-2"]),
        ),
        "primary_incident_id": "incident-1", "story_id": "story-1",
        "timeline_entries": (timeline_entry(),), "playbook_id": "playbook-1",
        "playbook_steps": (playbook_step(), mutating_step()),
        "tenant_id": "tenant-a", "now_epoch": 120,
        "accepted_policy_decision_refs": ("policy/decision-1",),
        "accepted_action_ticket_refs": ("ticket/one",),
        "kill_switch_state": "ENGAGED", "deployment_state": "DISABLED",
        "audit": audit,
    }
    values.update(changes)
    return project_soc_dry_run_lifecycle(**values)


def test_integrated_lifecycle_is_reference_only_deterministic_and_uses_one_evidence_sink():
    calls = []
    result = lifecycle(lambda *args: calls.append(args))
    assert tuple(item.incident_id for item in result.incidents) == ("incident-1", "incident-2")
    assert result.attack_story.incident_ids == ("incident-1", "incident-2")
    assert result.timeline.incident_id == result.playbook.incident_id == "incident-1"
    assert tuple(step.step_id for step in result.playbook.steps) == ("step-1", "step-2")
    assert [event for event, _ in calls] == [
        "soc_incident_projected", "soc_incident_projected",
        "soc_attack_story_projected", "soc_incident_timeline_projected",
        "soc_response_playbook_proposed",
    ]
    assert all(evidence["tenant_id"] == "tenant-a" for _, evidence in calls)
    assert result.mode == "DRY_RUN" and result.deployment == "DISABLED"
    assert result.kill_switch == "ENGAGED" and not result.authority_expanded
    with pytest.raises(FrozenInstanceError):
        result.mode = "LIVE"


@pytest.mark.parametrize("failed_event,expected_events", [
    ("soc_incident_projected", []),
    ("soc_attack_story_projected", ["soc_incident_projected", "soc_incident_projected"]),
    ("soc_incident_timeline_projected", ["soc_incident_projected", "soc_incident_projected", "soc_attack_story_projected"]),
    ("soc_response_playbook_proposed", ["soc_incident_projected", "soc_incident_projected", "soc_attack_story_projected", "soc_incident_timeline_projected"]),
])
def test_integrated_lifecycle_evidence_failure_stops_all_later_stages(failed_event, expected_events):
    calls = []

    def audit(event, evidence):
        if event == failed_event:
            raise OSError("offline")
        calls.append((event, evidence))

    with pytest.raises(SOCIncidentDenied, match="EVIDENCE_WRITE_FAILED"):
        lifecycle(audit)
    assert [event for event, _ in calls] == expected_events


@pytest.mark.parametrize("changes,reason", [
    ({"records": (incident(tenant_id="tenant-b"), incident(incident_id="incident-2"))}, "TENANT_MISMATCH"),
    ({"accepted_policy_decision_refs": ("policy/other",)}, "LIFECYCLE_POLICY_REFERENCE_DENIED"),
    ({"accepted_action_ticket_refs": ()}, "LIFECYCLE_TICKET_REFERENCE_DENIED"),
    ({"kill_switch_state": "DISENGAGED"}, "LIFECYCLE_SAFETY_STATE_INVALID"),
    ({"deployment_state": "ENABLED"}, "LIFECYCLE_SAFETY_STATE_INVALID"),
])
def test_integrated_lifecycle_denies_boundary_authority_and_safety_failures(changes, reason):
    with pytest.raises(SOCIncidentDenied, match=reason):
        lifecycle(lambda *_args: None, **changes)
