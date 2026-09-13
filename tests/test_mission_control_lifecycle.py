import pytest

from swarm.console import canonical_activity_snapshot, compose_canonical_activity
from swarm.mission_control import (
    MissionControlError,
    serialize_evidence_activity,
    serialize_harness_activity,
    serialize_incident_activity,
    serialize_model_mcp_activity,
    serialize_policy_ticket_activity,
)
from tests.test_mission_control import (
    evidence_record,
    incident_lifecycle,
    model_mcp_activity,
    policy_ticket_activity,
    project,
)


def canonical_providers():
    harness = project(tenant_id="tenant-a", task_tenants={"FWQ-0001": "tenant-a", "FWQ-0002": "tenant-a"})
    return {
        "harness": serialize_harness_activity(harness),
        "incident": serialize_incident_activity(incident_lifecycle()),
        "evidence": serialize_evidence_activity((evidence_record(),)),
        "policy_ticket": serialize_policy_ticket_activity(policy_ticket_activity()),
        "model_mcp": serialize_model_mcp_activity(model_mcp_activity()),
    }


def test_integrated_canonical_lifecycle_is_one_tenant_and_read_only():
    payload = compose_canonical_activity(canonical_providers())
    assert payload["data_mode"] == "CANONICAL"
    assert payload["tenant_id"] == "tenant-a"
    assert payload["safety"] == {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED"}
    assert set(payload["providers"]) == {"harness", "incident", "evidence", "policy_ticket", "model_mcp"}


def test_integrated_lifecycle_preserves_honest_partial_empty_and_unavailable_state():
    providers = canonical_providers()
    providers["incident"] = serialize_incident_activity(None)
    assert compose_canonical_activity(providers)["data_mode"] == "PARTIAL"
    empty = {
        "harness": serialize_harness_activity(None),
        "incident": serialize_incident_activity(None),
        "evidence": serialize_evidence_activity(None),
        "policy_ticket": serialize_policy_ticket_activity(None),
        "model_mcp": serialize_model_mcp_activity(None),
    }
    assert compose_canonical_activity(empty)["data_mode"] == "EMPTY"
    unavailable = {name: {**value, "data_mode": "UNAVAILABLE"} for name, value in empty.items()}
    assert compose_canonical_activity(unavailable)["data_mode"] == "UNAVAILABLE"


def test_integrated_lifecycle_rejects_cross_tenant_missing_state_and_authority_flags():
    providers = canonical_providers()
    providers["harness"] = serialize_harness_activity(project(tenant_id="tenant-b", task_tenants={"FWQ-0001": "tenant-b", "FWQ-0002": "tenant-b"}))
    with pytest.raises(MissionControlError, match="cross tenants"):
        compose_canonical_activity(providers)
    with pytest.raises(MissionControlError, match="incomplete"):
        compose_canonical_activity({key: value for key, value in canonical_providers().items() if key != "evidence"})
    forged = canonical_providers()
    forged["model_mcp"] = {**forged["model_mcp"], "safety": {**forged["model_mcp"]["safety"], "tool_executed": True}}
    with pytest.raises(MissionControlError, match="authority"):
        compose_canonical_activity(forged)
    forged = canonical_providers()
    forged["evidence"] = {**forged["evidence"], "data_mode": "EMPTY"}
    with pytest.raises(MissionControlError, match="exposed state"):
        compose_canonical_activity(forged)


def test_loopback_composition_fails_closed_on_cross_provider_tenant_conflict():
    canonical = canonical_providers()
    snapshot = canonical_activity_snapshot(
        harness=lambda: project(tenant_id="tenant-a", task_tenants={"FWQ-0001": "tenant-a", "FWQ-0002": "tenant-a"}),
        incident=incident_lifecycle,
        evidence=lambda: (evidence_record(),),
        policy_ticket=policy_ticket_activity,
        model_mcp=model_mcp_activity,
    )
    assert snapshot["data_mode"] == "CANONICAL"
    assert snapshot["providers"]["model_mcp"] == canonical["model_mcp"]
    denied = canonical_activity_snapshot(
        harness=lambda: project(tenant_id="tenant-b", task_tenants={"FWQ-0001": "tenant-b", "FWQ-0002": "tenant-b"}),
        incident=incident_lifecycle,
        evidence=lambda: (evidence_record(),),
        policy_ticket=policy_ticket_activity,
        model_mcp=model_mcp_activity,
    )
    assert denied["data_mode"] == "UNAVAILABLE"
    assert denied["providers"] is None
