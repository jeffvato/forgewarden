from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.action_ticket import ActionTicket, ActionTicketRegistry
from swarm.asoc import HMACLeaseSigner
from swarm.data_security import DataSecurityObservationDenied, bind_data_security_references, classify_data_security_observation, normalize_data_security_observation, propose_data_security_dlp


def fixture(**overrides):
    value = {
        "event_id": "dspm-1", "tenant_id": "tenant-a", "observed_at_epoch": 100,
        "data_asset_ref": "fw-data/tenant-a/customer-records",
        "location_asset_ref": "fw-asset/tenant-a/database-1",
        "classification": "RESTRICTED", "location_class": "DATABASE",
        "owner_identity_ref": "fw-id/tenant-a.data-owner",
        "access_path": "SHARED", "copy_count": 3,
        "encryption_state": "ENCRYPTED", "ai_access_state": "NONE",
        "policy_state": "COMPLIANT", "evidence_ref": "fw-evid/tenant-a/dspm-1",
    }
    value.update(overrides)
    return value


def test_data_security_observation_is_immutable_evidence_first_and_minimized():
    evidence = []
    value = normalize_data_security_observation(
        fixture(), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *args: evidence.append(args),
    )
    assert value.classification == "RESTRICTED" and value.copy_count == 3
    assert value.trust == "UNTRUSTED_DATA"
    assert value.mode == "DRY_RUN" and value.action == "DETECT_ONLY"
    assert value.authority_granted is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert "owner_identity_ref" not in evidence[0][1]
    with pytest.raises(FrozenInstanceError):
        value.copy_count = 4


@pytest.mark.parametrize("value,reason", [
    (fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (fixture(data_asset_ref="fw-data/tenant-b/customer-records"), "DATA_ASSET_REF_INVALID"),
    (fixture(location_asset_ref="fw-asset/tenant-b/database-1"), "LOCATION_ASSET_REF_INVALID"),
    (fixture(owner_identity_ref="fw-id/tenant-b.data-owner"), "OWNER_IDENTITY_REF_INVALID"),
    (fixture(evidence_ref="fw-evid/tenant-b/dspm-1"), "EVIDENCE_REF_INVALID"),
    (fixture(classification="SECRET"), "CLASSIFICATION_INVALID"),
    (fixture(location_class="INTERNET"), "LOCATION_CLASS_INVALID"),
    (fixture(access_path="ROOT"), "ACCESS_PATH_INVALID"),
    (fixture(encryption_state="DECRYPTED"), "ENCRYPTION_STATE_INVALID"),
    (fixture(ai_access_state="ADMIN"), "AI_ACCESS_STATE_INVALID"),
    (fixture(policy_state="BYPASSED"), "POLICY_STATE_INVALID"),
    (fixture(copy_count=True), "COPY_COUNT_INVALID"),
    (fixture(copy_count=100001), "COPY_COUNT_INVALID"),
    (fixture(observed_at_epoch=151), "OBSERVED_AT_INVALID"),
    (fixture(extra="content"), "FIXTURE_INVALID"),
])
def test_data_security_observation_denies_invalid_or_cross_tenant_input(value, reason):
    evidence = []
    with pytest.raises(DataSecurityObservationDenied, match=reason):
        normalize_data_security_observation(
            value, tenant_id="tenant-a", now_epoch=150,
            audit=lambda *args: evidence.append(args),
        )
    assert evidence == []


@pytest.mark.parametrize("copy_count", [0, 100000])
def test_data_security_observation_accepts_copy_count_boundaries(copy_count):
    assert normalize_data_security_observation(
        fixture(copy_count=copy_count), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *_args: None,
    ).copy_count == copy_count


def test_data_security_observation_denies_non_json_and_evidence_failure():
    with pytest.raises(DataSecurityObservationDenied, match="FIXTURE_INVALID"):
        normalize_data_security_observation(
            fixture(copy_count={3}), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )
    with pytest.raises(DataSecurityObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_data_security_observation(
            fixture(), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("tenant_id,now_epoch,reason", [
    ("", 150, "TENANT_INVALID"),
    ("tenant-a", True, "OBSERVED_AT_INVALID"),
    ("tenant-a", -1, "OBSERVED_AT_INVALID"),
])
def test_data_security_observation_denies_invalid_expected_boundary(tenant_id, now_epoch, reason):
    with pytest.raises(DataSecurityObservationDenied, match=reason):
        normalize_data_security_observation(
            fixture(), tenant_id=tenant_id, now_epoch=now_epoch,
            audit=lambda *_args: None,
        )


@pytest.mark.parametrize("invalid", [None, [], "fixture"])
def test_data_security_observation_denies_non_mapping_fixture(invalid):
    with pytest.raises(DataSecurityObservationDenied, match="FIXTURE_INVALID"):
        normalize_data_security_observation(
            invalid, tenant_id="tenant-a", now_epoch=150, audit=lambda *_args: None,
        )


@pytest.mark.parametrize("invalid", [None, 1, "audit"])
def test_data_security_observation_denies_non_callable_audit(invalid):
    with pytest.raises(DataSecurityObservationDenied, match="FIXTURE_INVALID"):
        normalize_data_security_observation(
            fixture(), tenant_id="tenant-a", now_epoch=150, audit=invalid,
        )


def test_data_security_observation_denies_oversized_fixture():
    with pytest.raises(DataSecurityObservationDenied, match="FIXTURE_INVALID"):
        normalize_data_security_observation(
            fixture(event_id="x" * 32768), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )


def observation(**overrides):
    return normalize_data_security_observation(
        fixture(**overrides), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *_args: None,
    )


@pytest.mark.parametrize("changes,risk,recommendations", [
    ({"access_path": "EXTERNAL", "ai_access_state": "UNAPPROVED"}, "CRITICAL", ("WARN", "PROPOSE_DLP")),
    ({"policy_state": "VIOLATION"}, "HIGH", ("WARN", "PROPOSE_DLP")),
    ({"classification": "INTERNAL", "encryption_state": "UNENCRYPTED"}, "MEDIUM", ("WARN",)),
    ({"classification": "PUBLIC", "copy_count": 0}, "LOW", ("WARN",)),
])
def test_data_security_classification_is_deterministic_and_advisory(changes, risk, recommendations):
    evidence = []
    value = classify_data_security_observation(
        observation(**changes), tenant_id="tenant-a",
        audit=lambda *args: evidence.append(args),
    )
    assert value.risk == risk and value.recommendations == recommendations
    assert value.signals == tuple(sorted(value.signals))
    assert value.action == "ADVISE_ONLY" and value.authority_granted is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert evidence[0][1]["response_executed"] is False


def test_data_security_classification_denies_contradictory_ai_workflow_facts():
    with pytest.raises(DataSecurityObservationDenied, match="FACTS_CONTRADICTORY"):
        classify_data_security_observation(
            observation(location_class="AI_WORKFLOW", ai_access_state="NONE"),
            tenant_id="tenant-a", audit=lambda *_args: None,
        )


def test_data_security_classification_denies_cross_tenant_authority_and_evidence_failure():
    admitted = observation()
    with pytest.raises(DataSecurityObservationDenied, match="TENANT_MISMATCH"):
        classify_data_security_observation(
            admitted, tenant_id="tenant-b", audit=lambda *_args: None,
        )
    with pytest.raises(DataSecurityObservationDenied, match="OBSERVATION_AUTHORITY_INVALID"):
        classify_data_security_observation(
            replace(admitted, action="ENFORCE"), tenant_id="tenant-a",
            audit=lambda *_args: None,
        )
    with pytest.raises(DataSecurityObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        classify_data_security_observation(
            admitted, tenant_id="tenant-a",
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("invalid", [None, {}, "observation"])
def test_data_security_classification_denies_invalid_observation(invalid):
    with pytest.raises(DataSecurityObservationDenied, match="OBSERVATION_INVALID"):
        classify_data_security_observation(
            invalid, tenant_id="tenant-a", audit=lambda *_args: None,
        )


def finding():
    return classify_data_security_observation(
        observation(policy_state="VIOLATION"), tenant_id="tenant-a",
        audit=lambda *_args: None,
    )


def binding_kwargs(**overrides):
    values = {
        "tenant_id": "tenant-a", "saas_ref": "fw-saas/tenant-a/storage-1",
        "supply_ref": "fw-component/tenant-a/repository-1",
        "ai_workflow_ref": "fw-workflow/tenant-a/agent-task-1",
        "policy_decision_ref": "fw-policy/tenant-a/dspm-1",
        "soc_incident_ref": "fw-incident/tenant-a/dspm-1",
        "evidence_refs": ("fw-evid/tenant-a/dspm-1",),
    }
    values.update(overrides)
    return values


def test_data_security_reference_binding_reuses_canonical_owners_evidence_first():
    evidence = []
    value = bind_data_security_references(
        finding(), **binding_kwargs(), audit=lambda *args: evidence.append(args),
    )
    assert value.data_asset_ref == "fw-data/tenant-a/customer-records"
    assert value.owner_identity_ref == "fw-id/tenant-a.data-owner"
    assert value.saas_ref == "fw-saas/tenant-a/storage-1"
    assert value.action == "CORRELATE_ONLY" and value.authority_granted is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert evidence[0][1]["response_executed"] is False


@pytest.mark.parametrize("changes,reason", [
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"saas_ref": "fw-saas/tenant-b/storage-1"}, "SAAS_REF_INVALID"),
    ({"supply_ref": "fw-vuln/tenant-a/repository-1"}, "SUPPLY_REF_INVALID"),
    ({"ai_workflow_ref": "fw-workflow/tenant-b/agent-task-1"}, "AI_WORKFLOW_REF_INVALID"),
    ({"policy_decision_ref": "fw-policy/tenant-b/dspm-1"}, "POLICY_REF_INVALID"),
    ({"soc_incident_ref": "fw-incident/tenant-b/dspm-1"}, "SOC_INCIDENT_REF_INVALID"),
    ({"evidence_refs": ()}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": ("fw-vuln/tenant-a/dspm-1",)}, "EVIDENCE_REFS_INVALID"),
    ({"evidence_refs": ("fw-evid/tenant-a/dspm-1", "fw-evid/tenant-a/dspm-1")}, "EVIDENCE_REFS_INVALID"),
])
def test_data_security_reference_binding_denies_invalid_or_cross_tenant_refs(changes, reason):
    with pytest.raises(DataSecurityObservationDenied, match=reason):
        bind_data_security_references(
            finding(), **binding_kwargs(**changes), audit=lambda *_args: None,
        )


def test_data_security_reference_binding_denies_forged_finding_and_evidence_failure():
    source = finding()
    with pytest.raises(DataSecurityObservationDenied, match="FINDING_INVALID"):
        bind_data_security_references(
            replace(source, authority_granted=True), **binding_kwargs(),
            audit=lambda *_args: None,
        )
    with pytest.raises(DataSecurityObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        bind_data_security_references(
            source, **binding_kwargs(),
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


def reference_binding():
    return bind_data_security_references(
        finding(), **binding_kwargs(), audit=lambda *_args: None,
    )


def tickets(**overrides):
    registry = ActionTicketRegistry(HMACLeaseSigner({"key-1": b"test-only-key-material"}))
    values = {
        "ticket_id": "ticket-1", "tenant_id": "tenant-a",
        "subject_agent_id": "agent-1", "lease_id": "lease-1",
        "capability": "dspm.dlp.propose",
        "resource": "fw-data/tenant-a/customer-records",
        "action_class": "DSPM_DLP_PROPOSAL", "issued_by": "operator-1",
        "approval_reference": "approval-1", "policy_version": "policy-v1",
        "issued_at": 100, "expires_at": 200, "key_reference": "key-1",
    }
    values.update(overrides)
    registry.issue(ActionTicket(**values))
    return registry


def proposal_kwargs(**overrides):
    values = {
        "tickets": tickets(), "ticket_id": "ticket-1",
        "target_ref": "fw-data/tenant-a/customer-records",
        "policy_decision_ref": "fw-policy/tenant-a/dspm-1",
        "subject_agent_id": "agent-1", "lease_id": "lease-1",
        "policy_version": "policy-v1", "now": 150,
        "kill_switch_state": "ENGAGED", "audit": lambda *_args: None,
    }
    values.update(overrides)
    return values


def test_data_security_dlp_proposal_consumes_ticket_and_never_executes():
    evidence = []
    args = proposal_kwargs(audit=lambda *items: evidence.append(items))
    value = propose_data_security_dlp(reference_binding(), **args)
    assert value.risk == "HIGH" and value.action_class == "DSPM_DLP_PROPOSAL"
    assert value.disposition == "PROPOSE_ONLY"
    assert value.mode == "DRY_RUN" and value.deployment == "DISABLED"
    assert value.kill_switch == "ENGAGED"
    assert value.authority_granted is False and value.response_executed is False
    assert evidence[0][1]["response_executed"] is False
    with pytest.raises(DataSecurityObservationDenied, match="ACTION_TICKET_DENIED"):
        propose_data_security_dlp(reference_binding(), **args)


@pytest.mark.parametrize("changes,reason", [
    ({"kill_switch_state": "CLEAR"}, "KILL_SWITCH_NOT_ENGAGED"),
    ({"target_ref": "fw-data/tenant-b/customer-records"}, "PROPOSAL_REF_INVALID"),
    ({"target_ref": "fw-data/tenant-a/other"}, "PROPOSAL_REF_INVALID"),
    ({"target_ref": "fw-asset/tenant-a/customer-records"}, "PROPOSAL_REF_INVALID"),
    ({"policy_decision_ref": "fw-policy/tenant-b/dspm-1"}, "PROPOSAL_REF_INVALID"),
    ({"policy_decision_ref": "policy-without-prefix"}, "PROPOSAL_REF_INVALID"),
    ({"ticket_id": "missing-ticket"}, "ACTION_TICKET_DENIED"),
    ({"subject_agent_id": "agent-2"}, "ACTION_TICKET_DENIED"),
    ({"lease_id": "lease-2"}, "ACTION_TICKET_DENIED"),
    ({"policy_version": "policy-v2"}, "ACTION_TICKET_DENIED"),
    ({"now": 200}, "ACTION_TICKET_DENIED"),
])
def test_data_security_dlp_proposal_denies_boundary_mismatch(changes, reason):
    with pytest.raises(DataSecurityObservationDenied, match=reason):
        propose_data_security_dlp(
            reference_binding(), **proposal_kwargs(**changes),
        )


def test_data_security_dlp_proposal_revalidates_source_and_evidence():
    for changes in (
        {"risk": "MEDIUM"}, {"trust": "TRUSTED"}, {"mode": "LIVE"},
        {"action": "ENFORCE"}, {"authority_granted": True},
    ):
        with pytest.raises(DataSecurityObservationDenied, match="PROPOSAL_SOURCE_INVALID"):
            propose_data_security_dlp(
                replace(reference_binding(), **changes), **proposal_kwargs(),
            )
    with pytest.raises(DataSecurityObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        propose_data_security_dlp(
            reference_binding(), **proposal_kwargs(
                audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
            ),
        )
