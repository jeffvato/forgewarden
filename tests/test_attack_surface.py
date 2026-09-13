from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.action_ticket import ActionTicket, ActionTicketRegistry
from swarm.asoc import HMACLeaseSigner
from swarm.attack_surface import (
    AttackSurfaceObservation,
    AttackSurfaceObservationDenied,
    AttackSurfaceFinding,
    bind_attack_surface_references,
    classify_attack_surface_observation,
    normalize_attack_surface_observation,
    propose_attack_surface_risk_reduction,
    run_attack_surface_dry_run_lifecycle,
)


def fixture(**overrides):
    value = {
        "event_id": "asm-1", "tenant_id": "tenant-a", "observed_at_epoch": 100,
        "asset_type": "WEBSITE", "asset_ref": "fw-asset/tenant-a/site-1",
        "exposure_ref": "fw-exposure/tenant-a/site-1", "service": "HTTP",
        "protocol": "HTTPS", "port": 443, "ownership_state": "KNOWN",
        "visibility_state": "PUBLIC", "evidence_ref": "fw-evid/tenant-a/asm-1",
    }
    value.update(overrides)
    return value


def test_attack_surface_observation_is_immutable_evidence_first_and_minimized():
    evidence = []
    value = normalize_attack_surface_observation(
        fixture(), tenant_id="tenant-a", now_epoch=150,
        audit=lambda *args: evidence.append(args),
    )
    assert value.asset_type == "WEBSITE" and value.visibility_state == "PUBLIC"
    assert value.trust == "UNTRUSTED_DATA"
    assert value.mode == "DRY_RUN" and value.action == "DETECT_ONLY"
    assert value.authority_granted is False
    assert evidence[0][0] == "attack_surface_observation_normalized"
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert not {"asset_ref", "exposure_ref"} & evidence[0][1].keys()
    with pytest.raises(FrozenInstanceError):
        value.port = 80


@pytest.mark.parametrize("value,reason", [
    (fixture(tenant_id="tenant-b"), "TENANT_MISMATCH"),
    (fixture(asset_ref="fw-asset/tenant-b/site-1"), "ASSET_REF_INVALID"),
    (fixture(exposure_ref="fw-exposure/tenant-b/site-1"), "EXPOSURE_REF_INVALID"),
    (fixture(evidence_ref="fw-evid/tenant-b/asm-1"), "EVIDENCE_REF_INVALID"),
    (fixture(asset_type="HOST"), "ASSET_TYPE_INVALID"),
    (fixture(service="SHELL"), "SERVICE_INVALID"),
    (fixture(protocol="https"), "PROTOCOL_INVALID"),
    (fixture(ownership_state="CLAIMED"), "OWNERSHIP_STATE_INVALID"),
    (fixture(visibility_state="HIDDEN"), "VISIBILITY_STATE_INVALID"),
    (fixture(port=True), "PORT_INVALID"),
    (fixture(port=65536), "PORT_INVALID"),
    (fixture(observed_at_epoch=151), "OBSERVED_AT_INVALID"),
    (fixture(extra="value"), "FIXTURE_INVALID"),
])
def test_attack_surface_observation_rejects_invalid_or_cross_tenant_input(value, reason):
    evidence = []
    with pytest.raises(AttackSurfaceObservationDenied, match=reason):
        normalize_attack_surface_observation(
            value, tenant_id="tenant-a", now_epoch=150,
            audit=lambda *args: evidence.append(args),
        )
    assert evidence == []


def test_attack_surface_observation_accepts_port_boundaries_and_denies_evidence_failure():
    for port in (0, 65535):
        assert normalize_attack_surface_observation(
            fixture(port=port), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        ).port == port
    with pytest.raises(AttackSurfaceObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_attack_surface_observation(
            fixture(), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


def test_attack_surface_observation_rejects_boolean_observation_time():
    with pytest.raises(AttackSurfaceObservationDenied, match="OBSERVED_AT_INVALID"):
        normalize_attack_surface_observation(
            fixture(observed_at_epoch=True), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )


@pytest.mark.parametrize("tenant_id", ["", "Tenant With Spaces"])
def test_attack_surface_observation_rejects_invalid_expected_tenant(tenant_id):
    with pytest.raises(AttackSurfaceObservationDenied, match="TENANT_INVALID"):
        normalize_attack_surface_observation(
            fixture(), tenant_id=tenant_id, now_epoch=150, audit=lambda *_args: None,
        )


@pytest.mark.parametrize("now_epoch", [True, -1])
def test_attack_surface_observation_rejects_invalid_current_time(now_epoch):
    with pytest.raises(AttackSurfaceObservationDenied, match="OBSERVED_AT_INVALID"):
        normalize_attack_surface_observation(
            fixture(), tenant_id="tenant-a", now_epoch=now_epoch,
            audit=lambda *_args: None,
        )


def test_attack_surface_observation_rejects_non_json_fixture_value():
    with pytest.raises(AttackSurfaceObservationDenied, match="FIXTURE_INVALID"):
        normalize_attack_surface_observation(
            fixture(service={"HTTP"}), tenant_id="tenant-a", now_epoch=150,
            audit=lambda *_args: None,
        )


def observation(**overrides):
    values = fixture(**overrides)
    return normalize_attack_surface_observation(
        values, tenant_id=values["tenant_id"], now_epoch=150,
        audit=lambda *_args: None,
    )


@pytest.mark.parametrize("visibility,ownership,exploitability,forgotten,risk,recommendations", [
    ("PUBLIC", "KNOWN", "CONFIRMED_EXPLOITABLE", False, "CRITICAL", ("WARN", "PROPOSE_RISK_REDUCTION")),
    ("UNEXPECTED", "UNKNOWN", "UNKNOWN", True, "HIGH", ("WARN", "PROPOSE_RISK_REDUCTION")),
    ("PUBLIC", "KNOWN", "NOT_EXPLOITABLE", False, "MEDIUM", ("WARN",)),
    ("RESTRICTED", "KNOWN", "NOT_EXPLOITABLE", False, "LOW", ("WARN",)),
])
def test_attack_surface_classification_is_deterministic_and_advisory(
    visibility, ownership, exploitability, forgotten, risk, recommendations,
):
    evidence = []
    value = classify_attack_surface_observation(
        observation(visibility_state=visibility, ownership_state=ownership),
        tenant_id="tenant-a", exploitability_state=exploitability,
        forgotten_asset=forgotten, audit=lambda *args: evidence.append(args),
    )
    assert value.risk == risk and value.recommendations == recommendations
    assert value.action == "ADVISE_ONLY" and value.authority_granted is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert evidence[0][1]["response_executed"] is False


@pytest.mark.parametrize("kwargs,reason", [
    ({"tenant_id": "tenant-b", "exploitability_state": "UNKNOWN", "forgotten_asset": False}, "TENANT_MISMATCH"),
    ({"tenant_id": "tenant-a", "exploitability_state": "EXPLOIT_NOW", "forgotten_asset": False}, "EXPLOITABILITY_INVALID"),
    ({"tenant_id": "tenant-a", "exploitability_state": "UNKNOWN", "forgotten_asset": 1}, "FORGOTTEN_ASSET_INVALID"),
    ({"tenant_id": "tenant-a", "exploitability_state": "UNKNOWN", "forgotten_asset": True}, "FACTS_CONTRADICTORY"),
])
def test_attack_surface_classification_denies_invalid_cross_tenant_or_contradictory_facts(kwargs, reason):
    with pytest.raises(AttackSurfaceObservationDenied, match=reason):
        classify_attack_surface_observation(
            observation(), audit=lambda *_args: None, **kwargs,
        )


def test_attack_surface_classification_denies_authority_shape_and_evidence_failure():
    admitted = observation()
    forged = AttackSurfaceObservation(
        admitted.event_id, admitted.tenant_id, admitted.observed_at_epoch,
        admitted.asset_type, admitted.asset_ref, admitted.exposure_ref,
        admitted.service, admitted.protocol, admitted.port,
        admitted.ownership_state, admitted.visibility_state, admitted.evidence_ref,
        authority_granted=True,
    )
    with pytest.raises(AttackSurfaceObservationDenied, match="OBSERVATION_AUTHORITY_INVALID"):
        classify_attack_surface_observation(
            forged, tenant_id="tenant-a", exploitability_state="UNKNOWN",
            forgotten_asset=False, audit=lambda *_args: None,
        )
    with pytest.raises(AttackSurfaceObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        classify_attack_surface_observation(
            admitted, tenant_id="tenant-a", exploitability_state="UNKNOWN",
            forgotten_asset=False,
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("invalid", [None, {}, "observation", 1])
def test_attack_surface_classification_denies_non_observation_input(invalid):
    with pytest.raises(AttackSurfaceObservationDenied, match="OBSERVATION_INVALID"):
        classify_attack_surface_observation(
            invalid, tenant_id="tenant-a", exploitability_state="UNKNOWN",
            forgotten_asset=False, audit=lambda *_args: None,
        )


@pytest.mark.parametrize("invalid", [None, 1, "audit"])
def test_attack_surface_classification_denies_non_callable_audit(invalid):
    with pytest.raises(AttackSurfaceObservationDenied, match="OBSERVATION_INVALID"):
        classify_attack_surface_observation(
            observation(), tenant_id="tenant-a", exploitability_state="UNKNOWN",
            forgotten_asset=False, audit=invalid,
        )


def finding(**observation_overrides):
    return classify_attack_surface_observation(
        observation(**observation_overrides), tenant_id="tenant-a",
        exploitability_state="CONFIRMED_EXPLOITABLE", forgotten_asset=False,
        audit=lambda *_args: None,
    )


def binding_kwargs(**overrides):
    values = {
        "tenant_id": "tenant-a", "network_ref": "fw-network/tenant-a/exposure-1",
        "vulnerability_refs": ("fw-vuln/tenant-a/cve-1",),
        "catalog_ref": "fw-catalog/tenant-a/trusted-1",
        "signature_ref": "fw-signature/tenant-a/cert-1",
        "soc_incident_ref": "fw-incident/tenant-a/asm-1",
        "evidence_refs": ("fw-evid/tenant-a/asm-1",),
    }
    values.update(overrides)
    return values


def test_attack_surface_reference_binding_reuses_canonical_owners_evidence_first():
    evidence = []
    value = bind_attack_surface_references(
        finding(), **binding_kwargs(), audit=lambda *args: evidence.append(args),
    )
    assert value.asset_ref == "fw-asset/tenant-a/site-1"
    assert value.network_ref == "fw-network/tenant-a/exposure-1"
    assert value.vulnerability_refs == ("fw-vuln/tenant-a/cve-1",)
    assert value.action == "CORRELATE_ONLY" and value.authority_granted is False
    assert evidence[0][1]["deployment"] == "DISABLED"
    assert evidence[0][1]["response_executed"] is False


@pytest.mark.parametrize("changes,reason", [
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"network_ref": "fw-network/tenant-b/exposure-1"}, "NETWORK_REF_INVALID"),
    ({"vulnerability_refs": ("fw-vuln/tenant-b/cve-1",)}, "VULNERABILITY_REFS_INVALID"),
    ({"vulnerability_refs": ("fw-vuln/tenant-a/cve-1", "fw-vuln/tenant-a/cve-1")}, "VULNERABILITY_REFS_INVALID"),
    ({"catalog_ref": "fw-catalog/tenant-b/trusted-1"}, "CERTIFICATE_REF_INVALID"),
    ({"signature_ref": "fw-catalog/tenant-a/cert-1"}, "CERTIFICATE_REF_INVALID"),
    ({"soc_incident_ref": "fw-incident/tenant-b/asm-1"}, "SOC_INCIDENT_REF_INVALID"),
    ({"evidence_refs": ("fw-vuln/tenant-a/cve-1",)}, "EVIDENCE_REFS_INVALID"),
])
def test_attack_surface_reference_binding_denies_invalid_or_cross_tenant_refs(changes, reason):
    with pytest.raises(AttackSurfaceObservationDenied, match=reason):
        bind_attack_surface_references(
            finding(), **binding_kwargs(**changes), audit=lambda *_args: None,
        )


def test_attack_surface_reference_binding_denies_forged_finding_and_evidence_failure():
    source = finding()
    forged = AttackSurfaceFinding(
        source.event_id, source.tenant_id, source.asset_ref, source.exposure_ref,
        source.visibility_state, source.ownership_state,
        source.exploitability_state, source.forgotten_asset, source.risk,
        source.recommendations, authority_granted=True,
    )
    with pytest.raises(AttackSurfaceObservationDenied, match="FINDING_INVALID"):
        bind_attack_surface_references(
            forged, **binding_kwargs(), audit=lambda *_args: None,
        )
    with pytest.raises(AttackSurfaceObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        bind_attack_surface_references(
            source, **binding_kwargs(),
            audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
        )


@pytest.mark.parametrize("field,prefix,reason", [
    ("vulnerability_refs", "fw-vuln", "VULNERABILITY_REFS_INVALID"),
    ("evidence_refs", "fw-evid", "EVIDENCE_REFS_INVALID"),
])
def test_attack_surface_reference_binding_enforces_reference_count_boundaries(field, prefix, reason):
    maximum = tuple(f"{prefix}/tenant-a/ref-{index:02d}" for index in range(16))
    assert bind_attack_surface_references(
        finding(), **binding_kwargs(**{field: maximum}), audit=lambda *_args: None,
    )
    for invalid in ((), maximum + (f"{prefix}/tenant-a/ref-16",)):
        with pytest.raises(AttackSurfaceObservationDenied, match=reason):
            bind_attack_surface_references(
                finding(), **binding_kwargs(**{field: invalid}), audit=lambda *_args: None,
            )


def reference_binding():
    return bind_attack_surface_references(
        finding(), **binding_kwargs(), audit=lambda *_args: None,
    )


def tickets(**overrides):
    registry = ActionTicketRegistry(HMACLeaseSigner({"key-1": b"test-only-key-material"}))
    values = {
        "ticket_id": "ticket-1", "tenant_id": "tenant-a",
        "subject_agent_id": "agent-1", "lease_id": "lease-1",
        "capability": "asm.risk_reduction.propose",
        "resource": "fw-exposure/tenant-a/site-1",
        "action_class": "ASM_RISK_REDUCTION_PROPOSAL",
        "issued_by": "operator-1", "approval_reference": "approval-1",
        "policy_version": "policy-v1", "issued_at": 100, "expires_at": 200,
        "key_reference": "key-1",
    }
    values.update(overrides)
    registry.issue(ActionTicket(**values))
    return registry


def proposal_kwargs(**overrides):
    values = {
        "tickets": tickets(), "ticket_id": "ticket-1",
        "target_ref": "fw-exposure/tenant-a/site-1",
        "policy_decision_ref": "fw-policy/tenant-a/decision-1",
        "subject_agent_id": "agent-1", "lease_id": "lease-1",
        "policy_version": "policy-v1", "now": 150,
        "kill_switch_state": "ENGAGED", "audit": lambda *_args: None,
    }
    values.update(overrides)
    return values


def test_attack_surface_risk_reduction_proposal_consumes_ticket_and_never_executes():
    evidence = []
    args = proposal_kwargs(audit=lambda *items: evidence.append(items))
    value = propose_attack_surface_risk_reduction(reference_binding(), **args)
    assert value.risk == "CRITICAL"
    assert value.action_class == "ASM_RISK_REDUCTION_PROPOSAL"
    assert value.disposition == "PROPOSE_ONLY"
    assert value.mode == "DRY_RUN" and value.deployment == "DISABLED"
    assert value.kill_switch == "ENGAGED"
    assert value.authority_granted is False and value.response_executed is False
    assert evidence[0][1]["response_executed"] is False
    with pytest.raises(AttackSurfaceObservationDenied, match="ACTION_TICKET_DENIED"):
        propose_attack_surface_risk_reduction(reference_binding(), **args)


@pytest.mark.parametrize("changes,reason", [
    ({"kill_switch_state": "CLEAR"}, "KILL_SWITCH_NOT_ENGAGED"),
    ({"target_ref": "fw-exposure/tenant-b/site-1"}, "PROPOSAL_REF_INVALID"),
    ({"target_ref": "fw-exposure/tenant-a/other"}, "PROPOSAL_REF_INVALID"),
    ({"target_ref": "fw-asset/tenant-a/site-1"}, "PROPOSAL_REF_INVALID"),
    ({"policy_decision_ref": "fw-policy/tenant-b/decision-1"}, "PROPOSAL_REF_INVALID"),
    ({"policy_decision_ref": "policy-without-prefix"}, "PROPOSAL_REF_INVALID"),
    ({"ticket_id": "missing-ticket"}, "ACTION_TICKET_DENIED"),
    ({"subject_agent_id": "agent-2"}, "ACTION_TICKET_DENIED"),
    ({"lease_id": "lease-2"}, "ACTION_TICKET_DENIED"),
    ({"policy_version": "policy-v2"}, "ACTION_TICKET_DENIED"),
])
def test_attack_surface_risk_reduction_proposal_denies_boundary_mismatch(changes, reason):
    with pytest.raises(AttackSurfaceObservationDenied, match=reason):
        propose_attack_surface_risk_reduction(
            reference_binding(), **proposal_kwargs(**changes),
        )


def test_attack_surface_risk_reduction_proposal_revalidates_source_and_evidence():
    for changes in (
        {"risk": "MEDIUM"}, {"trust": "TRUSTED"}, {"mode": "LIVE"},
        {"action": "EXECUTE"}, {"authority_granted": True},
    ):
        with pytest.raises(AttackSurfaceObservationDenied, match="PROPOSAL_SOURCE_INVALID"):
            propose_attack_surface_risk_reduction(
                replace(reference_binding(), **changes), **proposal_kwargs(),
            )
    with pytest.raises(AttackSurfaceObservationDenied, match="EVIDENCE_WRITE_FAILED"):
        propose_attack_surface_risk_reduction(
            reference_binding(), **proposal_kwargs(
                audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")),
            ),
        )


def test_attack_surface_risk_reduction_proposal_denies_expired_ticket():
    with pytest.raises(AttackSurfaceObservationDenied, match="ACTION_TICKET_DENIED"):
        propose_attack_surface_risk_reduction(
            reference_binding(), **proposal_kwargs(now=200),
        )


def attack_surface_lifecycle(*, audit=lambda *_args: None, fixture_overrides=None, **overrides):
    values = {
        "fixture": fixture(**(fixture_overrides or {})), "tenant_id": "tenant-a",
        "now_epoch": 150, "exploitability_state": "CONFIRMED_EXPLOITABLE",
        "forgotten_asset": False, "network_ref": "fw-network/tenant-a/exposure-1",
        "vulnerability_refs": ("fw-vuln/tenant-a/cve-1",),
        "catalog_ref": "fw-catalog/tenant-a/trusted-1",
        "signature_ref": "fw-signature/tenant-a/cert-1",
        "soc_incident_ref": "fw-incident/tenant-a/asm-1",
        "evidence_refs": ("fw-evid/tenant-a/asm-1",),
        "tickets": tickets(), "ticket_id": "ticket-1",
        "target_ref": "fw-exposure/tenant-a/site-1",
        "policy_decision_ref": "fw-policy/tenant-a/decision-1",
        "subject_agent_id": "agent-1", "lease_id": "lease-1",
        "policy_version": "policy-v1", "kill_switch_state": "ENGAGED",
        "audit": audit,
    }
    values.update(overrides)
    return run_attack_surface_dry_run_lifecycle(**values)


def test_attack_surface_lifecycle_preserves_stage_order_and_no_authority():
    evidence = []
    lifecycle = attack_surface_lifecycle(audit=lambda *items: evidence.append(items))
    assert [item[0] for item in evidence] == [
        "attack_surface_observation_normalized",
        "attack_surface_observation_classified",
        "attack_surface_references_bound",
        "attack_surface_risk_reduction_proposed",
    ]
    assert len({
        lifecycle.observation.event_id, lifecycle.finding.event_id,
        lifecycle.binding.event_id, lifecycle.proposal.event_id,
    }) == 1
    assert lifecycle.mode == "DRY_RUN" and lifecycle.deployment == "DISABLED"
    assert lifecycle.kill_switch == "ENGAGED"
    assert lifecycle.authority_granted is False and lifecycle.response_executed is False


def test_attack_surface_lifecycle_stops_before_proposal_for_lower_risk():
    evidence = []
    with pytest.raises(AttackSurfaceObservationDenied, match="PROPOSAL_SOURCE_INVALID"):
        attack_surface_lifecycle(
            audit=lambda *items: evidence.append(items),
            exploitability_state="NOT_EXPLOITABLE",
        )
    assert [item[0] for item in evidence] == [
        "attack_surface_observation_normalized",
        "attack_surface_observation_classified",
        "attack_surface_references_bound",
    ]
