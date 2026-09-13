from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.high_assurance import HighAssuranceProfileDenied, admit_high_assurance_model, normalize_high_assurance_profile
from swarm.harness_models import ApprovedModelCandidate
from swarm.harness_risk import AssuranceTier
from swarm.harness_worker import WorkerRole


def profile(**changes):
    value = {
        "schema_version": "1", "profile_id": "fw-gov-profile/tenant-a/reviewer-prod",
        "tenant_id": "tenant-a", "security_boundary": "fw-boundary/tenant-a/government",
        "environment": "GOVERNMENT", "data_classifications": ["CONFIDENTIAL", "RESTRICTED"],
        "minimum_assurance_tier": "T3", "authorization_state": "EVIDENCE_BOUND",
        "ato_reference": "fw-authorization/tenant-a/ato-001", "fedramp_state": "AUTHORIZED",
        "dod_impact_level": "IL4", "sovereign_required": False, "offline_required": False,
        "valid_from_epoch": 100, "valid_until_epoch": 200,
        "evidence_ref": "fw-evid/tenant-a/gov/profile-001",
    }
    value.update(changes)
    return value


def test_profile_is_immutable_evidence_first_and_grants_no_authority():
    events = []
    result = normalize_high_assurance_profile(profile(), tenant_id="tenant-a", now_epoch=150, audit=lambda *args: events.append(args))
    assert result.source_trust == "CALLER_SUPPLIED_UNTRUSTED"
    assert result.mode == "DRY_RUN" and result.deployment == "DISABLED"
    assert result.authority_granted is False
    assert events[0][0] == "high_assurance_profile_normalized"
    assert events[0][1]["provider_invoked"] is False and events[0][1]["credential_resolved"] is False
    assert "ato_reference" not in events[0][1]
    with pytest.raises(FrozenInstanceError):
        result.authorization_state = "REVOKED"


@pytest.mark.parametrize("changes,reason", [
    ({"schema_version": "2"}, "PROFILE_INVALID"),
    ({"extra": "authority"}, "PROFILE_INVALID"),
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"profile_id": "fw-gov-profile/tenant-b/reviewer"}, "PROFILE_ID_INVALID"),
    ({"security_boundary": "fw-boundary/tenant-b/government"}, "SECURITY_BOUNDARY_INVALID"),
    ({"evidence_ref": "fw-evid/tenant-b/gov/profile"}, "EVIDENCE_REF_INVALID"),
    ({"ato_reference": "fw-authorization/tenant-b/ato"}, "ATO_REFERENCE_INVALID"),
    ({"environment": "ANY"}, "ENVIRONMENT_INVALID"),
    ({"data_classifications": ("RESTRICTED",)}, "DATA_CLASSIFICATIONS_INVALID"),
    ({"data_classifications": ["RESTRICTED", "CONFIDENTIAL"]}, "DATA_CLASSIFICATIONS_INVALID"),
    ({"data_classifications": ["CONFIDENTIAL", "CONFIDENTIAL"]}, "DATA_CLASSIFICATIONS_INVALID"),
    ({"data_classifications": ["ROOT"]}, "DATA_CLASSIFICATIONS_INVALID"),
    ({"minimum_assurance_tier": "T5"}, "ASSURANCE_TIER_INVALID"),
    ({"authorization_state": "CERTIFIED"}, "AUTHORIZATION_STATE_INVALID"),
    ({"fedramp_state": "COMPLIANT"}, "FEDRAMP_STATE_INVALID"),
    ({"dod_impact_level": "IL7"}, "DOD_IMPACT_LEVEL_INVALID"),
    ({"sovereign_required": "yes"}, "EXECUTION_CONSTRAINT_INVALID"),
    ({"offline_required": True}, "OFFLINE_ENVIRONMENT_MISMATCH"),
    ({"sovereign_required": True}, "SOVEREIGN_ENVIRONMENT_MISMATCH"),
    ({"valid_from_epoch": True}, "VALIDITY_INVALID"),
    ({"valid_until_epoch": 150}, "VALIDITY_INVALID"),
    ({"authorization_state": "EVIDENCE_BOUND", "ato_reference": None}, "AUTHORIZATION_REFERENCE_REQUIRED"),
    ({"authorization_state": "PENDING", "ato_reference": None, "fedramp_state": "AUTHORIZED", "dod_impact_level": "NOT_APPLICABLE"}, "AUTHORIZATION_CLAIM_INVALID"),
])
def test_profile_denies_malformed_stale_cross_tenant_or_claim_shaped_input(changes, reason):
    events = []
    with pytest.raises(HighAssuranceProfileDenied, match=reason):
        normalize_high_assurance_profile(profile(**changes), tenant_id="tenant-a", now_epoch=150, audit=lambda *args: events.append(args))
    assert events == []


def test_profile_accepts_pending_non_claim_and_offline_sovereign_boundaries():
    pending = normalize_high_assurance_profile(profile(authorization_state="PENDING", ato_reference=None, fedramp_state="IN_PROCESS", dod_impact_level="NOT_APPLICABLE"), tenant_id="tenant-a", now_epoch=100, audit=lambda *_: None)
    assert pending.authorization_state == "PENDING"
    offline = normalize_high_assurance_profile(profile(environment="OFFLINE", sovereign_required=True, offline_required=True), tenant_id="tenant-a", now_epoch=199, audit=lambda *_: None)
    assert offline.offline_required and offline.sovereign_required


def test_profile_denies_secret_material_non_json_oversize_and_evidence_failure():
    with pytest.raises(HighAssuranceProfileDenied, match="PROFILE_INVALID"):
        normalize_high_assurance_profile(profile(ato_reference="api_key=abcdefghijk"), tenant_id="tenant-a", now_epoch=150, audit=lambda *_: None)
    with pytest.raises(HighAssuranceProfileDenied, match="PROFILE_INVALID"):
        normalize_high_assurance_profile(profile(data_classifications={"RESTRICTED"}), tenant_id="tenant-a", now_epoch=150, audit=lambda *_: None)
    with pytest.raises(HighAssuranceProfileDenied, match="PROFILE_INVALID"):
        normalize_high_assurance_profile(profile(profile_id="fw-gov-profile/tenant-a/" + "x" * 17000), tenant_id="tenant-a", now_epoch=150, audit=lambda *_: None)
    with pytest.raises(HighAssuranceProfileDenied, match="EVIDENCE_WRITE_FAILED"):
        normalize_high_assurance_profile(profile(), tenant_id="tenant-a", now_epoch=150, audit=lambda *_: (_ for _ in ()).throw(OSError("offline")))


@pytest.mark.parametrize("tenant_id,now_epoch", [("Tenant A", 150), ("tenant-a", -1), ("tenant-a", True)])
def test_profile_denies_invalid_expected_boundary(tenant_id, now_epoch):
    with pytest.raises(HighAssuranceProfileDenied):
        normalize_high_assurance_profile(profile(), tenant_id=tenant_id, now_epoch=now_epoch, audit=lambda *_: None)


def admitted_profile(**changes):
    return normalize_high_assurance_profile(profile(**changes), tenant_id="tenant-a", now_epoch=150, audit=lambda *_: None)


def candidate(**changes):
    values = {
        "candidate_id": "approved-reviewer", "tenant_id": "tenant-a",
        "provider": "approved-provider", "model_id": "approved-model",
        "environment": "government", "assurance_tier": AssuranceTier.T3,
        "allowed_roles": (WorkerRole.READ_ONLY_REVIEWER,),
        "allowed_data_classifications": ("CONFIDENTIAL", "RESTRICTED"),
        "allowed_tools": ("source.read",), "estimated_cost_microunits": 10,
        "registry_evidence_reference": "fw-evid/tenant-a/model/approved-reviewer",
        "approved": True, "available": True,
    }
    values.update(changes)
    return ApprovedModelCandidate(**values)


def admission(profile_value=None, candidate_value=None, **changes):
    arguments = {
        "tenant_id": "tenant-a", "security_boundary": "fw-boundary/tenant-a/government",
        "environment": "GOVERNMENT", "data_classification": "RESTRICTED",
        "now_epoch": 150, "audit": lambda *_: None,
    }
    arguments.update(changes)
    return admit_high_assurance_model(profile_value or admitted_profile(), candidate_value or candidate(), **arguments)


def test_exact_profile_and_registry_candidate_admit_metadata_without_invocation():
    evidence = []
    result = admission(audit=lambda *args: evidence.append(args))
    assert result.required_assurance_tier == "T3" and result.candidate_assurance_tier == "T3"
    assert result.disposition == "METADATA_ADMITTED"
    assert result.mode == "DRY_RUN" and result.deployment == "DISABLED"
    assert result.invocation_authorized is False and result.authority_granted is False
    assert evidence[0][1]["opaque_router_consulted"] is False
    with pytest.raises(FrozenInstanceError):
        result.invocation_authorized = True


@pytest.mark.parametrize("profile_changes,candidate_changes,call_changes,reason", [
    ({}, {"tenant_id": "tenant-b"}, {}, "TENANT_MISMATCH"),
    ({}, {}, {"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({}, {}, {"security_boundary": "fw-boundary/tenant-a/other"}, "SECURITY_BOUNDARY_MISMATCH"),
    ({}, {"environment": "commercial"}, {}, "ENVIRONMENT_MISMATCH"),
    ({}, {}, {"environment": "COMMERCIAL"}, "ENVIRONMENT_MISMATCH"),
    ({}, {"allowed_data_classifications": ("CONFIDENTIAL",)}, {}, "DATA_CLASSIFICATION_MISMATCH"),
    ({}, {}, {"data_classification": "CLASSIFIED"}, "DATA_CLASSIFICATION_MISMATCH"),
    ({"minimum_assurance_tier": "T4"}, {}, {}, "ASSURANCE_DOWNGRADE_DENIED"),
    ({}, {"approved": False}, {}, "MODEL_NOT_APPROVED_OR_AVAILABLE"),
    ({}, {"available": False}, {}, "MODEL_NOT_APPROVED_OR_AVAILABLE"),
    ({"authorization_state": "PENDING", "ato_reference": None, "fedramp_state": "IN_PROCESS", "dod_impact_level": "NOT_APPLICABLE"}, {}, {}, "PROFILE_NOT_AUTHORIZED"),
    ({}, {}, {"now_epoch": 200}, "PROFILE_STALE"),
    ({}, {}, {"now_epoch": True}, "PROFILE_STALE"),
])
def test_model_admission_denies_mismatch_downgrade_stale_or_unapproved(profile_changes, candidate_changes, call_changes, reason):
    with pytest.raises(HighAssuranceProfileDenied, match=reason):
        admission(admitted_profile(**profile_changes), candidate(**candidate_changes), **call_changes)


def test_model_admission_denies_forged_profile_authority_and_evidence_failure():
    forged = replace(admitted_profile(), authority_granted=True)
    with pytest.raises(HighAssuranceProfileDenied, match="PROFILE_AUTHORITY_INVALID"):
        admission(forged)
    with pytest.raises(HighAssuranceProfileDenied, match="EVIDENCE_WRITE_FAILED"):
        admission(audit=lambda *_: (_ for _ in ()).throw(OSError("offline")))


@pytest.mark.parametrize("profile_changes,candidate_changes,reason", [
    ({"evidence_ref": "fw-evid/tenant-b/gov/profile"}, {}, "EVIDENCE_REF_INVALID"),
    ({"ato_reference": "fw-authorization/tenant-b/ato"}, {}, "ATO_REFERENCE_INVALID"),
    ({}, {"registry_evidence_reference": "fw-evid/tenant-b/model/candidate"}, "REGISTRY_EVIDENCE_REF_INVALID"),
])
def test_model_admission_revalidates_forged_or_cross_tenant_evidence_references(profile_changes, candidate_changes, reason):
    forged_profile = replace(admitted_profile(), **profile_changes)
    with pytest.raises(HighAssuranceProfileDenied, match=reason):
        admission(forged_profile, candidate(**candidate_changes))
