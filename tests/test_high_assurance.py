from dataclasses import FrozenInstanceError

import pytest

from swarm.high_assurance import HighAssuranceProfileDenied, normalize_high_assurance_profile


def profile(**changes):
    value = {
        "schema_version": "1", "profile_id": "fw-gov-profile/tenant-a/reviewer-prod",
        "tenant_id": "tenant-a", "security_boundary": "fw-boundary/tenant-a/government",
        "environment": "GOVERNMENT", "data_classifications": ("CONFIDENTIAL", "RESTRICTED"),
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
    ({"data_classifications": ["RESTRICTED"]}, "DATA_CLASSIFICATIONS_INVALID"),
    ({"data_classifications": ("RESTRICTED", "CONFIDENTIAL")}, "DATA_CLASSIFICATIONS_INVALID"),
    ({"data_classifications": ("ROOT",)}, "DATA_CLASSIFICATIONS_INVALID"),
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
