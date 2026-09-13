from dataclasses import FrozenInstanceError, replace

import pytest

from swarm.high_assurance import HighAssuranceProfileDenied, admit_high_assurance_model, bind_high_assurance_evidence, normalize_high_assurance_failure, normalize_high_assurance_profile, run_high_assurance_dry_run_lifecycle, select_high_assurance_failover
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


def failure_fixture(**changes):
    value = {
        "failure_id": "fw-gov-failure/tenant-a/provider-down-1",
        "tenant_id": "tenant-a", "profile_id": "fw-gov-profile/tenant-a/reviewer-prod",
        "candidate_id": "approved-reviewer", "environment": "GOVERNMENT",
        "failed_at_epoch": 151, "reason": "PROVIDER_UNAVAILABLE",
        "evidence_ref": "fw-evid/tenant-a/gov/failure-1",
    }
    value.update(changes)
    return value


def failure(**changes):
    return normalize_high_assurance_failure(failure_fixture(**changes), tenant_id="tenant-a", now_epoch=155, audit=lambda *_: None)


def test_failure_metadata_is_exact_immutable_evidence_first_and_non_invoking():
    events = []
    result = normalize_high_assurance_failure(failure_fixture(), tenant_id="tenant-a", now_epoch=155, audit=lambda *args: events.append(args))
    assert result.reason == "PROVIDER_UNAVAILABLE" and result.mode == "DRY_RUN"
    assert result.authority_granted is False
    assert events[0][1]["provider_retried"] is False
    with pytest.raises(FrozenInstanceError):
        result.reason = "TIMEOUT"


@pytest.mark.parametrize("changes,reason", [
    ({"extra": "retry"}, "FAILURE_INVALID"),
    ({"tenant_id": "tenant-b"}, "TENANT_MISMATCH"),
    ({"failure_id": "fw-gov-failure/tenant-b/failure"}, "FAILURE_ID_INVALID"),
    ({"profile_id": "fw-gov-profile/tenant-b/profile"}, "PROFILE_ID_INVALID"),
    ({"evidence_ref": "fw-evid/tenant-b/failure"}, "EVIDENCE_REF_INVALID"),
    ({"candidate_id": ""}, "CANDIDATE_ID_INVALID"),
    ({"environment": "REMOTE"}, "ENVIRONMENT_INVALID"),
    ({"reason": "AUTHORITY_EXPANSION"}, "FAILURE_REASON_INVALID"),
    ({"failed_at_epoch": 156}, "FAILURE_TIME_INVALID"),
    ({"failed_at_epoch": True}, "FAILURE_TIME_INVALID"),
])
def test_failure_metadata_denies_malformed_cross_tenant_or_future_input(changes, reason):
    with pytest.raises(HighAssuranceProfileDenied, match=reason):
        normalize_high_assurance_failure(failure_fixture(**changes), tenant_id="tenant-a", now_epoch=155, audit=lambda *_: None)


def failover(profile_value=None, admission_value=None, failure_value=None, candidates=None, **changes):
    profile_value = profile_value or admitted_profile()
    admission_value = admission_value or admission(profile_value=profile_value)
    failure_value = failure_value or failure()
    candidates = candidates or (candidate(candidate_id="equivalent", model_id="equivalent-model", estimated_cost_microunits=5),)
    arguments = {"tenant_id": "tenant-a", "data_classification": "RESTRICTED", "now_epoch": 155, "audit": lambda *_: None}
    arguments.update(changes)
    return select_high_assurance_failover(profile_value, admission_value, failure_value, candidates, **arguments)


def test_failover_selects_lowest_cost_same_or_higher_approved_equivalent_without_invocation():
    events = []
    choices = (
        candidate(candidate_id="higher", model_id="higher-model", assurance_tier=AssuranceTier.T4, estimated_cost_microunits=20),
        candidate(candidate_id="same", model_id="same-model", estimated_cost_microunits=10),
        candidate(candidate_id="weak", model_id="weak-model", assurance_tier=AssuranceTier.T2, estimated_cost_microunits=1),
    )
    result = failover(candidates=choices, audit=lambda *args: events.append(args))
    assert result.selected_candidate_id == "same" and result.assurance_tier == "T3"
    assert result.invocation_authorized is False and result.authority_granted is False
    assert events[0][1]["deployment"] == "DISABLED"


def test_offline_profile_denies_remote_candidates_and_accepts_only_offline_equivalent():
    offline_profile = admitted_profile(environment="OFFLINE", sovereign_required=True, offline_required=True)
    offline_admission = admission(offline_profile, candidate(environment="offline"), environment="OFFLINE")
    offline_failure = failure(environment="OFFLINE")
    with pytest.raises(HighAssuranceProfileDenied, match="NO_APPROVED_MODEL"):
        failover(offline_profile, offline_admission, offline_failure, (candidate(candidate_id="remote", model_id="remote-model", environment="government"),))
    selected = failover(offline_profile, offline_admission, offline_failure, (candidate(candidate_id="local", model_id="local-model", environment="offline"),))
    assert selected.environment == "OFFLINE" and selected.selected_candidate_id == "local"


@pytest.mark.parametrize("candidate_changes", [
    {"assurance_tier": AssuranceTier.T2}, {"approved": False}, {"available": False},
    {"tenant_id": "tenant-b"}, {"environment": "commercial"},
    {"allowed_data_classifications": ("CONFIDENTIAL",)},
])
def test_failover_denies_downgrade_unapproved_unavailable_or_non_equivalent(candidate_changes):
    with pytest.raises(HighAssuranceProfileDenied, match="NO_APPROVED_MODEL"):
        failover(candidates=(candidate(candidate_id="other", model_id="other-model", **candidate_changes),))


def test_failover_denies_failure_substitution_forged_authority_and_evidence_failure():
    with pytest.raises(HighAssuranceProfileDenied, match="FAILURE_BINDING_MISMATCH"):
        failover(failure_value=replace(failure(), candidate_id="other"))
    with pytest.raises(HighAssuranceProfileDenied, match="FAILOVER_AUTHORITY_INVALID"):
        failover(failure_value=replace(failure(), authority_granted=True))
    with pytest.raises(HighAssuranceProfileDenied, match="EVIDENCE_WRITE_FAILED"):
        failover(audit=lambda *_: (_ for _ in ()).throw(OSError("offline")))


def test_evidence_binding_preserves_direct_admission_and_failover_chronology():
    profile_value = admitted_profile()
    admission_value = admission(profile_value=profile_value)
    direct = bind_high_assurance_evidence(
        profile_value, admission_value, tenant_id="tenant-a",
        evidence_refs=(profile_value.evidence_ref, admission_value.registry_evidence_ref),
        audit=lambda *_: None,
    )
    assert direct.failed_candidate_id is None and direct.selected_candidate_id == admission_value.candidate_id
    failure_value = failure()
    failover_value = failover(profile_value, admission_value, failure_value)
    refs = tuple(sorted((profile_value.evidence_ref, admission_value.registry_evidence_ref, failure_value.evidence_ref)))
    bound = bind_high_assurance_evidence(profile_value, admission_value, tenant_id="tenant-a", evidence_refs=refs, audit=lambda *_: None, failure=failure_value, failover=failover_value)
    assert bound.failed_candidate_id == admission_value.candidate_id
    assert bound.selected_candidate_id == failover_value.selected_candidate_id
    assert bound.action == "CORRELATE_ONLY" and not bound.invocation_authorized


def test_evidence_binding_denies_incomplete_duplicate_cross_tenant_or_tampered_chronology():
    profile_value = admitted_profile(); admission_value = admission(profile_value=profile_value)
    failure_value = failure(); failover_value = failover(profile_value, admission_value, failure_value)
    base = tuple(sorted((profile_value.evidence_ref, admission_value.registry_evidence_ref, failure_value.evidence_ref)))
    for refs, reason in (
        ((profile_value.evidence_ref,), "INCOMPLETE"),
        ((profile_value.evidence_ref,) * 2, "INVALID"),
        (tuple(sorted(("fw-evid/tenant-b/other",) + base)), "EVIDENCE_REF_INVALID"),
    ):
        with pytest.raises(HighAssuranceProfileDenied, match=reason):
            bind_high_assurance_evidence(profile_value, admission_value, tenant_id="tenant-a", evidence_refs=refs, audit=lambda *_: None, failure=failure_value, failover=failover_value)
    with pytest.raises(HighAssuranceProfileDenied, match="FAILOVER_CHRONOLOGY_INVALID"):
        bind_high_assurance_evidence(profile_value, admission_value, tenant_id="tenant-a", evidence_refs=base, audit=lambda *_: None, failure=failure_value, failover=replace(failover_value, failed_candidate_id="other"))
    with pytest.raises(HighAssuranceProfileDenied, match="ADMISSION_BINDING_INVALID"):
        bind_high_assurance_evidence(profile_value, replace(admission_value, invocation_authorized=True), tenant_id="tenant-a", evidence_refs=tuple(sorted((profile_value.evidence_ref, admission_value.registry_evidence_ref))), audit=lambda *_: None)


def test_evidence_binding_wraps_durability_failure_with_original_cause():
    profile_value = admitted_profile(); admission_value = admission(profile_value=profile_value)
    refs = tuple(sorted((profile_value.evidence_ref, admission_value.registry_evidence_ref)))
    failure = OSError("evidence offline")
    with pytest.raises(HighAssuranceProfileDenied, match="EVIDENCE_WRITE_FAILED") as caught:
        bind_high_assurance_evidence(
            profile_value, admission_value, tenant_id="tenant-a",
            evidence_refs=refs,
            audit=lambda *_: (_ for _ in ()).throw(failure),
        )
    assert caught.value.__cause__ is failure


def lifecycle(*, profile_changes=None, primary_changes=None, failure_changes=None, fallbacks=(), evidence_refs=None, now_epoch=155):
    profile_value = profile(**(profile_changes or {}))
    primary = candidate(**(primary_changes or {}))
    failure_value = failure_fixture(**failure_changes) if failure_changes is not None else None
    refs = evidence_refs or tuple(sorted((profile_value["evidence_ref"], primary.registry_evidence_reference) + ((failure_value["evidence_ref"],) if failure_value else ())))
    return run_high_assurance_dry_run_lifecycle(
        profile_value, primary, tenant_id="tenant-a",
        security_boundary="fw-boundary/tenant-a/government",
        environment=profile_value["environment"], data_classification="RESTRICTED",
        now_epoch=now_epoch, evidence_refs=refs, audit=lambda *_: None,
        failure_fixture=failure_value, fallback_candidates=fallbacks,
    )


def test_integrated_direct_and_failover_lifecycles_preserve_exact_bindings():
    direct = lifecycle()
    assert direct.failure is None and direct.failover is None
    assert direct.evidence.selected_candidate_id == direct.admission.candidate_id
    assert direct.kill_switch == "ENGAGED" and not direct.invocation_authorized
    fallback = candidate(candidate_id="equivalent", model_id="equivalent-model", estimated_cost_microunits=5)
    recovered = lifecycle(failure_changes={}, fallbacks=(fallback,))
    assert recovered.failure.candidate_id == recovered.admission.candidate_id
    assert recovered.failover.selected_candidate_id == fallback.candidate_id
    assert recovered.evidence.selected_candidate_id == fallback.candidate_id
    assert recovered.evidence.evidence_refs == tuple(sorted((recovered.profile.evidence_ref, recovered.admission.registry_evidence_ref, recovered.failure.evidence_ref)))


def test_integrated_lifecycle_denies_downgrade_stale_substitution_and_no_approved_model():
    with pytest.raises(HighAssuranceProfileDenied, match="NO_APPROVED_MODEL"):
        lifecycle(failure_changes={}, fallbacks=(candidate(candidate_id="weak", model_id="weak-model", assurance_tier=AssuranceTier.T2),))
    with pytest.raises(HighAssuranceProfileDenied, match="VALIDITY_INVALID"):
        lifecycle(now_epoch=200)
    with pytest.raises(HighAssuranceProfileDenied, match="FAILURE_BINDING_MISMATCH"):
        lifecycle(failure_changes={"candidate_id": "substituted"}, fallbacks=(candidate(candidate_id="equivalent", model_id="equivalent-model"),))
    with pytest.raises(HighAssuranceProfileDenied, match="UNBOUND_FALLBACK"):
        lifecycle(fallbacks=(candidate(candidate_id="unused", model_id="unused-model"),))


def test_integrated_offline_lifecycle_rejects_remote_fallback_and_opaque_authority_surface():
    offline = {"environment": "OFFLINE", "sovereign_required": True, "offline_required": True}
    primary = {"environment": "offline"}
    with pytest.raises(HighAssuranceProfileDenied, match="NO_APPROVED_MODEL"):
        lifecycle(profile_changes=offline, primary_changes=primary, failure_changes={"environment": "OFFLINE"}, fallbacks=(candidate(candidate_id="remote", model_id="remote-model", environment="government"),))
    result = lifecycle(profile_changes=offline, primary_changes=primary, failure_changes={"environment": "OFFLINE"}, fallbacks=(candidate(candidate_id="local", model_id="local-model", environment="offline"),))
    assert not hasattr(result, "router") and not hasattr(result, "invoke")
    assert not result.authority_granted and not result.invocation_authorized
