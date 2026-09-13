"""Authority-free FW-GOV high-assurance authorization metadata.

Profiles are caller-supplied, untrusted inputs to later deterministic admission.
They do not certify compliance or grant model, provider, credential, deployment,
or execution authority.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping

from .harness_models import ApprovedModelCandidate
from .harness_risk import AssuranceTier


MAX_PROFILE_BYTES = 16 * 1024
_FIELDS = frozenset({
    "schema_version", "profile_id", "tenant_id", "security_boundary",
    "environment", "data_classifications", "minimum_assurance_tier",
    "authorization_state", "ato_reference", "fedramp_state",
    "dod_impact_level", "sovereign_required", "offline_required",
    "valid_from_epoch", "valid_until_epoch", "evidence_ref",
})
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_PROFILE = re.compile(r"^fw-gov-profile/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.-]{0,127}$")
_BOUNDARY = re.compile(r"^fw-boundary/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.-]{0,127}$")
_AUTH_REF = re.compile(r"^fw-authorization/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
_EVID_REF = re.compile(r"^fw-evid/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
_SECRET = re.compile(r"(?i)(bearer\s+\S+|api[_-]?key\s*[:=]|secret\s*[:=]|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|ya29\.[a-z0-9._-]{8,})")
_ENVIRONMENTS = frozenset({"COMMERCIAL", "GOVERNMENT", "SOVEREIGN", "OFFLINE"})
_DATA_CLASSES = frozenset({"PUBLIC", "INTERNAL", "CONFIDENTIAL", "RESTRICTED", "REGULATED", "CLASSIFIED"})
_TIERS = frozenset({"T0", "T1", "T2", "T3", "T4"})
_AUTH_STATES = frozenset({"PENDING", "EVIDENCE_BOUND", "SUSPENDED", "REVOKED", "EXPIRED"})
_FEDRAMP_STATES = frozenset({"NOT_APPLICABLE", "IN_PROCESS", "AUTHORIZED"})
_DOD_LEVELS = frozenset({"NOT_APPLICABLE", "IL2", "IL4", "IL5", "IL6"})


class HighAssuranceProfileDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


@dataclass(frozen=True)
class HighAssuranceAuthorizationProfile:
    schema_version: str
    profile_id: str
    tenant_id: str
    security_boundary: str
    environment: str
    data_classifications: tuple[str, ...]
    minimum_assurance_tier: str
    authorization_state: str
    ato_reference: str | None
    fedramp_state: str
    dod_impact_level: str
    sovereign_required: bool
    offline_required: bool
    valid_from_epoch: int
    valid_until_epoch: int
    evidence_ref: str
    source_trust: str = "CALLER_SUPPLIED_UNTRUSTED"
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    authority_granted: bool = False


@dataclass(frozen=True)
class HighAssuranceModelAdmission:
    profile_id: str
    tenant_id: str
    security_boundary: str
    candidate_id: str
    provider: str
    model_id: str
    environment: str
    data_classification: str
    required_assurance_tier: str
    candidate_assurance_tier: str
    authorization_state: str
    profile_evidence_ref: str
    registry_evidence_ref: str
    disposition: str = "METADATA_ADMITTED"
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    invocation_authorized: bool = False
    authority_granted: bool = False


def _tenant_ref(value: Any, pattern: re.Pattern[str], tenant_id: str, reason: str) -> str:
    match = pattern.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) != tenant_id:
        raise HighAssuranceProfileDenied(reason)
    return value


def normalize_high_assurance_profile(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> HighAssuranceAuthorizationProfile:
    """Validate exact high-assurance metadata and record minimized Evidence first."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise HighAssuranceProfileDenied("PROFILE_INVALID")
    try:
        encoded = json.dumps(fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise HighAssuranceProfileDenied("PROFILE_INVALID") from exc
    if (
        len(encoded) > MAX_PROFILE_BYTES or set(fixture) != _FIELDS
        or fixture.get("schema_version") != "1"
        or _SECRET.search(encoded.decode("utf-8"))
    ):
        raise HighAssuranceProfileDenied("PROFILE_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise HighAssuranceProfileDenied("TENANT_INVALID")
    if fixture.get("tenant_id") != tenant_id:
        raise HighAssuranceProfileDenied("TENANT_MISMATCH")
    profile_id = _tenant_ref(fixture.get("profile_id"), _PROFILE, tenant_id, "PROFILE_ID_INVALID")
    boundary = _tenant_ref(fixture.get("security_boundary"), _BOUNDARY, tenant_id, "SECURITY_BOUNDARY_INVALID")
    evidence_ref = _tenant_ref(fixture.get("evidence_ref"), _EVID_REF, tenant_id, "EVIDENCE_REF_INVALID")
    ato = fixture.get("ato_reference")
    if ato is not None:
        ato = _tenant_ref(ato, _AUTH_REF, tenant_id, "ATO_REFERENCE_INVALID")
    environment = fixture.get("environment")
    classes = fixture.get("data_classifications")
    tier = fixture.get("minimum_assurance_tier")
    auth_state = fixture.get("authorization_state")
    fedramp = fixture.get("fedramp_state")
    impact = fixture.get("dod_impact_level")
    if environment not in _ENVIRONMENTS:
        raise HighAssuranceProfileDenied("ENVIRONMENT_INVALID")
    if (
        not isinstance(classes, list) or not classes
        or len(classes) > len(_DATA_CLASSES)
        or sorted(set(classes)) != classes
        or any(item not in _DATA_CLASSES for item in classes)
    ):
        raise HighAssuranceProfileDenied("DATA_CLASSIFICATIONS_INVALID")
    classes = tuple(classes)
    if tier not in _TIERS:
        raise HighAssuranceProfileDenied("ASSURANCE_TIER_INVALID")
    if auth_state not in _AUTH_STATES:
        raise HighAssuranceProfileDenied("AUTHORIZATION_STATE_INVALID")
    if fedramp not in _FEDRAMP_STATES:
        raise HighAssuranceProfileDenied("FEDRAMP_STATE_INVALID")
    if impact not in _DOD_LEVELS:
        raise HighAssuranceProfileDenied("DOD_IMPACT_LEVEL_INVALID")
    sovereign, offline = fixture.get("sovereign_required"), fixture.get("offline_required")
    if not isinstance(sovereign, bool) or not isinstance(offline, bool):
        raise HighAssuranceProfileDenied("EXECUTION_CONSTRAINT_INVALID")
    if offline and environment != "OFFLINE":
        raise HighAssuranceProfileDenied("OFFLINE_ENVIRONMENT_MISMATCH")
    if sovereign and environment not in {"SOVEREIGN", "OFFLINE"}:
        raise HighAssuranceProfileDenied("SOVEREIGN_ENVIRONMENT_MISMATCH")
    start, end = fixture.get("valid_from_epoch"), fixture.get("valid_until_epoch")
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (now_epoch, start, end)) or start < 0 or not start <= now_epoch < end:
        raise HighAssuranceProfileDenied("VALIDITY_INVALID")
    if auth_state == "EVIDENCE_BOUND" and ato is None:
        raise HighAssuranceProfileDenied("AUTHORIZATION_REFERENCE_REQUIRED")
    if auth_state != "EVIDENCE_BOUND" and (fedramp == "AUTHORIZED" or impact != "NOT_APPLICABLE"):
        raise HighAssuranceProfileDenied("AUTHORIZATION_CLAIM_INVALID")
    try:
        audit("high_assurance_profile_normalized", {
            "profile_id": profile_id, "tenant_id": tenant_id,
            "security_boundary": boundary, "environment": environment,
            "data_classifications": classes, "minimum_assurance_tier": tier,
            "authorization_state": auth_state, "fedramp_state": fedramp,
            "dod_impact_level": impact, "sovereign_required": sovereign,
            "offline_required": offline, "valid_from_epoch": start,
            "valid_until_epoch": end, "evidence_ref": evidence_ref,
            "source_trust": "CALLER_SUPPLIED_UNTRUSTED", "mode": "DRY_RUN",
            "deployment": "DISABLED", "authority_granted": False,
            "provider_invoked": False, "credential_resolved": False,
        })
    except Exception as exc:
        raise HighAssuranceProfileDenied("EVIDENCE_WRITE_FAILED") from exc
    return HighAssuranceAuthorizationProfile(
        "1", profile_id, tenant_id, boundary, environment, classes, tier,
        auth_state, ato, fedramp, impact, sovereign, offline, start, end,
        evidence_ref,
    )


def admit_high_assurance_model(
    profile: HighAssuranceAuthorizationProfile,
    candidate: ApprovedModelCandidate,
    *,
    tenant_id: str,
    security_boundary: str,
    environment: str,
    data_classification: str,
    now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> HighAssuranceModelAdmission:
    """Compose an exact profile and registry candidate without invoking a model."""
    if (
        not isinstance(profile, HighAssuranceAuthorizationProfile)
        or not isinstance(candidate, ApprovedModelCandidate)
        or not callable(audit)
    ):
        raise HighAssuranceProfileDenied("MODEL_ADMISSION_INVALID")
    if (
        profile.source_trust != "CALLER_SUPPLIED_UNTRUSTED"
        or profile.mode != "DRY_RUN" or profile.deployment != "DISABLED"
        or profile.authority_granted is not False
    ):
        raise HighAssuranceProfileDenied("PROFILE_AUTHORITY_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise HighAssuranceProfileDenied("TENANT_INVALID")
    if profile.tenant_id != tenant_id or candidate.tenant_id != tenant_id:
        raise HighAssuranceProfileDenied("TENANT_MISMATCH")
    _tenant_ref(profile.profile_id, _PROFILE, tenant_id, "PROFILE_ID_INVALID")
    profile_evidence_ref = _tenant_ref(
        profile.evidence_ref, _EVID_REF, tenant_id, "EVIDENCE_REF_INVALID",
    )
    registry_evidence_ref = _tenant_ref(
        candidate.registry_evidence_reference, _EVID_REF, tenant_id,
        "REGISTRY_EVIDENCE_REF_INVALID",
    )
    expected_boundary = _tenant_ref(
        security_boundary, _BOUNDARY, tenant_id, "SECURITY_BOUNDARY_INVALID",
    )
    if profile.security_boundary != expected_boundary:
        raise HighAssuranceProfileDenied("SECURITY_BOUNDARY_MISMATCH")
    if environment != profile.environment or candidate.environment.upper() != environment:
        raise HighAssuranceProfileDenied("ENVIRONMENT_MISMATCH")
    if (
        not isinstance(data_classification, str)
        or data_classification not in profile.data_classifications
        or data_classification not in candidate.allowed_data_classifications
    ):
        raise HighAssuranceProfileDenied("DATA_CLASSIFICATION_MISMATCH")
    if (
        not isinstance(now_epoch, int) or isinstance(now_epoch, bool)
        or not profile.valid_from_epoch <= now_epoch < profile.valid_until_epoch
    ):
        raise HighAssuranceProfileDenied("PROFILE_STALE")
    if profile.authorization_state != "EVIDENCE_BOUND" or profile.ato_reference is None:
        raise HighAssuranceProfileDenied("PROFILE_NOT_AUTHORIZED")
    _tenant_ref(profile.ato_reference, _AUTH_REF, tenant_id, "ATO_REFERENCE_INVALID")
    required_tier = AssuranceTier[profile.minimum_assurance_tier]
    if candidate.assurance_tier < required_tier:
        raise HighAssuranceProfileDenied("ASSURANCE_DOWNGRADE_DENIED")
    if not candidate.approved or not candidate.available:
        raise HighAssuranceProfileDenied("MODEL_NOT_APPROVED_OR_AVAILABLE")
    try:
        audit("high_assurance_model_admitted", {
            "profile_id": profile.profile_id, "tenant_id": tenant_id,
            "security_boundary": expected_boundary,
            "candidate_id": candidate.candidate_id,
            "provider": candidate.provider, "model_id": candidate.model_id,
            "environment": environment,
            "data_classification": data_classification,
            "required_assurance_tier": required_tier.name,
            "candidate_assurance_tier": candidate.assurance_tier.name,
            "authorization_state": profile.authorization_state,
            "profile_evidence_ref": profile_evidence_ref,
            "registry_evidence_ref": registry_evidence_ref,
            "mode": "DRY_RUN", "deployment": "DISABLED",
            "invocation_authorized": False, "authority_granted": False,
            "opaque_router_consulted": False,
        })
    except Exception as exc:
        raise HighAssuranceProfileDenied("EVIDENCE_WRITE_FAILED") from exc
    return HighAssuranceModelAdmission(
        profile.profile_id, tenant_id, expected_boundary, candidate.candidate_id,
        candidate.provider, candidate.model_id, environment, data_classification,
        required_tier.name, candidate.assurance_tier.name,
        profile.authorization_state, profile_evidence_ref,
        registry_evidence_ref,
    )
