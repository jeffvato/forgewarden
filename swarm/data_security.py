"""Bounded caller-supplied FW-DSPM metadata contracts.

This module reads no content, enumerates no data, opens no service, and executes
no DLP, data-movement, mutation, or response action.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping


MAX_DSPM_FIXTURE_BYTES = 32 * 1024
MAX_DSPM_COPY_COUNT = 100_000
_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_OWNER_REF = re.compile(
    r"^fw-(data|asset|evid)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_IDENTITY_REF = re.compile(r"^fw-id/([a-z][a-z0-9_.-]{0,127})\.[a-z][a-z0-9_.-]{0,126}$")
_CLASSIFICATIONS = frozenset({"CONFIDENTIAL", "INTERNAL", "PUBLIC", "RESTRICTED"})
_LOCATIONS = frozenset({
    "AI_WORKFLOW", "BROWSER_EMAIL", "DATABASE", "ENDPOINT", "REPOSITORY", "SAAS_CLOUD",
})
_ACCESS_PATHS = frozenset({"DIRECT", "EXTERNAL", "SHARED", "UNKNOWN"})
_ENCRYPTION = frozenset({"ENCRYPTED", "UNENCRYPTED", "UNKNOWN"})
_AI_ACCESS = frozenset({"APPROVED", "NONE", "UNAPPROVED", "UNKNOWN"})
_POLICY = frozenset({"COMPLIANT", "UNKNOWN", "VIOLATION"})
_REQUIRED = frozenset({
    "event_id", "tenant_id", "observed_at_epoch", "data_asset_ref",
    "location_asset_ref", "classification", "location_class",
    "owner_identity_ref", "access_path", "copy_count", "encryption_state",
    "ai_access_state", "policy_state", "evidence_ref",
})


class DataSecurityObservationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _TEXT.fullmatch(value):
        raise DataSecurityObservationDenied(f"{field}_INVALID")
    return value


def _owner_ref(value: Any, kind: str, tenant_id: str, field: str) -> str:
    match = _OWNER_REF.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) != kind or match.group(2) != tenant_id:
        raise DataSecurityObservationDenied(f"{field}_INVALID")
    return value


@dataclass(frozen=True)
class DataSecurityObservation:
    event_id: str
    tenant_id: str
    observed_at_epoch: int
    data_asset_ref: str
    location_asset_ref: str
    classification: str
    location_class: str
    owner_identity_ref: str
    access_path: str
    copy_count: int
    encryption_state: str
    ai_access_state: str
    policy_state: str
    evidence_ref: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"
    authority_granted: bool = False


def normalize_data_security_observation(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> DataSecurityObservation:
    """Validate one exact data-posture fixture and record Evidence first."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise DataSecurityObservationDenied("FIXTURE_INVALID")
    try:
        encoded = json.dumps(
            fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise DataSecurityObservationDenied("FIXTURE_INVALID") from exc
    if len(encoded) > MAX_DSPM_FIXTURE_BYTES or set(fixture) != _REQUIRED:
        raise DataSecurityObservationDenied("FIXTURE_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise DataSecurityObservationDenied("TENANT_INVALID")
    if fixture.get("tenant_id") != tenant_id:
        raise DataSecurityObservationDenied("TENANT_MISMATCH")
    observed = fixture.get("observed_at_epoch")
    if (
        not isinstance(observed, int) or isinstance(observed, bool)
        or not isinstance(now_epoch, int) or isinstance(now_epoch, bool)
        or observed < 0 or observed > now_epoch
    ):
        raise DataSecurityObservationDenied("OBSERVED_AT_INVALID")
    classification, location = fixture.get("classification"), fixture.get("location_class")
    access_path, encryption = fixture.get("access_path"), fixture.get("encryption_state")
    ai_access, policy = fixture.get("ai_access_state"), fixture.get("policy_state")
    if classification not in _CLASSIFICATIONS:
        raise DataSecurityObservationDenied("CLASSIFICATION_INVALID")
    if location not in _LOCATIONS:
        raise DataSecurityObservationDenied("LOCATION_CLASS_INVALID")
    if access_path not in _ACCESS_PATHS:
        raise DataSecurityObservationDenied("ACCESS_PATH_INVALID")
    if encryption not in _ENCRYPTION:
        raise DataSecurityObservationDenied("ENCRYPTION_STATE_INVALID")
    if ai_access not in _AI_ACCESS:
        raise DataSecurityObservationDenied("AI_ACCESS_STATE_INVALID")
    if policy not in _POLICY:
        raise DataSecurityObservationDenied("POLICY_STATE_INVALID")
    copy_count = fixture.get("copy_count")
    if (
        not isinstance(copy_count, int) or isinstance(copy_count, bool)
        or not 0 <= copy_count <= MAX_DSPM_COPY_COUNT
    ):
        raise DataSecurityObservationDenied("COPY_COUNT_INVALID")
    event_id = _text(fixture.get("event_id"), "EVENT_ID")
    data_ref = _owner_ref(fixture.get("data_asset_ref"), "data", tenant_id, "DATA_ASSET_REF")
    location_ref = _owner_ref(fixture.get("location_asset_ref"), "asset", tenant_id, "LOCATION_ASSET_REF")
    evidence_ref = _owner_ref(fixture.get("evidence_ref"), "evid", tenant_id, "EVIDENCE_REF")
    identity_ref = fixture.get("owner_identity_ref")
    identity_match = _IDENTITY_REF.fullmatch(identity_ref) if isinstance(identity_ref, str) else None
    if identity_match is None or identity_match.group(1) != tenant_id:
        raise DataSecurityObservationDenied("OWNER_IDENTITY_REF_INVALID")
    try:
        audit("data_security_observation_normalized", {
            "event_id": event_id, "tenant_id": tenant_id,
            "observed_at_epoch": observed, "data_asset_ref": data_ref,
            "location_class": location, "classification": classification,
            "access_path": access_path, "copy_count": copy_count,
            "encryption_state": encryption, "ai_access_state": ai_access,
            "policy_state": policy, "evidence_ref": evidence_ref,
            "trust": "UNTRUSTED_DATA", "mode": "DRY_RUN",
            "action": "DETECT_ONLY", "deployment": "DISABLED",
            "response_executed": False, "authority_granted": False,
        })
    except Exception as exc:
        raise DataSecurityObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return DataSecurityObservation(
        event_id, tenant_id, observed, data_ref, location_ref, classification,
        location, identity_ref, access_path, copy_count, encryption, ai_access,
        policy, evidence_ref,
    )
