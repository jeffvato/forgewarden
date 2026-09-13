"""Bounded caller-supplied SaaS security observation normalization."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping

MAX_SAAS_FIXTURE_BYTES = 32 * 1024
MAX_SAAS_REF_BYTES = 256
MAX_SAAS_INDICATORS = 16
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_PROVIDERS = frozenset({"GENERIC_SAAS", "GOOGLE_WORKSPACE", "MICROSOFT_365", "SALESFORCE"})
_OBSERVATION_TYPES = frozenset({"ACCOUNT_POSTURE", "OAUTH_APP_POSTURE", "PUBLIC_SHARING", "SIGN_IN_RISK"})
_INDICATORS = frozenset({
    "AI_APP_DATA_ACCESS", "DORMANT_ACCOUNT", "EXCESSIVE_PRIVILEGE",
    "PUBLIC_SHARE", "RISKY_OAUTH_CONSENT", "SUSPICIOUS_SIGN_IN",
    "UNSAFE_THIRD_PARTY_APP",
})
_REQUIRED = frozenset({
    "event_id", "tenant_id", "observed_at_epoch", "provider",
    "application_ref", "principal_ref", "target_ref", "observation_type",
    "related_indicators", "evidence_ref",
})


class SaaSObservationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _reference(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value.encode("utf-8")) > MAX_SAAS_REF_BYTES
        or not _REF.fullmatch(value)
    ):
        raise SaaSObservationDenied(f"{field}_INVALID")
    return value


@dataclass(frozen=True)
class SaaSObservation:
    event_id: str
    tenant_id: str
    observed_at_epoch: int
    provider: str
    application_ref: str
    principal_ref: str
    target_ref: str
    observation_type: str
    related_indicators: tuple[str, ...]
    evidence_ref: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


def normalize_saas_observation(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> SaaSObservation:
    """Validate and Evidence-log one explicit SaaS metadata fixture."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise SaaSObservationDenied("FIXTURE_INVALID")
    try:
        size = len(json.dumps(
            fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8"))
    except (TypeError, ValueError, OverflowError) as exc:
        raise SaaSObservationDenied("FIXTURE_INVALID") from exc
    if size > MAX_SAAS_FIXTURE_BYTES or set(fixture) != _REQUIRED:
        raise SaaSObservationDenied("FIXTURE_INVALID")
    expected_tenant = _reference(tenant_id, "TENANT")
    if fixture.get("tenant_id") != expected_tenant:
        raise SaaSObservationDenied("TENANT_MISMATCH")
    provider = fixture.get("provider")
    observation_type = fixture.get("observation_type")
    if provider not in _PROVIDERS:
        raise SaaSObservationDenied("PROVIDER_INVALID")
    if observation_type not in _OBSERVATION_TYPES:
        raise SaaSObservationDenied("OBSERVATION_TYPE_INVALID")
    observed = fixture.get("observed_at_epoch")
    if (
        not isinstance(observed, int) or isinstance(observed, bool)
        or not isinstance(now_epoch, int) or isinstance(now_epoch, bool)
        or observed < 0 or observed > now_epoch
    ):
        raise SaaSObservationDenied("OBSERVED_AT_INVALID")
    indicators_value = fixture.get("related_indicators")
    if (
        not isinstance(indicators_value, (list, tuple))
        or not 1 <= len(indicators_value) <= MAX_SAAS_INDICATORS
        or len(set(indicators_value)) != len(indicators_value)
        or any(item not in _INDICATORS for item in indicators_value)
    ):
        raise SaaSObservationDenied("INDICATORS_INVALID")
    event_id = _reference(fixture.get("event_id"), "EVENT_ID")
    application_ref = _reference(fixture.get("application_ref"), "APPLICATION_REF")
    principal_ref = _reference(fixture.get("principal_ref"), "PRINCIPAL_REF")
    target_ref = _reference(fixture.get("target_ref"), "TARGET_REF")
    evidence_ref = _reference(fixture.get("evidence_ref"), "EVIDENCE_REF")
    indicators = tuple(sorted(indicators_value))
    try:
        audit("saas_observation_normalized", {
            "event_id": event_id,
            "tenant_id": expected_tenant,
            "observed_at_epoch": observed,
            "provider": provider,
            "observation_type": observation_type,
            "indicator_count": len(indicators),
            "evidence_ref": evidence_ref,
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SaaSObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return SaaSObservation(
        event_id, expected_tenant, observed, provider, application_ref,
        principal_ref, target_ref, observation_type, indicators, evidence_ref,
    )
