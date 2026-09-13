"""Bounded caller-supplied SaaS security observation normalization."""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping

from .action_ticket import ActionTicketError, ActionTicketRegistry

MAX_SAAS_FIXTURE_BYTES = 32 * 1024
MAX_SAAS_REF_BYTES = 256
MAX_SAAS_INDICATORS = 16
MAX_SAAS_CORRELATION_EVIDENCE_REFS = 16
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,255}$")
_TENANT_REF = re.compile(
    r"^fw-(incident|finding|evid|resource|policy)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$"
)
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


@dataclass(frozen=True)
class SaaSFinding:
    event_id: str
    tenant_id: str
    provider: str
    signals: tuple[str, ...]
    confidence: str
    recommendations: tuple[str, ...] = ("WARN",)
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


@dataclass(frozen=True)
class SaaSCorrelationReference:
    event_id: str
    tenant_id: str
    provider: str
    confidence: str
    signals: tuple[str, ...]
    soc_incident_ref: str
    aid_finding_ref: str
    evidence_refs: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "CORRELATE_ONLY"


@dataclass(frozen=True)
class SaaSResponseProposal:
    event_id: str
    tenant_id: str
    target_ref: str
    soc_incident_ref: str
    aid_finding_ref: str
    policy_decision_ref: str
    action_ticket_ref: str
    action_class: str = "SAAS_APP_DISABLE_PROPOSAL"
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    kill_switch: str = "ENGAGED"
    disposition: str = "PROPOSE_ONLY"
    authority_granted: bool = False
    response_executed: bool = False


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


def classify_saas_observation(
    observation: SaaSObservation, *, tenant_id: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> SaaSFinding:
    """Classify exact normalized indicators without provider or response access."""
    if not isinstance(observation, SaaSObservation) or not callable(audit):
        raise SaaSObservationDenied("OBSERVATION_INVALID")
    expected_tenant = _reference(tenant_id, "TENANT")
    if observation.tenant_id != expected_tenant:
        raise SaaSObservationDenied("TENANT_MISMATCH")
    if (
        observation.trust != "UNTRUSTED_DATA"
        or observation.mode != "DRY_RUN"
        or observation.action != "DETECT_ONLY"
    ):
        raise SaaSObservationDenied("OBSERVATION_AUTHORITY_INVALID")
    if (
        observation.provider not in _PROVIDERS
        or observation.observation_type not in _OBSERVATION_TYPES
        or not isinstance(observation.observed_at_epoch, int)
        or isinstance(observation.observed_at_epoch, bool)
        or observation.observed_at_epoch < 0
        or not isinstance(observation.related_indicators, tuple)
        or not 1 <= len(observation.related_indicators) <= MAX_SAAS_INDICATORS
        or tuple(sorted(set(observation.related_indicators))) != observation.related_indicators
        or any(item not in _INDICATORS for item in observation.related_indicators)
    ):
        raise SaaSObservationDenied("OBSERVATION_INVALID")
    for value, field in (
        (observation.event_id, "EVENT_ID"),
        (observation.application_ref, "APPLICATION_REF"),
        (observation.principal_ref, "PRINCIPAL_REF"),
        (observation.target_ref, "TARGET_REF"),
        (observation.evidence_ref, "EVIDENCE_REF"),
    ):
        _reference(value, field)
    signals = set(observation.related_indicators)
    high_pairs = (
        {"RISKY_OAUTH_CONSENT", "EXCESSIVE_PRIVILEGE"},
        {"AI_APP_DATA_ACCESS", "PUBLIC_SHARE"},
        {"SUSPICIOUS_SIGN_IN", "EXCESSIVE_PRIVILEGE"},
    )
    if any(pair <= signals for pair in high_pairs):
        confidence = "HIGH"
    elif signals & {
        "AI_APP_DATA_ACCESS", "PUBLIC_SHARE", "RISKY_OAUTH_CONSENT",
        "SUSPICIOUS_SIGN_IN", "UNSAFE_THIRD_PARTY_APP",
    }:
        confidence = "MEDIUM"
    else:
        confidence = "LOW"
    ordered = tuple(sorted(signals))
    try:
        audit("saas_observation_classified", {
            "event_id": observation.event_id,
            "tenant_id": expected_tenant,
            "provider": observation.provider,
            "observation_type": observation.observation_type,
            "signals": list(ordered),
            "confidence": confidence,
            "recommendations": ["WARN"],
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "response_executed": False,
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SaaSObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return SaaSFinding(
        observation.event_id, expected_tenant, observation.provider, ordered,
        confidence,
    )


def bind_saas_correlation_references(
    finding: SaaSFinding, *, tenant_id: str, soc_incident_ref: str,
    aid_finding_ref: str, evidence_refs: tuple[str, ...],
    audit: Callable[[str, dict[str, Any]], None],
) -> SaaSCorrelationReference:
    """Bind canonical FW-SOC/FW-AID references without creating incident state."""
    if not isinstance(finding, SaaSFinding) or not callable(audit):
        raise SaaSObservationDenied("FINDING_INVALID")
    expected_tenant = _reference(tenant_id, "TENANT")
    if finding.tenant_id != expected_tenant:
        raise SaaSObservationDenied("TENANT_MISMATCH")
    if (
        finding.provider not in _PROVIDERS
        or finding.confidence not in {"LOW", "MEDIUM", "HIGH"}
        or finding.recommendations != ("WARN",)
        or finding.trust != "UNTRUSTED_DATA"
        or finding.mode != "DRY_RUN"
        or finding.action != "DETECT_ONLY"
        or not isinstance(finding.signals, tuple)
        or not 1 <= len(finding.signals) <= MAX_SAAS_INDICATORS
        or tuple(sorted(set(finding.signals))) != finding.signals
        or any(item not in _INDICATORS for item in finding.signals)
    ):
        raise SaaSObservationDenied("FINDING_INVALID")
    _reference(finding.event_id, "EVENT_ID")
    refs = (
        (soc_incident_ref, "incident"),
        (aid_finding_ref, "finding"),
    )
    for value, kind in refs:
        match = _TENANT_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != kind or match.group(2) != expected_tenant:
            raise SaaSObservationDenied("CORRELATION_REF_INVALID")
    if (
        not isinstance(evidence_refs, tuple)
        or not 1 <= len(evidence_refs) <= MAX_SAAS_CORRELATION_EVIDENCE_REFS
        or tuple(sorted(set(evidence_refs))) != evidence_refs
    ):
        raise SaaSObservationDenied("EVIDENCE_REFS_INVALID")
    for value in evidence_refs:
        match = _TENANT_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != "evid" or match.group(2) != expected_tenant:
            raise SaaSObservationDenied("EVIDENCE_REFS_INVALID")
    result = SaaSCorrelationReference(
        finding.event_id, expected_tenant, finding.provider,
        finding.confidence, finding.signals, soc_incident_ref,
        aid_finding_ref, evidence_refs,
    )
    try:
        audit("saas_correlation_references_bound", {
            "event_id": finding.event_id,
            "tenant_id": expected_tenant,
            "provider": finding.provider,
            "confidence": finding.confidence,
            "signals": list(finding.signals),
            "soc_incident_ref": soc_incident_ref,
            "aid_finding_ref": aid_finding_ref,
            "evidence_refs": list(evidence_refs),
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "CORRELATE_ONLY",
            "response_executed": False,
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SaaSObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return result


def propose_saas_app_disable(
    correlation: SaaSCorrelationReference, *, tickets: ActionTicketRegistry,
    ticket_id: str, target_ref: str, policy_decision_ref: str,
    subject_agent_id: str, lease_id: str, policy_version: str, now: int,
    kill_switch_state: str, audit: Callable[[str, dict[str, Any]], None],
) -> SaaSResponseProposal:
    """Consume exact proposal authority without changing a SaaS provider."""
    if (
        not isinstance(correlation, SaaSCorrelationReference)
        or not isinstance(tickets, ActionTicketRegistry)
        or not callable(audit)
    ):
        raise SaaSObservationDenied("PROPOSAL_INPUT_INVALID")
    expected_tenant = _reference(correlation.tenant_id, "TENANT")
    if (
        correlation.confidence != "HIGH"
        or correlation.trust != "UNTRUSTED_DATA"
        or correlation.mode != "DRY_RUN"
        or correlation.action != "CORRELATE_ONLY"
    ):
        raise SaaSObservationDenied("PROPOSAL_SOURCE_INVALID")
    if kill_switch_state != "ENGAGED":
        raise SaaSObservationDenied("KILL_SWITCH_NOT_ENGAGED")
    target_match = _TENANT_REF.fullmatch(target_ref) if isinstance(target_ref, str) else None
    policy_match = _TENANT_REF.fullmatch(policy_decision_ref) if isinstance(policy_decision_ref, str) else None
    if (
        target_match is None or target_match.group(1) != "resource"
        or policy_match is None or policy_match.group(1) != "policy"
        or target_match.group(2) != expected_tenant
        or policy_match.group(2) != expected_tenant
    ):
        raise SaaSObservationDenied("PROPOSAL_REF_INVALID")
    binding = {
        "tenant_id": expected_tenant,
        "subject_agent_id": subject_agent_id,
        "lease_id": lease_id,
        "capability": "saas.app.disable.propose",
        "resource": target_ref,
        "action_class": "SAAS_APP_DISABLE_PROPOSAL",
        "policy_version": policy_version,
        "now": now,
    }
    try:
        tickets.validate(ticket_id, **binding)
    except ActionTicketError as exc:
        raise SaaSObservationDenied("ACTION_TICKET_DENIED") from exc
    try:
        audit("saas_app_disable_proposed", {
            "event_id": correlation.event_id,
            "tenant_id": expected_tenant,
            "target_ref": target_ref,
            "soc_incident_ref": correlation.soc_incident_ref,
            "aid_finding_ref": correlation.aid_finding_ref,
            "policy_decision_ref": policy_decision_ref,
            "action_ticket_ref": ticket_id,
            "action_class": "SAAS_APP_DISABLE_PROPOSAL",
            "mode": "DRY_RUN",
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "disposition": "PROPOSE_ONLY",
            "authority_granted": False,
            "response_executed": False,
        })
    except Exception as exc:
        raise SaaSObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    try:
        tickets.validate_and_consume(ticket_id, **binding)
    except ActionTicketError as exc:
        raise SaaSObservationDenied("ACTION_TICKET_DENIED") from exc
    return SaaSResponseProposal(
        correlation.event_id, expected_tenant, target_ref,
        correlation.soc_incident_ref, correlation.aid_finding_ref,
        policy_decision_ref, ticket_id,
    )
