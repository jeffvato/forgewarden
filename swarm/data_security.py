"""Bounded caller-supplied FW-DSPM metadata contracts.

This module reads no content, enumerates no data, opens no service, and executes
no DLP, data-movement, mutation, or response action.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping

from .action_ticket import ActionTicketError, ActionTicketRegistry


MAX_DSPM_FIXTURE_BYTES = 32 * 1024
MAX_DSPM_COPY_COUNT = 100_000
MAX_DSPM_EVIDENCE_REFS = 16
_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_OWNER_REF = re.compile(
    r"^fw-(data|asset|evid)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_IDENTITY_REF = re.compile(r"^fw-id/([a-z][a-z0-9_.-]{0,127})\.[a-z][a-z0-9_.-]{0,126}$")
_CANONICAL_REF = re.compile(
    r"^fw-(saas|component|workflow|policy|incident|evid)/"
    r"([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_PROPOSAL_REF = re.compile(
    r"^fw-(data|policy)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_CLASSIFICATIONS = frozenset({"CONFIDENTIAL", "INTERNAL", "PUBLIC", "RESTRICTED"})
_LOCATIONS = frozenset({
    "AI_WORKFLOW", "BROWSER_EMAIL", "DATABASE", "ENDPOINT", "REPOSITORY", "SAAS_CLOUD",
})
_ACCESS_PATHS = frozenset({"DIRECT", "EXTERNAL", "SHARED", "UNKNOWN"})
_ENCRYPTION = frozenset({"ENCRYPTED", "UNENCRYPTED", "UNKNOWN"})
_AI_ACCESS = frozenset({"APPROVED", "NONE", "UNAPPROVED", "UNKNOWN"})
_POLICY = frozenset({"COMPLIANT", "UNKNOWN", "VIOLATION"})
_RISK_SIGNALS = frozenset({
    "AI_ACCESS_UNAPPROVED", "COPIES_ELEVATED", "ENCRYPTION_MISSING",
    "ENCRYPTION_UNKNOWN", "EXTERNAL_ACCESS", "POLICY_UNKNOWN",
    "POLICY_VIOLATION", "SENSITIVE_DATA",
})
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


@dataclass(frozen=True)
class DataSecurityFinding:
    event_id: str
    tenant_id: str
    data_asset_ref: str
    location_asset_ref: str
    owner_identity_ref: str
    location_class: str
    classification: str
    signals: tuple[str, ...]
    risk: str
    recommendations: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "ADVISE_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class DataSecurityReferenceBinding:
    event_id: str
    tenant_id: str
    data_asset_ref: str
    location_asset_ref: str
    owner_identity_ref: str
    risk: str
    saas_ref: str
    supply_ref: str
    ai_workflow_ref: str
    policy_decision_ref: str
    soc_incident_ref: str
    evidence_refs: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "CORRELATE_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class DataSecurityDLPProposal:
    event_id: str
    tenant_id: str
    target_ref: str
    policy_decision_ref: str
    action_ticket_ref: str
    risk: str
    action_class: str = "DSPM_DLP_PROPOSAL"
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    kill_switch: str = "ENGAGED"
    disposition: str = "PROPOSE_ONLY"
    authority_granted: bool = False
    response_executed: bool = False


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


def classify_data_security_observation(
    observation: DataSecurityObservation, *, tenant_id: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> DataSecurityFinding:
    """Classify only admitted posture facts without inspecting data or using AI."""
    if not isinstance(observation, DataSecurityObservation) or not callable(audit):
        raise DataSecurityObservationDenied("OBSERVATION_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise DataSecurityObservationDenied("TENANT_INVALID")
    if observation.tenant_id != tenant_id:
        raise DataSecurityObservationDenied("TENANT_MISMATCH")
    if (
        observation.trust != "UNTRUSTED_DATA" or observation.mode != "DRY_RUN"
        or observation.action != "DETECT_ONLY"
        or observation.authority_granted is not False
    ):
        raise DataSecurityObservationDenied("OBSERVATION_AUTHORITY_INVALID")
    if observation.location_class == "AI_WORKFLOW" and observation.ai_access_state == "NONE":
        raise DataSecurityObservationDenied("FACTS_CONTRADICTORY")
    signals: set[str] = set()
    sensitive = observation.classification in {"CONFIDENTIAL", "RESTRICTED"}
    if sensitive:
        signals.add("SENSITIVE_DATA")
    if observation.access_path == "EXTERNAL":
        signals.add("EXTERNAL_ACCESS")
    if observation.encryption_state == "UNENCRYPTED":
        signals.add("ENCRYPTION_MISSING")
    elif observation.encryption_state == "UNKNOWN":
        signals.add("ENCRYPTION_UNKNOWN")
    if observation.ai_access_state == "UNAPPROVED":
        signals.add("AI_ACCESS_UNAPPROVED")
    if observation.policy_state == "VIOLATION":
        signals.add("POLICY_VIOLATION")
    elif observation.policy_state == "UNKNOWN":
        signals.add("POLICY_UNKNOWN")
    if observation.copy_count > 10:
        signals.add("COPIES_ELEVATED")
    severe = {"EXTERNAL_ACCESS", "AI_ACCESS_UNAPPROVED", "POLICY_VIOLATION"}
    if sensitive and len(signals & severe) >= 2:
        risk = "CRITICAL"
    elif sensitive and signals & severe:
        risk = "HIGH"
    elif signals & severe or signals & {"ENCRYPTION_MISSING", "COPIES_ELEVATED"}:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    ordered_signals = tuple(sorted(signals))
    if not set(ordered_signals) <= _RISK_SIGNALS:
        raise DataSecurityObservationDenied("SIGNALS_INVALID")
    recommendations = (
        ("WARN", "PROPOSE_DLP") if risk in {"HIGH", "CRITICAL"} else ("WARN",)
    )
    try:
        audit("data_security_observation_classified", {
            "event_id": observation.event_id, "tenant_id": tenant_id,
            "data_asset_ref": observation.data_asset_ref,
            "classification": observation.classification,
            "signals": ordered_signals, "risk": risk,
            "recommendations": recommendations,
            "evidence_ref": observation.evidence_ref,
            "trust": "UNTRUSTED_DATA", "mode": "DRY_RUN",
            "action": "ADVISE_ONLY", "deployment": "DISABLED",
            "response_executed": False, "authority_granted": False,
        })
    except Exception as exc:
        raise DataSecurityObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return DataSecurityFinding(
        observation.event_id, tenant_id, observation.data_asset_ref,
        observation.location_asset_ref, observation.owner_identity_ref,
        observation.location_class, observation.classification, ordered_signals,
        risk, recommendations,
    )


def bind_data_security_references(
    finding: DataSecurityFinding, *, tenant_id: str, saas_ref: str,
    supply_ref: str, ai_workflow_ref: str, policy_decision_ref: str,
    soc_incident_ref: str, evidence_refs: tuple[str, ...],
    audit: Callable[[str, dict[str, Any]], None],
) -> DataSecurityReferenceBinding:
    """Bind existing owner references without accessing data or creating state."""
    if not isinstance(finding, DataSecurityFinding) or not callable(audit):
        raise DataSecurityObservationDenied("FINDING_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise DataSecurityObservationDenied("TENANT_INVALID")
    if finding.tenant_id != tenant_id:
        raise DataSecurityObservationDenied("TENANT_MISMATCH")
    expected_recommendations = (
        ("WARN", "PROPOSE_DLP") if finding.risk in {"HIGH", "CRITICAL"} else ("WARN",)
    )
    if (
        finding.risk not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        or finding.recommendations != expected_recommendations
        or finding.trust != "UNTRUSTED_DATA" or finding.mode != "DRY_RUN"
        or finding.action != "ADVISE_ONLY"
        or finding.authority_granted is not False
        or tuple(sorted(set(finding.signals))) != finding.signals
        or not set(finding.signals) <= _RISK_SIGNALS
    ):
        raise DataSecurityObservationDenied("FINDING_INVALID")
    data_ref = _owner_ref(finding.data_asset_ref, "data", tenant_id, "DATA_ASSET_REF")
    location_ref = _owner_ref(finding.location_asset_ref, "asset", tenant_id, "LOCATION_ASSET_REF")
    identity_match = _IDENTITY_REF.fullmatch(finding.owner_identity_ref) if isinstance(finding.owner_identity_ref, str) else None
    if identity_match is None or identity_match.group(1) != tenant_id:
        raise DataSecurityObservationDenied("OWNER_IDENTITY_REF_INVALID")
    for value, kind, reason in (
        (saas_ref, "saas", "SAAS_REF_INVALID"),
        (supply_ref, "component", "SUPPLY_REF_INVALID"),
        (ai_workflow_ref, "workflow", "AI_WORKFLOW_REF_INVALID"),
        (policy_decision_ref, "policy", "POLICY_REF_INVALID"),
        (soc_incident_ref, "incident", "SOC_INCIDENT_REF_INVALID"),
    ):
        match = _CANONICAL_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != kind or match.group(2) != tenant_id:
            raise DataSecurityObservationDenied(reason)
    if (
        not isinstance(evidence_refs, tuple)
        or not 1 <= len(evidence_refs) <= MAX_DSPM_EVIDENCE_REFS
        or tuple(sorted(set(evidence_refs))) != evidence_refs
    ):
        raise DataSecurityObservationDenied("EVIDENCE_REFS_INVALID")
    for value in evidence_refs:
        match = _CANONICAL_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != "evid" or match.group(2) != tenant_id:
            raise DataSecurityObservationDenied("EVIDENCE_REFS_INVALID")
    try:
        audit("data_security_references_bound", {
            "event_id": finding.event_id, "tenant_id": tenant_id,
            "data_asset_ref": data_ref, "location_asset_ref": location_ref,
            "owner_identity_ref": finding.owner_identity_ref, "risk": finding.risk,
            "saas_ref": saas_ref, "supply_ref": supply_ref,
            "ai_workflow_ref": ai_workflow_ref,
            "policy_decision_ref": policy_decision_ref,
            "soc_incident_ref": soc_incident_ref, "evidence_refs": evidence_refs,
            "trust": "UNTRUSTED_DATA", "mode": "DRY_RUN",
            "action": "CORRELATE_ONLY", "deployment": "DISABLED",
            "response_executed": False, "authority_granted": False,
        })
    except Exception as exc:
        raise DataSecurityObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return DataSecurityReferenceBinding(
        finding.event_id, tenant_id, data_ref, location_ref,
        finding.owner_identity_ref, finding.risk, saas_ref, supply_ref,
        ai_workflow_ref, policy_decision_ref, soc_incident_ref, evidence_refs,
    )


def propose_data_security_dlp(
    binding: DataSecurityReferenceBinding, *, tickets: ActionTicketRegistry,
    ticket_id: str, target_ref: str, policy_decision_ref: str,
    subject_agent_id: str, lease_id: str, policy_version: str, now: int,
    kill_switch_state: str, audit: Callable[[str, dict[str, Any]], None],
) -> DataSecurityDLPProposal:
    """Consume proposal-only authority without inspecting or changing data."""
    if (
        not isinstance(binding, DataSecurityReferenceBinding)
        or not isinstance(tickets, ActionTicketRegistry) or not callable(audit)
    ):
        raise DataSecurityObservationDenied("PROPOSAL_INPUT_INVALID")
    if (
        binding.risk not in {"HIGH", "CRITICAL"}
        or binding.trust != "UNTRUSTED_DATA" or binding.mode != "DRY_RUN"
        or binding.action != "CORRELATE_ONLY"
        or binding.authority_granted is not False
    ):
        raise DataSecurityObservationDenied("PROPOSAL_SOURCE_INVALID")
    if kill_switch_state != "ENGAGED":
        raise DataSecurityObservationDenied("KILL_SWITCH_NOT_ENGAGED")
    target_match = _PROPOSAL_REF.fullmatch(target_ref) if isinstance(target_ref, str) else None
    policy_match = _PROPOSAL_REF.fullmatch(policy_decision_ref) if isinstance(policy_decision_ref, str) else None
    if (
        target_match is None or target_match.group(1) != "data"
        or policy_match is None or policy_match.group(1) != "policy"
        or target_match.group(2) != binding.tenant_id
        or policy_match.group(2) != binding.tenant_id
        or target_ref != binding.data_asset_ref
    ):
        raise DataSecurityObservationDenied("PROPOSAL_REF_INVALID")
    ticket_binding = {
        "tenant_id": binding.tenant_id, "subject_agent_id": subject_agent_id,
        "lease_id": lease_id, "capability": "dspm.dlp.propose",
        "resource": target_ref, "action_class": "DSPM_DLP_PROPOSAL",
        "policy_version": policy_version, "now": now,
    }
    try:
        tickets.validate(ticket_id, **ticket_binding)
    except ActionTicketError as exc:
        raise DataSecurityObservationDenied("ACTION_TICKET_DENIED") from exc
    try:
        audit("data_security_dlp_proposed", {
            "event_id": binding.event_id, "tenant_id": binding.tenant_id,
            "target_ref": target_ref, "policy_decision_ref": policy_decision_ref,
            "action_ticket_ref": ticket_id, "risk": binding.risk,
            "action_class": "DSPM_DLP_PROPOSAL", "mode": "DRY_RUN",
            "deployment": "DISABLED", "kill_switch": "ENGAGED",
            "disposition": "PROPOSE_ONLY", "authority_granted": False,
            "response_executed": False,
        })
    except Exception as exc:
        raise DataSecurityObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    try:
        tickets.validate_and_consume(ticket_id, **ticket_binding)
    except ActionTicketError as exc:
        raise DataSecurityObservationDenied("ACTION_TICKET_DENIED") from exc
    return DataSecurityDLPProposal(
        binding.event_id, binding.tenant_id, target_ref, policy_decision_ref,
        ticket_id, binding.risk,
    )
