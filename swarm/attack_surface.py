"""Bounded caller-supplied FW-ASM metadata contracts.

This module performs no discovery, DNS lookup, scan, connection, cloud query,
certificate retrieval, or response action.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping

from .action_ticket import ActionTicketError, ActionTicketRegistry


MAX_ASM_FIXTURE_BYTES = 32 * 1024
MAX_ASM_OWNER_REFS = 16
_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_OWNER_REF = re.compile(
    r"^fw-(asset|exposure|evid)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_CANONICAL_REF = re.compile(
    r"^fw-(network|vuln|catalog|signature|incident|evid)/"
    r"([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_PROPOSAL_REF = re.compile(
    r"^fw-(exposure|policy)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_ASSET_TYPES = frozenset({
    "API", "CLOUD_RESOURCE", "DATABASE", "DEVELOPMENT_SYSTEM", "DOMAIN",
    "PUBLIC_IP", "REMOTE_ACCESS", "VPN_ENDPOINT", "WEBSITE",
})
_SERVICES = frozenset({"API", "DATABASE", "DNS", "HTTP", "REMOTE_ACCESS", "VPN"})
_PROTOCOLS = frozenset({"DNS", "HTTP", "HTTPS", "RDP", "SSH", "TCP", "TLS", "UDP", "VPN"})
_OWNERSHIP = frozenset({"KNOWN", "UNKNOWN"})
_VISIBILITY = frozenset({"PUBLIC", "RESTRICTED", "UNEXPECTED"})
_EXPLOITABILITY = frozenset({
    "CONFIRMED_EXPLOITABLE", "NOT_EXPLOITABLE", "POTENTIALLY_EXPLOITABLE", "UNKNOWN",
})
_REQUIRED = frozenset({
    "event_id", "tenant_id", "observed_at_epoch", "asset_type", "asset_ref",
    "exposure_ref", "service", "protocol", "port", "ownership_state",
    "visibility_state", "evidence_ref",
})


class AttackSurfaceObservationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _TEXT.fullmatch(value):
        raise AttackSurfaceObservationDenied(f"{field}_INVALID")
    return value


def _owner_ref(value: Any, kind: str, tenant_id: str, field: str) -> str:
    match = _OWNER_REF.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) != kind or match.group(2) != tenant_id:
        raise AttackSurfaceObservationDenied(f"{field}_INVALID")
    return value


@dataclass(frozen=True)
class AttackSurfaceObservation:
    event_id: str
    tenant_id: str
    observed_at_epoch: int
    asset_type: str
    asset_ref: str
    exposure_ref: str
    service: str
    protocol: str
    port: int
    ownership_state: str
    visibility_state: str
    evidence_ref: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class AttackSurfaceFinding:
    event_id: str
    tenant_id: str
    asset_ref: str
    exposure_ref: str
    visibility_state: str
    ownership_state: str
    exploitability_state: str
    forgotten_asset: bool
    risk: str
    recommendations: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "ADVISE_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class AttackSurfaceReferenceBinding:
    event_id: str
    tenant_id: str
    asset_ref: str
    exposure_ref: str
    risk: str
    network_ref: str
    vulnerability_refs: tuple[str, ...]
    catalog_ref: str
    signature_ref: str
    soc_incident_ref: str
    evidence_refs: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "CORRELATE_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class AttackSurfaceRiskReductionProposal:
    event_id: str
    tenant_id: str
    target_ref: str
    policy_decision_ref: str
    action_ticket_ref: str
    risk: str
    action_class: str = "ASM_RISK_REDUCTION_PROPOSAL"
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    kill_switch: str = "ENGAGED"
    disposition: str = "PROPOSE_ONLY"
    authority_granted: bool = False
    response_executed: bool = False


@dataclass(frozen=True)
class AttackSurfaceDryRunLifecycle:
    observation: AttackSurfaceObservation
    finding: AttackSurfaceFinding
    binding: AttackSurfaceReferenceBinding
    proposal: AttackSurfaceRiskReductionProposal
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    kill_switch: str = "ENGAGED"
    authority_granted: bool = False
    response_executed: bool = False


def normalize_attack_surface_observation(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> AttackSurfaceObservation:
    """Validate one exact external-asset fixture and record Evidence first."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise AttackSurfaceObservationDenied("FIXTURE_INVALID")
    try:
        encoded = json.dumps(fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise AttackSurfaceObservationDenied("FIXTURE_INVALID") from exc
    if len(encoded) > MAX_ASM_FIXTURE_BYTES or set(fixture) != _REQUIRED:
        raise AttackSurfaceObservationDenied("FIXTURE_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise AttackSurfaceObservationDenied("TENANT_INVALID")
    if fixture.get("tenant_id") != tenant_id:
        raise AttackSurfaceObservationDenied("TENANT_MISMATCH")
    observed = fixture.get("observed_at_epoch")
    if (
        not isinstance(observed, int) or isinstance(observed, bool)
        or not isinstance(now_epoch, int) or isinstance(now_epoch, bool)
        or observed < 0 or observed > now_epoch
    ):
        raise AttackSurfaceObservationDenied("OBSERVED_AT_INVALID")
    asset_type, service = fixture.get("asset_type"), fixture.get("service")
    protocol, ownership = fixture.get("protocol"), fixture.get("ownership_state")
    visibility, port = fixture.get("visibility_state"), fixture.get("port")
    if asset_type not in _ASSET_TYPES:
        raise AttackSurfaceObservationDenied("ASSET_TYPE_INVALID")
    if service not in _SERVICES:
        raise AttackSurfaceObservationDenied("SERVICE_INVALID")
    if protocol not in _PROTOCOLS:
        raise AttackSurfaceObservationDenied("PROTOCOL_INVALID")
    if ownership not in _OWNERSHIP:
        raise AttackSurfaceObservationDenied("OWNERSHIP_STATE_INVALID")
    if visibility not in _VISIBILITY:
        raise AttackSurfaceObservationDenied("VISIBILITY_STATE_INVALID")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise AttackSurfaceObservationDenied("PORT_INVALID")
    event_id = _text(fixture.get("event_id"), "EVENT_ID")
    asset_ref = _owner_ref(fixture.get("asset_ref"), "asset", tenant_id, "ASSET_REF")
    exposure_ref = _owner_ref(fixture.get("exposure_ref"), "exposure", tenant_id, "EXPOSURE_REF")
    evidence_ref = _owner_ref(fixture.get("evidence_ref"), "evid", tenant_id, "EVIDENCE_REF")
    try:
        audit("attack_surface_observation_normalized", {
            "event_id": event_id, "tenant_id": tenant_id,
            "observed_at_epoch": observed, "asset_type": asset_type,
            "service": service, "protocol": protocol, "port": port,
            "ownership_state": ownership, "visibility_state": visibility,
            "evidence_ref": evidence_ref, "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN", "action": "DETECT_ONLY",
            "deployment": "DISABLED", "response_executed": False,
            "authority_granted": False,
        })
    except Exception as exc:
        raise AttackSurfaceObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return AttackSurfaceObservation(
        event_id, tenant_id, observed, asset_type, asset_ref, exposure_ref,
        service, protocol, port, ownership, visibility, evidence_ref,
    )


def classify_attack_surface_observation(
    observation: AttackSurfaceObservation, *, tenant_id: str,
    exploitability_state: str, forgotten_asset: bool,
    audit: Callable[[str, dict[str, Any]], None],
) -> AttackSurfaceFinding:
    """Classify admitted caller-supplied facts without discovery or model input."""
    if not isinstance(observation, AttackSurfaceObservation) or not callable(audit):
        raise AttackSurfaceObservationDenied("OBSERVATION_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise AttackSurfaceObservationDenied("TENANT_INVALID")
    if observation.tenant_id != tenant_id:
        raise AttackSurfaceObservationDenied("TENANT_MISMATCH")
    if (
        observation.trust != "UNTRUSTED_DATA" or observation.mode != "DRY_RUN"
        or observation.action != "DETECT_ONLY"
        or observation.authority_granted is not False
    ):
        raise AttackSurfaceObservationDenied("OBSERVATION_AUTHORITY_INVALID")
    if exploitability_state not in _EXPLOITABILITY:
        raise AttackSurfaceObservationDenied("EXPLOITABILITY_INVALID")
    if not isinstance(forgotten_asset, bool):
        raise AttackSurfaceObservationDenied("FORGOTTEN_ASSET_INVALID")
    if forgotten_asset and observation.ownership_state == "KNOWN":
        raise AttackSurfaceObservationDenied("FACTS_CONTRADICTORY")
    exposed = observation.visibility_state in {"PUBLIC", "UNEXPECTED"}
    if exposed and exploitability_state == "CONFIRMED_EXPLOITABLE":
        risk = "CRITICAL"
    elif exposed and (
        exploitability_state == "POTENTIALLY_EXPLOITABLE"
        or observation.ownership_state == "UNKNOWN" or forgotten_asset
    ):
        risk = "HIGH"
    elif exposed or exploitability_state in {"CONFIRMED_EXPLOITABLE", "POTENTIALLY_EXPLOITABLE"}:
        risk = "MEDIUM"
    else:
        risk = "LOW"
    recommendations = (
        ("WARN", "PROPOSE_RISK_REDUCTION")
        if risk in {"HIGH", "CRITICAL"} else ("WARN",)
    )
    try:
        audit("attack_surface_observation_classified", {
            "event_id": observation.event_id, "tenant_id": tenant_id,
            "asset_ref": observation.asset_ref,
            "visibility_state": observation.visibility_state,
            "ownership_state": observation.ownership_state,
            "exploitability_state": exploitability_state,
            "forgotten_asset": forgotten_asset, "risk": risk,
            "recommendations": recommendations,
            "evidence_ref": observation.evidence_ref,
            "trust": "UNTRUSTED_DATA", "mode": "DRY_RUN",
            "action": "ADVISE_ONLY", "deployment": "DISABLED",
            "response_executed": False, "authority_granted": False,
        })
    except Exception as exc:
        raise AttackSurfaceObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return AttackSurfaceFinding(
        observation.event_id, tenant_id, observation.asset_ref,
        observation.exposure_ref, observation.visibility_state,
        observation.ownership_state, exploitability_state, forgotten_asset,
        risk, recommendations,
    )


def bind_attack_surface_references(
    finding: AttackSurfaceFinding, *, tenant_id: str, network_ref: str,
    vulnerability_refs: tuple[str, ...], catalog_ref: str, signature_ref: str,
    soc_incident_ref: str, evidence_refs: tuple[str, ...],
    audit: Callable[[str, dict[str, Any]], None],
) -> AttackSurfaceReferenceBinding:
    """Bind canonical owner references without creating owner state or trust."""
    if not isinstance(finding, AttackSurfaceFinding) or not callable(audit):
        raise AttackSurfaceObservationDenied("FINDING_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise AttackSurfaceObservationDenied("TENANT_INVALID")
    if finding.tenant_id != tenant_id:
        raise AttackSurfaceObservationDenied("TENANT_MISMATCH")
    expected_recommendations = (
        ("WARN", "PROPOSE_RISK_REDUCTION")
        if finding.risk in {"HIGH", "CRITICAL"} else ("WARN",)
    )
    if (
        finding.risk not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        or finding.recommendations != expected_recommendations
        or finding.trust != "UNTRUSTED_DATA" or finding.mode != "DRY_RUN"
        or finding.action != "ADVISE_ONLY"
        or finding.authority_granted is not False
    ):
        raise AttackSurfaceObservationDenied("FINDING_INVALID")
    asset_ref = _owner_ref(finding.asset_ref, "asset", tenant_id, "ASSET_REF")
    exposure_ref = _owner_ref(finding.exposure_ref, "exposure", tenant_id, "EXPOSURE_REF")
    scalar_refs = (
        (network_ref, "network", "NETWORK_REF_INVALID"),
        (catalog_ref, "catalog", "CERTIFICATE_REF_INVALID"),
        (signature_ref, "signature", "CERTIFICATE_REF_INVALID"),
        (soc_incident_ref, "incident", "SOC_INCIDENT_REF_INVALID"),
    )
    for value, kind, reason in scalar_refs:
        match = _CANONICAL_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != kind or match.group(2) != tenant_id:
            raise AttackSurfaceObservationDenied(reason)
    for values, kind, reason in (
        (vulnerability_refs, "vuln", "VULNERABILITY_REFS_INVALID"),
        (evidence_refs, "evid", "EVIDENCE_REFS_INVALID"),
    ):
        if (
            not isinstance(values, tuple) or not 1 <= len(values) <= MAX_ASM_OWNER_REFS
            or tuple(sorted(set(values))) != values
        ):
            raise AttackSurfaceObservationDenied(reason)
        for value in values:
            match = _CANONICAL_REF.fullmatch(value) if isinstance(value, str) else None
            if match is None or match.group(1) != kind or match.group(2) != tenant_id:
                raise AttackSurfaceObservationDenied(reason)
    try:
        audit("attack_surface_references_bound", {
            "event_id": finding.event_id, "tenant_id": tenant_id,
            "asset_ref": asset_ref, "exposure_ref": exposure_ref,
            "risk": finding.risk, "network_ref": network_ref,
            "vulnerability_refs": vulnerability_refs,
            "catalog_ref": catalog_ref, "signature_ref": signature_ref,
            "soc_incident_ref": soc_incident_ref,
            "evidence_refs": evidence_refs, "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN", "action": "CORRELATE_ONLY",
            "deployment": "DISABLED", "response_executed": False,
            "authority_granted": False,
        })
    except Exception as exc:
        raise AttackSurfaceObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return AttackSurfaceReferenceBinding(
        finding.event_id, tenant_id, asset_ref, exposure_ref, finding.risk,
        network_ref, vulnerability_refs, catalog_ref, signature_ref,
        soc_incident_ref, evidence_refs,
    )


def propose_attack_surface_risk_reduction(
    binding: AttackSurfaceReferenceBinding, *, tickets: ActionTicketRegistry,
    ticket_id: str, target_ref: str, policy_decision_ref: str,
    subject_agent_id: str, lease_id: str, policy_version: str, now: int,
    kill_switch_state: str, audit: Callable[[str, dict[str, Any]], None],
) -> AttackSurfaceRiskReductionProposal:
    """Consume proposal-only authority without changing an external asset."""
    if (
        not isinstance(binding, AttackSurfaceReferenceBinding)
        or not isinstance(tickets, ActionTicketRegistry) or not callable(audit)
    ):
        raise AttackSurfaceObservationDenied("PROPOSAL_INPUT_INVALID")
    if (
        binding.risk not in {"HIGH", "CRITICAL"}
        or binding.trust != "UNTRUSTED_DATA" or binding.mode != "DRY_RUN"
        or binding.action != "CORRELATE_ONLY"
        or binding.authority_granted is not False
    ):
        raise AttackSurfaceObservationDenied("PROPOSAL_SOURCE_INVALID")
    if kill_switch_state != "ENGAGED":
        raise AttackSurfaceObservationDenied("KILL_SWITCH_NOT_ENGAGED")
    target_match = _PROPOSAL_REF.fullmatch(target_ref) if isinstance(target_ref, str) else None
    policy_match = _PROPOSAL_REF.fullmatch(policy_decision_ref) if isinstance(policy_decision_ref, str) else None
    if (
        target_match is None or target_match.group(1) != "exposure"
        or policy_match is None or policy_match.group(1) != "policy"
        or target_match.group(2) != binding.tenant_id
        or policy_match.group(2) != binding.tenant_id
        or target_ref != binding.exposure_ref
    ):
        raise AttackSurfaceObservationDenied("PROPOSAL_REF_INVALID")
    ticket_binding = {
        "tenant_id": binding.tenant_id, "subject_agent_id": subject_agent_id,
        "lease_id": lease_id, "capability": "asm.risk_reduction.propose",
        "resource": target_ref, "action_class": "ASM_RISK_REDUCTION_PROPOSAL",
        "policy_version": policy_version, "now": now,
    }
    try:
        tickets.validate(ticket_id, **ticket_binding)
    except ActionTicketError as exc:
        raise AttackSurfaceObservationDenied("ACTION_TICKET_DENIED") from exc
    try:
        audit("attack_surface_risk_reduction_proposed", {
            "event_id": binding.event_id, "tenant_id": binding.tenant_id,
            "target_ref": target_ref, "policy_decision_ref": policy_decision_ref,
            "action_ticket_ref": ticket_id, "risk": binding.risk,
            "action_class": "ASM_RISK_REDUCTION_PROPOSAL",
            "mode": "DRY_RUN", "deployment": "DISABLED",
            "kill_switch": "ENGAGED", "disposition": "PROPOSE_ONLY",
            "authority_granted": False, "response_executed": False,
        })
    except Exception as exc:
        raise AttackSurfaceObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    try:
        tickets.validate_and_consume(ticket_id, **ticket_binding)
    except ActionTicketError as exc:
        raise AttackSurfaceObservationDenied("ACTION_TICKET_DENIED") from exc
    return AttackSurfaceRiskReductionProposal(
        binding.event_id, binding.tenant_id, target_ref, policy_decision_ref,
        ticket_id, binding.risk,
    )


def run_attack_surface_dry_run_lifecycle(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    exploitability_state: str, forgotten_asset: bool, network_ref: str,
    vulnerability_refs: tuple[str, ...], catalog_ref: str, signature_ref: str,
    soc_incident_ref: str, evidence_refs: tuple[str, ...],
    tickets: ActionTicketRegistry, ticket_id: str, target_ref: str,
    policy_decision_ref: str, subject_agent_id: str, lease_id: str,
    policy_version: str, kill_switch_state: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> AttackSurfaceDryRunLifecycle:
    """Compose accepted FW-ASM stages without adding discovery or response."""
    observation = normalize_attack_surface_observation(
        fixture, tenant_id=tenant_id, now_epoch=now_epoch, audit=audit,
    )
    finding = classify_attack_surface_observation(
        observation, tenant_id=tenant_id,
        exploitability_state=exploitability_state,
        forgotten_asset=forgotten_asset, audit=audit,
    )
    binding = bind_attack_surface_references(
        finding, tenant_id=tenant_id, network_ref=network_ref,
        vulnerability_refs=vulnerability_refs, catalog_ref=catalog_ref,
        signature_ref=signature_ref, soc_incident_ref=soc_incident_ref,
        evidence_refs=evidence_refs, audit=audit,
    )
    proposal = propose_attack_surface_risk_reduction(
        binding, tickets=tickets, ticket_id=ticket_id, target_ref=target_ref,
        policy_decision_ref=policy_decision_ref,
        subject_agent_id=subject_agent_id, lease_id=lease_id,
        policy_version=policy_version, now=now_epoch,
        kill_switch_state=kill_switch_state, audit=audit,
    )
    return AttackSurfaceDryRunLifecycle(observation, finding, binding, proposal)
