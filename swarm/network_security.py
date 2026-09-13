"""Bounded caller-supplied FW-NET metadata contracts.

This module opens no sockets, captures no packets, queries no service, and
executes no network or response action.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping

from .action_ticket import ActionTicketError, ActionTicketRegistry


MAX_NETWORK_FIXTURE_BYTES = 32 * 1024
MAX_NETWORK_INDICATORS = 16
MAX_NETWORK_EVIDENCE_REFS = 16
_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_OWNER_REF = re.compile(
    r"^fw-(asset|network|evid)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_CORRELATION_REF = re.compile(
    r"^fw-(endpoint|finding|incident|evid)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_IDENTITY_REF = re.compile(r"^fw-id/([a-z][a-z0-9_.-]{0,127})\.([a-z][a-z0-9_.-]{0,126})$")
_PROPOSAL_REF = re.compile(
    r"^fw-(network|policy)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_PROTOCOLS = frozenset({
    "DHCP", "DNS", "HTTP", "HTTPS", "KERBEROS", "LDAP", "RDP", "SMB",
    "SSH", "TCP", "TLS", "UDP", "VPN", "WIFI",
})
_DIRECTIONS = frozenset({"EAST_WEST", "INBOUND", "OUTBOUND"})
_INDICATORS = frozenset({
    "C2_PATTERN", "CREDENTIAL_ABUSE", "DNS_ANOMALY", "EXFILTRATION_PATTERN",
    "LATERAL_MOVEMENT", "NETWORK_PROBE", "SMB_WRITE", "UNAUTHORIZED_EGRESS",
})
_REQUIRED = frozenset({
    "event_id", "tenant_id", "device_ref", "observed_at_epoch", "source_ref",
    "destination_ref", "protocol", "port", "direction", "indicators",
    "evidence_ref",
})


class NetworkObservationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _TEXT.fullmatch(value):
        raise NetworkObservationDenied(f"{field}_INVALID")
    return value


def _owner_ref(value: Any, kind: str, tenant_id: str, field: str) -> str:
    match = _OWNER_REF.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) != kind or match.group(2) != tenant_id:
        raise NetworkObservationDenied(f"{field}_INVALID")
    return value


@dataclass(frozen=True)
class NetworkObservation:
    event_id: str
    tenant_id: str
    device_ref: str
    observed_at_epoch: int
    source_ref: str
    destination_ref: str
    protocol: str
    port: int
    direction: str
    indicators: tuple[str, ...]
    evidence_ref: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class NetworkThreatFinding:
    event_id: str
    tenant_id: str
    device_ref: str
    protocol: str
    direction: str
    indicators: tuple[str, ...]
    risk: str
    recommendations: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class NetworkReferenceBinding:
    event_id: str
    tenant_id: str
    device_ref: str
    risk: str
    indicators: tuple[str, ...]
    endpoint_event_ref: str
    aid_finding_ref: str
    soc_incident_ref: str
    identity_ref: str
    evidence_refs: tuple[str, ...]
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "CORRELATE_ONLY"
    authority_granted: bool = False


@dataclass(frozen=True)
class NetworkContainmentProposal:
    event_id: str
    tenant_id: str
    target_ref: str
    policy_decision_ref: str
    action_ticket_ref: str
    risk: str
    action_class: str = "NETWORK_CONTAINMENT_PROPOSAL"
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    kill_switch: str = "ENGAGED"
    disposition: str = "PROPOSE_ONLY"
    authority_granted: bool = False
    response_executed: bool = False


@dataclass(frozen=True)
class NetworkDryRunLifecycle:
    observation: NetworkObservation
    finding: NetworkThreatFinding
    binding: NetworkReferenceBinding
    proposal: NetworkContainmentProposal
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    kill_switch: str = "ENGAGED"
    authority_granted: bool = False
    response_executed: bool = False


def normalize_network_observation(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> NetworkObservation:
    """Validate one exact metadata fixture and write minimized Evidence first."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise NetworkObservationDenied("FIXTURE_INVALID")
    try:
        encoded = json.dumps(
            fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise NetworkObservationDenied("FIXTURE_INVALID") from exc
    if len(encoded) > MAX_NETWORK_FIXTURE_BYTES or set(fixture) != _REQUIRED:
        raise NetworkObservationDenied("FIXTURE_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise NetworkObservationDenied("TENANT_INVALID")
    if fixture.get("tenant_id") != tenant_id:
        raise NetworkObservationDenied("TENANT_MISMATCH")
    observed = fixture.get("observed_at_epoch")
    if (
        not isinstance(observed, int) or isinstance(observed, bool)
        or not isinstance(now_epoch, int) or isinstance(now_epoch, bool)
        or observed < 0 or observed > now_epoch
    ):
        raise NetworkObservationDenied("OBSERVED_AT_INVALID")
    protocol = fixture.get("protocol")
    direction = fixture.get("direction")
    port = fixture.get("port")
    if protocol not in _PROTOCOLS:
        raise NetworkObservationDenied("PROTOCOL_INVALID")
    if direction not in _DIRECTIONS:
        raise NetworkObservationDenied("DIRECTION_INVALID")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise NetworkObservationDenied("PORT_INVALID")
    raw_indicators = fixture.get("indicators")
    if (
        not isinstance(raw_indicators, (list, tuple))
        or len(raw_indicators) > MAX_NETWORK_INDICATORS
    ):
        raise NetworkObservationDenied("INDICATORS_INVALID")
    indicators = tuple(raw_indicators)
    if tuple(sorted(set(indicators))) != indicators or not set(indicators) <= _INDICATORS:
        raise NetworkObservationDenied("INDICATORS_INVALID")
    event_id = _text(fixture.get("event_id"), "EVENT_ID")
    device_ref = _owner_ref(fixture.get("device_ref"), "asset", tenant_id, "DEVICE_REF")
    source_ref = _owner_ref(fixture.get("source_ref"), "network", tenant_id, "SOURCE_REF")
    destination_ref = _owner_ref(
        fixture.get("destination_ref"), "network", tenant_id, "DESTINATION_REF",
    )
    evidence_ref = _owner_ref(fixture.get("evidence_ref"), "evid", tenant_id, "EVIDENCE_REF")
    try:
        audit("network_observation_normalized", {
            "event_id": event_id,
            "tenant_id": tenant_id,
            "device_ref": device_ref,
            "observed_at_epoch": observed,
            "protocol": protocol,
            "port": port,
            "direction": direction,
            "indicator_count": len(indicators),
            "evidence_ref": evidence_ref,
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "deployment": "DISABLED",
            "response_executed": False,
            "authority_granted": False,
        })
    except Exception as exc:
        raise NetworkObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return NetworkObservation(
        event_id, tenant_id, device_ref, observed, source_ref, destination_ref,
        protocol, port, direction, indicators, evidence_ref,
    )


def classify_network_observation(
    observation: NetworkObservation, *, tenant_id: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> NetworkThreatFinding:
    """Classify only exact admitted facts without consulting a model."""
    if not isinstance(observation, NetworkObservation) or not callable(audit):
        raise NetworkObservationDenied("OBSERVATION_INVALID")
    if observation.tenant_id != tenant_id:
        raise NetworkObservationDenied("TENANT_MISMATCH")
    if (
        observation.trust != "UNTRUSTED_DATA" or observation.mode != "DRY_RUN"
        or observation.action != "DETECT_ONLY"
        or observation.authority_granted is not False
    ):
        raise NetworkObservationDenied("OBSERVATION_AUTHORITY_INVALID")
    indicators = observation.indicators
    if not indicators or tuple(sorted(set(indicators))) != indicators or not set(indicators) <= _INDICATORS:
        raise NetworkObservationDenied("INDICATORS_INVALID")
    if set(indicators) & {"C2_PATTERN", "EXFILTRATION_PATTERN", "UNAUTHORIZED_EGRESS"} and observation.direction != "OUTBOUND":
        raise NetworkObservationDenied("INDICATOR_CONTEXT_INVALID")
    if "LATERAL_MOVEMENT" in indicators and observation.direction != "EAST_WEST":
        raise NetworkObservationDenied("INDICATOR_CONTEXT_INVALID")
    if "SMB_WRITE" in indicators and observation.protocol != "SMB":
        raise NetworkObservationDenied("INDICATOR_CONTEXT_INVALID")
    if "DNS_ANOMALY" in indicators and observation.protocol != "DNS":
        raise NetworkObservationDenied("INDICATOR_CONTEXT_INVALID")
    if set(indicators) & {"C2_PATTERN", "EXFILTRATION_PATTERN"}:
        risk = "CRITICAL"
    elif set(indicators) & {"CREDENTIAL_ABUSE", "LATERAL_MOVEMENT", "UNAUTHORIZED_EGRESS"}:
        risk = "HIGH"
    elif set(indicators) & {"DNS_ANOMALY", "NETWORK_PROBE", "SMB_WRITE"}:
        risk = "MEDIUM"
    else:  # closed indicator set makes this defensive rather than reachable
        risk = "LOW"
    recommendations = ("WARN", "PROPOSE_BLOCK") if risk in {"HIGH", "CRITICAL"} else ("WARN",)
    try:
        audit("network_threat_classified", {
            "event_id": observation.event_id,
            "tenant_id": tenant_id,
            "device_ref": observation.device_ref,
            "protocol": observation.protocol,
            "direction": observation.direction,
            "risk": risk,
            "indicators": indicators,
            "evidence_ref": observation.evidence_ref,
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "DETECT_ONLY",
            "deployment": "DISABLED",
            "response_executed": False,
            "authority_granted": False,
        })
    except Exception as exc:
        raise NetworkObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return NetworkThreatFinding(
        observation.event_id, tenant_id, observation.device_ref,
        observation.protocol, observation.direction, indicators, risk,
        recommendations,
    )


def bind_network_references(
    finding: NetworkThreatFinding, *, tenant_id: str, endpoint_event_ref: str,
    aid_finding_ref: str, soc_incident_ref: str, identity_ref: str,
    evidence_refs: tuple[str, ...],
    audit: Callable[[str, dict[str, Any]], None],
) -> NetworkReferenceBinding:
    """Bind canonical owner references without creating owner state."""
    if not isinstance(finding, NetworkThreatFinding) or not callable(audit):
        raise NetworkObservationDenied("FINDING_INVALID")
    if finding.tenant_id != tenant_id:
        raise NetworkObservationDenied("TENANT_MISMATCH")
    expected_recommendations = (
        ("WARN", "PROPOSE_BLOCK")
        if finding.risk in {"HIGH", "CRITICAL"} else ("WARN",)
    )
    if (
        finding.risk not in {"MEDIUM", "HIGH", "CRITICAL"}
        or finding.recommendations != expected_recommendations
        or finding.trust != "UNTRUSTED_DATA" or finding.mode != "DRY_RUN"
        or finding.action != "DETECT_ONLY"
        or finding.authority_granted is not False
        or not finding.indicators
        or tuple(sorted(set(finding.indicators))) != finding.indicators
        or not set(finding.indicators) <= _INDICATORS
    ):
        raise NetworkObservationDenied("FINDING_INVALID")
    device_ref = _owner_ref(finding.device_ref, "asset", tenant_id, "DEVICE_REF")
    for value, kind in (
        (endpoint_event_ref, "endpoint"),
        (aid_finding_ref, "finding"),
        (soc_incident_ref, "incident"),
    ):
        match = _CORRELATION_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != kind or match.group(2) != tenant_id:
            raise NetworkObservationDenied("CORRELATION_REF_INVALID")
    if endpoint_event_ref != f"fw-endpoint/{tenant_id}/{finding.event_id}":
        raise NetworkObservationDenied("SOURCE_BINDING_INVALID")
    identity_match = _IDENTITY_REF.fullmatch(identity_ref) if isinstance(identity_ref, str) else None
    if identity_match is None or identity_match.group(1) != tenant_id:
        raise NetworkObservationDenied("IDENTITY_REF_INVALID")
    if (
        not isinstance(evidence_refs, tuple)
        or not 1 <= len(evidence_refs) <= MAX_NETWORK_EVIDENCE_REFS
        or tuple(sorted(set(evidence_refs))) != evidence_refs
    ):
        raise NetworkObservationDenied("EVIDENCE_REFS_INVALID")
    for value in evidence_refs:
        match = _CORRELATION_REF.fullmatch(value) if isinstance(value, str) else None
        if match is None or match.group(1) != "evid" or match.group(2) != tenant_id:
            raise NetworkObservationDenied("EVIDENCE_REFS_INVALID")
    result = NetworkReferenceBinding(
        finding.event_id, tenant_id, device_ref, finding.risk,
        finding.indicators, endpoint_event_ref, aid_finding_ref,
        soc_incident_ref, identity_ref, evidence_refs,
    )
    try:
        audit("network_references_bound", {
            "event_id": result.event_id,
            "tenant_id": tenant_id,
            "device_ref": device_ref,
            "risk": result.risk,
            "indicators": result.indicators,
            "endpoint_event_ref": endpoint_event_ref,
            "aid_finding_ref": aid_finding_ref,
            "soc_incident_ref": soc_incident_ref,
            "identity_ref": identity_ref,
            "evidence_refs": evidence_refs,
            "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN",
            "action": "CORRELATE_ONLY",
            "deployment": "DISABLED",
            "response_executed": False,
            "authority_granted": False,
        })
    except Exception as exc:
        raise NetworkObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return result


def propose_network_containment(
    binding: NetworkReferenceBinding, *, tickets: ActionTicketRegistry,
    ticket_id: str, target_ref: str, policy_decision_ref: str,
    subject_agent_id: str, lease_id: str, policy_version: str, now: int,
    kill_switch_state: str, audit: Callable[[str, dict[str, Any]], None],
) -> NetworkContainmentProposal:
    """Consume proposal-only authority without changing a network resource."""
    if (
        not isinstance(binding, NetworkReferenceBinding)
        or not isinstance(tickets, ActionTicketRegistry)
        or not callable(audit)
    ):
        raise NetworkObservationDenied("PROPOSAL_INPUT_INVALID")
    if (
        binding.risk not in {"HIGH", "CRITICAL"}
        or binding.trust != "UNTRUSTED_DATA" or binding.mode != "DRY_RUN"
        or binding.action != "CORRELATE_ONLY"
        or binding.authority_granted is not False
    ):
        raise NetworkObservationDenied("PROPOSAL_SOURCE_INVALID")
    if kill_switch_state != "ENGAGED":
        raise NetworkObservationDenied("KILL_SWITCH_NOT_ENGAGED")
    target_match = _PROPOSAL_REF.fullmatch(target_ref) if isinstance(target_ref, str) else None
    policy_match = _PROPOSAL_REF.fullmatch(policy_decision_ref) if isinstance(policy_decision_ref, str) else None
    if (
        target_match is None or target_match.group(1) != "network"
        or policy_match is None or policy_match.group(1) != "policy"
        or target_match.group(2) != binding.tenant_id
        or policy_match.group(2) != binding.tenant_id
    ):
        raise NetworkObservationDenied("PROPOSAL_REF_INVALID")
    ticket_binding = {
        "tenant_id": binding.tenant_id,
        "subject_agent_id": subject_agent_id,
        "lease_id": lease_id,
        "capability": "network.containment.propose",
        "resource": target_ref,
        "action_class": "NETWORK_CONTAINMENT_PROPOSAL",
        "policy_version": policy_version,
        "now": now,
    }
    try:
        tickets.validate(ticket_id, **ticket_binding)
    except ActionTicketError as exc:
        raise NetworkObservationDenied("ACTION_TICKET_DENIED") from exc
    try:
        audit("network_containment_proposed", {
            "event_id": binding.event_id,
            "tenant_id": binding.tenant_id,
            "target_ref": target_ref,
            "policy_decision_ref": policy_decision_ref,
            "action_ticket_ref": ticket_id,
            "risk": binding.risk,
            "action_class": "NETWORK_CONTAINMENT_PROPOSAL",
            "mode": "DRY_RUN",
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "disposition": "PROPOSE_ONLY",
            "authority_granted": False,
            "response_executed": False,
        })
    except Exception as exc:
        raise NetworkObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    try:
        tickets.validate_and_consume(ticket_id, **ticket_binding)
    except ActionTicketError as exc:
        raise NetworkObservationDenied("ACTION_TICKET_DENIED") from exc
    return NetworkContainmentProposal(
        binding.event_id, binding.tenant_id, target_ref,
        policy_decision_ref, ticket_id, binding.risk,
    )


def run_network_dry_run_lifecycle(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    endpoint_event_ref: str, aid_finding_ref: str, soc_incident_ref: str,
    identity_ref: str, evidence_refs: tuple[str, ...],
    tickets: ActionTicketRegistry, ticket_id: str, target_ref: str,
    policy_decision_ref: str, subject_agent_id: str, lease_id: str,
    policy_version: str, kill_switch_state: str,
    audit: Callable[[str, dict[str, Any]], None],
) -> NetworkDryRunLifecycle:
    """Compose accepted FW-NET stages without adding execution authority."""
    observation = normalize_network_observation(
        fixture, tenant_id=tenant_id, now_epoch=now_epoch, audit=audit,
    )
    finding = classify_network_observation(
        observation, tenant_id=tenant_id, audit=audit,
    )
    binding = bind_network_references(
        finding, tenant_id=tenant_id, endpoint_event_ref=endpoint_event_ref,
        aid_finding_ref=aid_finding_ref, soc_incident_ref=soc_incident_ref,
        identity_ref=identity_ref, evidence_refs=evidence_refs, audit=audit,
    )
    proposal = propose_network_containment(
        binding, tickets=tickets, ticket_id=ticket_id, target_ref=target_ref,
        policy_decision_ref=policy_decision_ref,
        subject_agent_id=subject_agent_id, lease_id=lease_id,
        policy_version=policy_version, now=now_epoch,
        kill_switch_state=kill_switch_state, audit=audit,
    )
    return NetworkDryRunLifecycle(observation, finding, binding, proposal)
