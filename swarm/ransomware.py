"""Bounded ransomware activity evaluation over normalized fixture events.

The evaluator consumes caller-supplied in-memory observations only. It has no
filesystem, process, endpoint, network, credential, quarantine, remediation,
recovery, or deployment authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import Iterable

from .asoc import AuditSink
from .action_ticket import ActionTicketError, ActionTicketRegistry
from .endpoint_fixtures import EndpointObservation

MAX_RANSOM_EVENTS = 128
MAX_RANSOM_WINDOW_SECONDS = 300
MAX_CANARIES_PER_DEVICE = 64
MAX_CANARY_IDENTIFIER_BYTES = 256
_FILE_OPERATIONS = frozenset({"WRITE", "RENAME", "DELETE"})
_STRONG_INDICATORS = frozenset({"EXTENSION_CHANGE", "HIGH_ENTROPY", "RANSOM_NOTE", "SHADOW_COPY_TAMPER"})


class RansomwareEvaluationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _bounded_scope(value: object, reason: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value.encode("utf-8")) > MAX_CANARY_IDENTIFIER_BYTES:
        raise RansomwareEvaluationDenied(reason)
    return value


def _canary_ref(identifier: str) -> str:
    return sha256(identifier.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RansomwareFinding:
    tenant_id: str
    device_id: str
    event_ids: tuple[str, ...]
    signals: tuple[str, ...]
    confidence: str
    recommendations: tuple[str, ...]
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


@dataclass(frozen=True)
class RansomwareIsolationProposal:
    tenant_id: str
    device_id: str
    event_ids: tuple[str, ...]
    ticket_id: str
    confidence: str = "HIGH"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


class RansomwareCanaryRegistry:
    """Bounded in-memory canary identifiers partitioned by tenant and device."""

    def __init__(self, audit: AuditSink) -> None:
        if not callable(audit):
            raise RansomwareEvaluationDenied("CANARY_REGISTRY_INVALID")
        self._audit = audit
        self._lock = RLock()
        self._canaries: dict[tuple[str, str], frozenset[str]] = {}

    def register(self, identifiers: tuple[str, ...], *, tenant_id: str, device_id: str) -> tuple[str, ...]:
        if not isinstance(identifiers, tuple) or not 1 <= len(identifiers) <= MAX_CANARIES_PER_DEVICE:
            raise RansomwareEvaluationDenied("CANARY_SET_INVALID")
        _bounded_scope(tenant_id, "CANARY_SCOPE_INVALID")
        _bounded_scope(device_id, "CANARY_SCOPE_INVALID")
        if any(not isinstance(item, str) or not item.strip() or item != item.strip() or len(item.encode("utf-8")) > MAX_CANARY_IDENTIFIER_BYTES for item in identifiers):
            raise RansomwareEvaluationDenied("CANARY_IDENTIFIER_INVALID")
        if len(set(identifiers)) != len(identifiers):
            raise RansomwareEvaluationDenied("CANARY_DUPLICATE")
        ordered = tuple(sorted(identifiers))
        key = (tenant_id, device_id)
        with self._lock:
            if key in self._canaries:
                raise RansomwareEvaluationDenied("CANARY_SCOPE_ALREADY_REGISTERED")
            try:
                self._audit("ransomware_canaries_registered", {
                    "tenant_id": tenant_id, "device_id": device_id,
                    "identifier_refs": [_canary_ref(item) for item in ordered], "count": len(ordered),
                    "mode": "DRY_RUN", "action": "DETECT_ONLY", "deployment": "DISABLED",
                })
            except Exception as exc:
                raise RansomwareEvaluationDenied("EVIDENCE_WRITE_FAILED") from exc
            self._canaries[key] = frozenset(ordered)
            return ordered

    def evaluate_touch(
        self, observation: EndpointObservation, *, tenant_id: str, device_id: str,
    ) -> RansomwareFinding | None:
        if not isinstance(observation, EndpointObservation):
            raise RansomwareEvaluationDenied("EVENT_INVALID")
        _bounded_scope(tenant_id, "CANARY_SCOPE_INVALID")
        _bounded_scope(device_id, "CANARY_SCOPE_INVALID")
        if (observation.tenant_id, observation.device_id) != (tenant_id, device_id):
            raise RansomwareEvaluationDenied("TENANT_OR_DEVICE_MISMATCH")
        if observation.mode != "DRY_RUN" or observation.action != "DETECT_ONLY":
            raise RansomwareEvaluationDenied("EVENT_AUTHORITY_INVALID")
        path = dict(observation.metadata).get("path") if observation.event_type == "FILE_LIFECYCLE" else None
        with self._lock:
            matched = path is not None and path in self._canaries.get((tenant_id, device_id), frozenset())
            if not matched:
                return None
            try:
                self._audit("ransomware_canary_touched", {
                    "tenant_id": tenant_id, "device_id": device_id,
                    "event_id": observation.event_id, "canary_ref": _canary_ref(path),
                    "recommendations": ["WARN"], "mode": "DRY_RUN",
                    "action": "DETECT_ONLY", "deployment": "DISABLED",
                })
            except Exception as exc:
                raise RansomwareEvaluationDenied("EVIDENCE_WRITE_FAILED") from exc
            return RansomwareFinding(
                tenant_id, device_id, (observation.event_id,), ("CANARY_TOUCHED",),
                "HIGH", ("WARN",),
            )


def evaluate_ransomware_activity(
    observations: Iterable[EndpointObservation], *, tenant_id: str,
    device_id: str, audit: AuditSink,
) -> RansomwareFinding | None:
    """Evaluate one bounded tenant/device window and Evidence-log the result."""
    if not isinstance(observations, (list, tuple)) or not callable(audit):
        raise RansomwareEvaluationDenied("INPUT_INVALID")
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise RansomwareEvaluationDenied("TENANT_INVALID")
    if not isinstance(device_id, str) or not device_id.strip():
        raise RansomwareEvaluationDenied("DEVICE_INVALID")
    if not 1 <= len(observations) <= MAX_RANSOM_EVENTS:
        raise RansomwareEvaluationDenied("EVENT_COUNT_INVALID")
    if any(not isinstance(item, EndpointObservation) for item in observations):
        raise RansomwareEvaluationDenied("EVENT_INVALID")
    if any((item.tenant_id, item.device_id) != (tenant_id, device_id) for item in observations):
        raise RansomwareEvaluationDenied("TENANT_OR_DEVICE_MISMATCH")
    if any(item.mode != "DRY_RUN" or item.action != "DETECT_ONLY" for item in observations):
        raise RansomwareEvaluationDenied("EVENT_AUTHORITY_INVALID")

    ordered = tuple(sorted(observations, key=lambda item: (item.observed_at_epoch, item.event_id)))
    event_ids = tuple(item.event_id for item in ordered)
    if len(set(event_ids)) != len(event_ids):
        raise RansomwareEvaluationDenied("EVENT_ID_DUPLICATE")
    if ordered[-1].observed_at_epoch - ordered[0].observed_at_epoch > MAX_RANSOM_WINDOW_SECONDS:
        raise RansomwareEvaluationDenied("EVENT_WINDOW_EXCEEDED")

    file_operations: list[str] = []
    strong: set[str] = set()
    for item in ordered:
        if item.event_type == "FILE_LIFECYCLE":
            operation = dict(item.metadata).get("operation", "")
            if operation in _FILE_OPERATIONS:
                file_operations.append(operation)
        strong.update(indicator for indicator in item.related_indicators if indicator in _STRONG_INDICATORS)

    signals = set(strong)
    if len(file_operations) >= 4 and len(set(file_operations)) >= 2:
        signals.add("MASS_FILE_CHANGE")
    confidence: str | None = None
    if "MASS_FILE_CHANGE" in signals and len(strong) >= 2:
        confidence = "HIGH"
    elif ("MASS_FILE_CHANGE" in signals and strong) or len(strong) >= 2:
        confidence = "MEDIUM"
    elif signals:
        confidence = "LOW"

    recommendations = ("WARN", "PROPOSE_ISOLATION") if confidence == "HIGH" else (("WARN",) if confidence else ())
    payload = {
        "tenant_id": tenant_id, "device_id": device_id, "event_ids": list(event_ids),
        "signals": sorted(signals), "confidence": confidence or "NONE",
        "recommendations": list(recommendations), "mode": "DRY_RUN",
        "action": "DETECT_ONLY", "deployment": "DISABLED",
    }
    try:
        audit("ransomware_activity_evaluated", payload)
    except Exception as exc:
        raise RansomwareEvaluationDenied("EVIDENCE_WRITE_FAILED") from exc
    if confidence is None:
        return None
    return RansomwareFinding(tenant_id, device_id, event_ids, tuple(sorted(signals)), confidence, recommendations)


def propose_ransomware_isolation(
    finding: RansomwareFinding, *, tickets: ActionTicketRegistry, ticket_id: str,
    subject_agent_id: str, lease_id: str, policy_version: str, now: int,
    kill_switch_state: str, audit: AuditSink,
) -> RansomwareIsolationProposal:
    """Record and consume authority for a proposal without isolating anything."""
    if not isinstance(finding, RansomwareFinding) or not isinstance(tickets, ActionTicketRegistry) or not callable(audit):
        raise RansomwareEvaluationDenied("PROPOSAL_INPUT_INVALID")
    if finding.confidence != "HIGH" or "PROPOSE_ISOLATION" not in finding.recommendations:
        raise RansomwareEvaluationDenied("CONFIDENCE_INSUFFICIENT")
    if finding.mode != "DRY_RUN" or finding.action != "DETECT_ONLY":
        raise RansomwareEvaluationDenied("FINDING_AUTHORITY_INVALID")
    if kill_switch_state != "ENGAGED":
        raise RansomwareEvaluationDenied("KILL_SWITCH_NOT_ENGAGED")
    resource = finding.device_id
    binding = {
        "tenant_id": finding.tenant_id, "subject_agent_id": subject_agent_id,
        "lease_id": lease_id, "capability": "endpoint.isolate.propose",
        "resource": resource, "action_class": "ISOLATION_PROPOSAL",
        "policy_version": policy_version, "now": now,
    }
    try:
        tickets.validate(ticket_id, **binding)
    except ActionTicketError as exc:
        raise RansomwareEvaluationDenied("ACTION_TICKET_DENIED") from exc
    try:
        audit("ransomware_isolation_proposed", {
            "tenant_id": finding.tenant_id, "device_id": finding.device_id,
            "event_ids": list(finding.event_ids), "ticket_id": ticket_id,
            "confidence": "HIGH", "mode": "DRY_RUN", "action": "DETECT_ONLY",
            "deployment": "DISABLED", "containment_executed": False,
        })
    except Exception as exc:
        raise RansomwareEvaluationDenied("EVIDENCE_WRITE_FAILED") from exc
    try:
        tickets.validate_and_consume(ticket_id, **binding)
    except ActionTicketError as exc:
        raise RansomwareEvaluationDenied("ACTION_TICKET_DENIED") from exc
    return RansomwareIsolationProposal(
        finding.tenant_id, finding.device_id, finding.event_ids, ticket_id,
    )
