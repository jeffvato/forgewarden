"""Bounded FW-SOC incident projections over canonical reference identifiers.

This module stores no events, Evidence, cases, or response state. It performs
no filesystem, process, credential, network, deployment, or response action.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


MAX_INCIDENT_REFS = 64
MAX_INCIDENT_TEXT_BYTES = 512
_KEYS = frozenset({
    "incident_id", "tenant_id", "title", "severity", "status",
    "created_at_epoch", "updated_at_epoch", "affected_refs",
    "normalized_event_refs", "evidence_refs", "disposition",
})
_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
_STATUSES = frozenset({"OPEN", "TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED"})
_ACTIVE = frozenset({"OPEN", "TRIAGED", "INVESTIGATING"})
_DISPOSITIONS = frozenset({"NONE", "TRUE_POSITIVE", "FALSE_POSITIVE", "MITIGATED", "ACCEPTED_RISK"})


class SOCIncidentDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value.encode("utf-8")) > MAX_INCIDENT_TEXT_BYTES:
        raise SOCIncidentDenied(f"{field}_INVALID")
    return value


def _refs(value: Any, field: str) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)) or not 1 <= len(value) <= MAX_INCIDENT_REFS:
        raise SOCIncidentDenied(f"{field}_INVALID")
    refs = tuple(_text(item, field) for item in value)
    if len(set(refs)) != len(refs):
        raise SOCIncidentDenied(f"{field}_DUPLICATE")
    return refs


@dataclass(frozen=True)
class SOCIncidentProjection:
    incident_id: str
    tenant_id: str
    title: str
    severity: str
    status: str
    created_at_epoch: int
    updated_at_epoch: int
    affected_refs: tuple[str, ...]
    normalized_event_refs: tuple[str, ...]
    evidence_refs: tuple[str, ...]
    disposition: str
    trust: str = "UNTRUSTED_CASE_FACT"
    mode: str = "DRY_RUN"
    action: str = "RECORD_ONLY"


def project_soc_incident(
    record: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> SOCIncidentProjection:
    """Validate reference-only case facts and emit Evidence before return."""
    if not isinstance(record, Mapping) or set(record) != _KEYS or not callable(audit):
        raise SOCIncidentDenied("INCIDENT_SCHEMA_INVALID")
    expected_tenant = _text(tenant_id, "TENANT")
    if record.get("tenant_id") != expected_tenant:
        raise SOCIncidentDenied("TENANT_MISMATCH")
    if not isinstance(now_epoch, int) or isinstance(now_epoch, bool) or now_epoch < 0:
        raise SOCIncidentDenied("TIME_INVALID")
    created, updated = record.get("created_at_epoch"), record.get("updated_at_epoch")
    if any(not isinstance(value, int) or isinstance(value, bool) for value in (created, updated)) or not 0 <= created <= updated <= now_epoch:
        raise SOCIncidentDenied("TIME_INVALID")
    severity, status, disposition = record.get("severity"), record.get("status"), record.get("disposition")
    if severity not in _SEVERITIES or status not in _STATUSES or disposition not in _DISPOSITIONS:
        raise SOCIncidentDenied("INCIDENT_STATE_INVALID")
    if (status in _ACTIVE) != (disposition == "NONE"):
        raise SOCIncidentDenied("INCIDENT_DISPOSITION_INVALID")
    incident_id = _text(record.get("incident_id"), "INCIDENT_ID")
    title = _text(record.get("title"), "TITLE")
    affected = _refs(record.get("affected_refs"), "AFFECTED_REFS")
    events = _refs(record.get("normalized_event_refs"), "NORMALIZED_EVENT_REFS")
    evidence = _refs(record.get("evidence_refs"), "EVIDENCE_REFS")
    try:
        audit("soc_incident_projected", {
            "incident_id": incident_id, "tenant_id": expected_tenant,
            "severity": severity, "status": status,
            "created_at_epoch": created, "updated_at_epoch": updated,
            "affected_refs": list(affected),
            "normalized_event_refs": list(events),
            "evidence_refs": list(evidence), "disposition": disposition,
            "trust": "UNTRUSTED_CASE_FACT", "mode": "DRY_RUN",
            "action": "RECORD_ONLY", "response_executed": False,
            "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SOCIncidentDenied("EVIDENCE_WRITE_FAILED") from exc
    return SOCIncidentProjection(
        incident_id, expected_tenant, title, severity, status, created, updated,
        affected, events, evidence, disposition,
    )
