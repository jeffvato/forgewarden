"""Bounded FW-SOC incident projections over canonical reference identifiers.

This module stores no events, Evidence, cases, or response state. It performs
no filesystem, process, credential, network, deployment, or response action.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Mapping


MAX_INCIDENT_REFS = 64
MAX_STORY_INCIDENTS = 32
MAX_TIMELINE_ENTRIES = 128
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
_TIMELINE_TYPES = frozenset({"DETECTION", "REVIEW", "APPROVAL", "RECOVERY", "DISPOSITION"})
_TIMELINE_KEYS = frozenset({"entry_id", "tenant_id", "incident_id", "occurred_at_epoch", "entry_type", "actor_ref", "source_ref", "evidence_ref"})


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


@dataclass(frozen=True)
class SOCAttackStoryProjection:
    story_id: str
    tenant_id: str
    incident_ids: tuple[str, ...]
    shared_affected_refs: tuple[str, ...]
    shared_normalized_event_refs: tuple[str, ...]
    severity: str
    first_seen_epoch: int
    last_seen_epoch: int
    trust: str = "UNTRUSTED_CASE_FACT"
    mode: str = "DRY_RUN"
    action: str = "CORRELATE_ONLY"


@dataclass(frozen=True)
class SOCTimelineEntry:
    entry_id: str
    tenant_id: str
    incident_id: str
    occurred_at_epoch: int
    entry_type: str
    actor_ref: str
    source_ref: str
    evidence_ref: str


@dataclass(frozen=True)
class SOCIncidentTimeline:
    tenant_id: str
    incident_id: str
    entries: tuple[SOCTimelineEntry, ...]
    trust: str = "UNTRUSTED_CASE_FACT"
    mode: str = "DRY_RUN"
    action: str = "PROJECT_ONLY"


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


def _validate_projection(value: Any, tenant_id: str) -> SOCIncidentProjection:
    if not isinstance(value, SOCIncidentProjection) or value.tenant_id != tenant_id:
        raise SOCIncidentDenied("STORY_TENANT_MISMATCH")
    if value.trust != "UNTRUSTED_CASE_FACT" or value.mode != "DRY_RUN" or value.action != "RECORD_ONLY":
        raise SOCIncidentDenied("STORY_AUTHORITY_INVALID")
    if value.severity not in _SEVERITIES or value.status not in _STATUSES or value.disposition not in _DISPOSITIONS:
        raise SOCIncidentDenied("STORY_INCIDENT_INVALID")
    if (value.status in _ACTIVE) != (value.disposition == "NONE"):
        raise SOCIncidentDenied("STORY_INCIDENT_INVALID")
    if any(not isinstance(item, int) or isinstance(item, bool) for item in (value.created_at_epoch, value.updated_at_epoch)) or not 0 <= value.created_at_epoch <= value.updated_at_epoch:
        raise SOCIncidentDenied("STORY_INCIDENT_INVALID")
    _text(value.incident_id, "INCIDENT_ID")
    _text(value.title, "TITLE")
    for refs, field in ((value.affected_refs, "AFFECTED_REFS"), (value.normalized_event_refs, "NORMALIZED_EVENT_REFS"), (value.evidence_refs, "EVIDENCE_REFS")):
        _refs(refs, field)
    return value


def project_attack_story(
    incidents: tuple[SOCIncidentProjection, ...], *, story_id: str,
    tenant_id: str, audit: Callable[[str, dict[str, Any]], None],
) -> SOCAttackStoryProjection:
    """Correlate exact shared references without copying event or Evidence data."""
    if not isinstance(incidents, tuple) or not 2 <= len(incidents) <= MAX_STORY_INCIDENTS or not callable(audit):
        raise SOCIncidentDenied("STORY_INPUT_INVALID")
    expected_tenant = _text(tenant_id, "TENANT")
    exact_story_id = _text(story_id, "STORY_ID")
    checked = tuple(_validate_projection(item, expected_tenant) for item in incidents)
    incident_ids = tuple(sorted(item.incident_id for item in checked))
    if len(set(incident_ids)) != len(incident_ids):
        raise SOCIncidentDenied("STORY_INCIDENT_DUPLICATE")

    affected_counts: dict[str, int] = {}
    event_counts: dict[str, int] = {}
    for item in checked:
        for ref in item.affected_refs:
            affected_counts[ref] = affected_counts.get(ref, 0) + 1
        for ref in item.normalized_event_refs:
            event_counts[ref] = event_counts.get(ref, 0) + 1
    shared_affected = tuple(sorted(ref for ref, count in affected_counts.items() if count >= 2))
    shared_events = tuple(sorted(ref for ref, count in event_counts.items() if count >= 2))
    if not shared_affected and not shared_events:
        raise SOCIncidentDenied("STORY_NOT_CORRELATED")
    if len(shared_affected) > MAX_INCIDENT_REFS or len(shared_events) > MAX_INCIDENT_REFS:
        raise SOCIncidentDenied("STORY_REFERENCES_EXCESSIVE")
    severity = max((item.severity for item in checked), key=("LOW", "MEDIUM", "HIGH", "CRITICAL").index)
    first_seen = min(item.created_at_epoch for item in checked)
    last_seen = max(item.updated_at_epoch for item in checked)
    try:
        audit("soc_attack_story_projected", {
            "story_id": exact_story_id, "tenant_id": expected_tenant,
            "incident_ids": list(incident_ids),
            "shared_affected_refs": list(shared_affected),
            "shared_normalized_event_refs": list(shared_events),
            "severity": severity, "first_seen_epoch": first_seen,
            "last_seen_epoch": last_seen, "trust": "UNTRUSTED_CASE_FACT",
            "mode": "DRY_RUN", "action": "CORRELATE_ONLY",
            "response_executed": False, "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SOCIncidentDenied("EVIDENCE_WRITE_FAILED") from exc
    return SOCAttackStoryProjection(
        exact_story_id, expected_tenant, incident_ids, shared_affected,
        shared_events, severity, first_seen, last_seen,
    )


def project_incident_timeline(
    incident: SOCIncidentProjection, entries: tuple[Mapping[str, Any], ...], *,
    tenant_id: str, audit: Callable[[str, dict[str, Any]], None],
) -> SOCIncidentTimeline:
    """Project ordered reference-only case history without executing recovery."""
    if not isinstance(entries, tuple) or not 1 <= len(entries) <= MAX_TIMELINE_ENTRIES or not callable(audit):
        raise SOCIncidentDenied("TIMELINE_INPUT_INVALID")
    expected_tenant = _text(tenant_id, "TENANT")
    bound_incident = _validate_projection(incident, expected_tenant)
    normalized: list[SOCTimelineEntry] = []
    for item in entries:
        if not isinstance(item, Mapping) or set(item) != _TIMELINE_KEYS:
            raise SOCIncidentDenied("TIMELINE_ENTRY_INVALID")
        if item.get("tenant_id") != expected_tenant or item.get("incident_id") != bound_incident.incident_id:
            raise SOCIncidentDenied("TIMELINE_BINDING_MISMATCH")
        occurred = item.get("occurred_at_epoch")
        entry_type = item.get("entry_type")
        if not isinstance(occurred, int) or isinstance(occurred, bool) or not bound_incident.created_at_epoch <= occurred <= bound_incident.updated_at_epoch or entry_type not in _TIMELINE_TYPES:
            raise SOCIncidentDenied("TIMELINE_ENTRY_INVALID")
        normalized.append(SOCTimelineEntry(
            _text(item.get("entry_id"), "TIMELINE_ENTRY_ID"), expected_tenant,
            bound_incident.incident_id, occurred, entry_type,
            _text(item.get("actor_ref"), "ACTOR_REF"),
            _text(item.get("source_ref"), "SOURCE_REF"),
            _text(item.get("evidence_ref"), "EVIDENCE_REF"),
        ))
    entry_ids = tuple(item.entry_id for item in normalized)
    if len(set(entry_ids)) != len(entry_ids):
        raise SOCIncidentDenied("TIMELINE_ENTRY_DUPLICATE")
    ordered = tuple(sorted(normalized, key=lambda item: (item.occurred_at_epoch, item.entry_id)))
    dispositions = tuple(item for item in ordered if item.entry_type == "DISPOSITION")
    if len(dispositions) > 1 or (bound_incident.status in _ACTIVE and dispositions) or (bound_incident.status not in _ACTIVE and (len(dispositions) != 1 or ordered[-1] != dispositions[0])):
        raise SOCIncidentDenied("TIMELINE_DISPOSITION_INVALID")
    try:
        audit("soc_incident_timeline_projected", {
            "tenant_id": expected_tenant, "incident_id": bound_incident.incident_id,
            "entries": [
                {"entry_id": item.entry_id, "occurred_at_epoch": item.occurred_at_epoch,
                 "entry_type": item.entry_type, "actor_ref": item.actor_ref,
                 "source_ref": item.source_ref, "evidence_ref": item.evidence_ref}
                for item in ordered
            ],
            "count": len(ordered), "trust": "UNTRUSTED_CASE_FACT",
            "mode": "DRY_RUN", "action": "PROJECT_ONLY",
            "response_executed": False, "deployment": "DISABLED",
        })
    except Exception as exc:
        raise SOCIncidentDenied("EVIDENCE_WRITE_FAILED") from exc
    return SOCIncidentTimeline(expected_tenant, bound_incident.incident_id, ordered)
