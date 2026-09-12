"""Canonical bounded normalized-event owner for caller-supplied fixtures.

This module owns only the stateful handoff after the existing fixture seam has
validated an observation.  It has no platform, filesystem, process, network,
credential, deployment, quarantine, remediation, or response access.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import re
from threading import RLock
from typing import Any, Mapping

from .asoc import AuditSink
from .endpoint_fixtures import EndpointFixtureDenied, EndpointObservation, normalize_fixture


MAX_QUEUED_EVENTS_PER_DEVICE = 1024
MAX_EVENT_BATCH = 128
MAX_CORRELATION_GROUPS = 64
MAX_AI_EVENTS_PER_AGENT = 1024
MAX_AI_ATTRIBUTIONS_PER_DEVICE = 1024
AI_EVENT_CLASSES = frozenset({"AID-ESCAPE","AID-EGRESS","AID-SECRETS","AID-PRIVILEGE","AID-LATERAL","AID-INJECTION","AID-MISSION","AID-COORDINATION","AID-EVALUATION","AID-TAMPER"})
AI_DECISIONS = frozenset({"ALLOWED","DENIED","OBSERVED"})
AI_TOOL_CATEGORIES = frozenset({"NONE","FILESYSTEM","PROCESS","SHELL","NETWORK","BROWSER","EMAIL","MCP","CLOUD","CONTAINER","KUBERNETES","IDENTITY","CREDENTIAL"})
AI_CLASSIFICATIONS = frozenset({"PUBLIC","INTERNAL","CONFIDENTIAL","RESTRICTED"})
_AI_ID=re.compile(r"^[a-z][a-z0-9_.:/-]{0,191}$"); _AI_SHA=re.compile(r"^[0-9a-f]{64}$"); _AI_TENANT=re.compile(r"^[a-z][a-z0-9_.-]{0,127}$"); _AI_SECRET=re.compile(r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=])")
AI_ENDPOINT_ATTRIBUTION_FIELDS=frozenset({"schema_version","tenant_id","device_id","endpoint_event_id","agent_ref","session_ref","task_ref","capability_lease_ref","action_ticket_ref","observed_at_epoch","evidence_references","mode","action","authority_granted"})
AI_EVENT_FIELDS=frozenset({"schema_version","event_id","tenant_id","event_class","source","classification","observed_at_epoch","agent_ref","model_ref","session_ref","task_ref","initiating_user_ref","purpose_sha256","capability_lease_ref","action_ticket_ref","tool_category","mcp_server_ref","target_resource_ref","decision","anomaly_indicators","evidence_references","mode","action","authority_granted"})

def _ai_text(value:Any,name:str)->str:
    if not isinstance(value,str) or not value or value!=value.strip() or not _AI_ID.fullmatch(value) or _AI_SECRET.search(value): raise EndpointFixtureDenied(f"AI_{name.upper()}_INVALID")
    return value

def _tenant_ref(value:str,prefix:str,tenant:str,name:str)->str:
    value=_ai_text(value,name)
    if not value.startswith(f"{prefix}/{tenant}/"): raise EndpointFixtureDenied(f"AI_{name.upper()}_TENANT_MISMATCH")
    return value

@dataclass(frozen=True)
class AIWorkloadSecurityEvent:
    schema_version:str; event_id:str; tenant_id:str; event_class:str; source:str; classification:str; observed_at_epoch:int; agent_ref:str; model_ref:str; session_ref:str; task_ref:str; initiating_user_ref:str; purpose_sha256:str; capability_lease_ref:str; action_ticket_ref:str; tool_category:str; mcp_server_ref:str; target_resource_ref:str; decision:str; anomaly_indicators:tuple[str,...]; evidence_references:tuple[str,...]; mode:str="DRY_RUN"; action:str="DETECT_ONLY"; authority_granted:bool=False
    def __post_init__(self):
        tenant=_ai_text(self.tenant_id,"tenant")
        if not _AI_TENANT.fullmatch(tenant) or self.schema_version!="1": raise EndpointFixtureDenied("AI_SCHEMA_OR_TENANT_INVALID")
        _tenant_ref(self.event_id,"fw-event",tenant,"event_id"); _tenant_ref(self.agent_ref,"fw-id",tenant,"agent_ref"); _tenant_ref(self.model_ref,"fw-model",tenant,"model_ref"); _tenant_ref(self.session_ref,"fw-session",tenant,"session_ref"); _tenant_ref(self.task_ref,"fw-task",tenant,"task_ref"); _tenant_ref(self.initiating_user_ref,"fw-id",tenant,"initiating_user_ref"); _tenant_ref(self.capability_lease_ref,"fw-lease",tenant,"capability_lease_ref"); _tenant_ref(self.action_ticket_ref,"fw-action",tenant,"action_ticket_ref"); _tenant_ref(self.target_resource_ref,"fw-resource",tenant,"target_resource_ref")
        _ai_text(self.source,"source"); _ai_text(self.mcp_server_ref,"mcp_server_ref")
        if self.event_class not in AI_EVENT_CLASSES or self.classification not in AI_CLASSIFICATIONS or self.decision not in AI_DECISIONS or self.tool_category not in AI_TOOL_CATEGORIES: raise EndpointFixtureDenied("AI_EVENT_ENUM_INVALID")
        if not isinstance(self.observed_at_epoch,int) or isinstance(self.observed_at_epoch,bool) or self.observed_at_epoch<0: raise EndpointFixtureDenied("AI_EVENT_TIME_INVALID")
        if not isinstance(self.purpose_sha256,str) or not _AI_SHA.fullmatch(self.purpose_sha256): raise EndpointFixtureDenied("AI_PURPOSE_HASH_INVALID")
        for values,name,maximum,prefix in ((self.anomaly_indicators,"indicators",32,None),(self.evidence_references,"evidence",32,"fw-evid")):
            if not isinstance(values,tuple) or len(values)>maximum or tuple(sorted(set(values)))!=values: raise EndpointFixtureDenied(f"AI_{name.upper()}_INVALID")
            for value in values:
                if prefix: _tenant_ref(value,prefix,tenant,f"{name}_reference")
                else: _ai_text(value,name)
        if self.mode!="DRY_RUN" or self.action!="DETECT_ONLY" or self.authority_granted is not False: raise EndpointFixtureDenied("AI_EVENT_AUTHORITY_FORBIDDEN")

def validate_ai_workload_event(value:Mapping[str,Any])->AIWorkloadSecurityEvent:
    if not isinstance(value,Mapping) or set(value)!=AI_EVENT_FIELDS: raise EndpointFixtureDenied("AI_EVENT_FIELDS_INVALID")
    converted=dict(value)
    for field in ("anomaly_indicators","evidence_references"):
        if isinstance(converted[field],list): converted[field]=tuple(converted[field])
    return AIWorkloadSecurityEvent(**converted)


@dataclass(frozen=True)
class AIEndpointAttribution:
    """Opaque AI identity bindings for one already-admitted endpoint fixture."""
    schema_version: str; tenant_id: str; device_id: str; endpoint_event_id: str
    agent_ref: str; session_ref: str; task_ref: str; capability_lease_ref: str; action_ticket_ref: str
    observed_at_epoch: int; evidence_references: tuple[str, ...]
    mode: str = "DRY_RUN"; action: str = "CORRELATE_ONLY"; authority_granted: bool = False

    def __post_init__(self) -> None:
        tenant = _ai_text(self.tenant_id, "tenant")
        if not _AI_TENANT.fullmatch(tenant) or self.schema_version != "1": raise EndpointFixtureDenied("AI_ENDPOINT_SCHEMA_OR_TENANT_INVALID")
        _ai_text(self.device_id, "device_id"); _ai_text(self.endpoint_event_id, "endpoint_event_id")
        _tenant_ref(self.agent_ref,"fw-id",tenant,"agent_ref"); _tenant_ref(self.session_ref,"fw-session",tenant,"session_ref"); _tenant_ref(self.task_ref,"fw-task",tenant,"task_ref"); _tenant_ref(self.capability_lease_ref,"fw-lease",tenant,"capability_lease_ref"); _tenant_ref(self.action_ticket_ref,"fw-action",tenant,"action_ticket_ref")
        if not isinstance(self.observed_at_epoch,int) or isinstance(self.observed_at_epoch,bool) or self.observed_at_epoch < 0: raise EndpointFixtureDenied("AI_ENDPOINT_TIME_INVALID")
        if not isinstance(self.evidence_references,tuple) or len(self.evidence_references)>32 or tuple(sorted(set(self.evidence_references))) != self.evidence_references: raise EndpointFixtureDenied("AI_ENDPOINT_EVIDENCE_INVALID")
        for reference in self.evidence_references: _tenant_ref(reference,"fw-evid",tenant,"evidence_reference")
        if self.mode!="DRY_RUN" or self.action!="CORRELATE_ONLY" or self.authority_granted is not False: raise EndpointFixtureDenied("AI_ENDPOINT_AUTHORITY_FORBIDDEN")


def validate_ai_endpoint_attribution(value: Mapping[str,Any]) -> AIEndpointAttribution:
    if not isinstance(value,Mapping) or set(value)!=AI_ENDPOINT_ATTRIBUTION_FIELDS: raise EndpointFixtureDenied("AI_ENDPOINT_FIELDS_INVALID")
    converted=dict(value)
    if isinstance(converted["evidence_references"],list): converted["evidence_references"]=tuple(converted["evidence_references"])
    return AIEndpointAttribution(**converted)


@dataclass(frozen=True)
class CorrelatedEventGroup:
    tenant_id: str
    device_id: str
    event_ids: tuple[str, ...]
    indicators: tuple[str, ...]
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


class NormalizedEventStore:
    """Bounded tenant/device event queue with event-ID deduplication."""

    def __init__(self, audit: AuditSink, *, max_queued_events_per_device: int = MAX_QUEUED_EVENTS_PER_DEVICE) -> None:
        if not callable(audit) or not isinstance(max_queued_events_per_device, int) or not 1 <= max_queued_events_per_device <= MAX_QUEUED_EVENTS_PER_DEVICE:
            raise ValueError("invalid normalized-event store configuration")
        self._audit = audit
        self._limit = max_queued_events_per_device
        self._lock = RLock()
        self._seen: set[tuple[str, str, str]] = set()
        self._seen_counts: dict[tuple[str, str], int] = {}
        self._queues: dict[tuple[str, str], deque[EndpointObservation]] = {}
        self._ai_queues: dict[tuple[str, str], deque[AIWorkloadSecurityEvent]] = {}
        self._ai_seen: set[tuple[str, str, str]] = set()
        self._ai_endpoint_attributions: dict[tuple[str, str], deque[AIEndpointAttribution]] = {}
        self._ai_endpoint_seen: set[tuple[str, str, str]] = set()

    @property
    def max_queued_events_per_device(self) -> int:
        return self._limit

    def admit_ai_security_event(self, value: Mapping[str, Any]) -> AIWorkloadSecurityEvent:
        """Validate privacy-minimized caller metadata, write Evidence, then enqueue."""
        event=validate_ai_workload_event(value); key=(event.tenant_id,event.agent_ref); event_key=(*key,event.event_id)
        with self._lock:
            queue=self._ai_queues.get(key,deque())
            if event_key in self._ai_seen: raise EndpointFixtureDenied("AI_EVENT_REPLAY")
            if len(queue)>=MAX_AI_EVENTS_PER_AGENT: raise EndpointFixtureDenied("AI_EVENT_QUEUE_FULL")
            try:
                self._audit("ai_security_event_admitted", {field:getattr(event,field) for field in AI_EVENT_FIELDS if field not in {"authority_granted"}} | {"authority_granted":False})
            except Exception as exc: raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            self._ai_seen.add(event_key); self._ai_queues.setdefault(key,queue).append(event); return event

    def pending_ai_security_events(self, *, tenant_id: str, agent_ref: str, limit: int = 128) -> tuple[AIWorkloadSecurityEvent, ...]:
        if not isinstance(limit,int) or isinstance(limit,bool) or not 1<=limit<=128: raise EndpointFixtureDenied("AI_EVENT_SNAPSHOT_LIMIT_INVALID")
        _tenant_ref(agent_ref,"fw-id",_ai_text(tenant_id,"tenant"),"agent_ref")
        with self._lock: return tuple(list(self._ai_queues.get((tenant_id,agent_ref),()))[:limit])


    def admit_ai_endpoint_attribution(self, value: Mapping[str,Any]) -> AIEndpointAttribution:
        """Bind opaque AI references to an existing endpoint fixture without executing anything."""
        attribution=validate_ai_endpoint_attribution(value); device_key=(attribution.tenant_id,attribution.device_id); replay_key=(*device_key,attribution.endpoint_event_id)
        with self._lock:
            matching=tuple(item for item in self._queues.get(device_key,()) if item.event_id==attribution.endpoint_event_id)
            if len(matching)!=1: raise EndpointFixtureDenied("AI_ENDPOINT_EVENT_NOT_PENDING")
            if matching[0].observed_at_epoch!=attribution.observed_at_epoch: raise EndpointFixtureDenied("AI_ENDPOINT_CHRONOLOGY_MISMATCH")
            queue=self._ai_endpoint_attributions.get(device_key,deque())
            if replay_key in self._ai_endpoint_seen: raise EndpointFixtureDenied("AI_ENDPOINT_REPLAY")
            if len(queue)>=MAX_AI_ATTRIBUTIONS_PER_DEVICE: raise EndpointFixtureDenied("AI_ENDPOINT_QUEUE_FULL")
            try:
                self._audit("ai_endpoint_attribution_admitted",{field:getattr(attribution,field) for field in AI_ENDPOINT_ATTRIBUTION_FIELDS if field!="authority_granted"}|{"authority_granted":False})
            except Exception as exc: raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            self._ai_endpoint_seen.add(replay_key); self._ai_endpoint_attributions.setdefault(device_key,queue).append(attribution); return attribution

    def pending_ai_endpoint_attributions(self, *, tenant_id:str, device_id:str, limit:int=128) -> tuple[AIEndpointAttribution,...]:
        if not isinstance(limit,int) or isinstance(limit,bool) or not 1<=limit<=128: raise EndpointFixtureDenied("AI_ENDPOINT_SNAPSHOT_LIMIT_INVALID")
        key=(_ai_text(tenant_id,"tenant"),_ai_text(device_id,"device_id"))
        with self._lock: return tuple(list(self._ai_endpoint_attributions.get(key,()))[:limit])

    def admit_fixture(
        self,
        fixture: Mapping[str, Any], *, tenant_id: str, device_id: str, source: str,
        now_epoch: int,
    ) -> EndpointObservation:
        """Normalize, deduplicate, write Evidence, then enqueue one observation."""
        # First perform all pure fixture validation without an Evidence side effect.
        observation = normalize_fixture(
            fixture, tenant_id=tenant_id, device_id=device_id, source=source,
            now_epoch=now_epoch, audit=lambda *_args: None,
        )
        event_key = (observation.tenant_id, observation.device_id, observation.event_id)
        device_key = (observation.tenant_id, observation.device_id)
        with self._lock:
            if event_key in self._seen:
                raise EndpointFixtureDenied("EVENT_ID_DUPLICATE")
            queue = self._queues.get(device_key)
            if queue is None:
                queue = deque()
            if len(queue) >= self._limit:
                raise EndpointFixtureDenied("EVENT_QUEUE_FULL")
            if self._seen_counts.get(device_key, 0) >= MAX_QUEUED_EVENTS_PER_DEVICE:
                raise EndpointFixtureDenied("EVENT_ID_CAPACITY")
            try:
                self._audit("endpoint_event_admitted", {
                    "event_id": observation.event_id,
                    "tenant_id": observation.tenant_id,
                    "device_id": observation.device_id,
                    "observed_at_epoch": observation.observed_at_epoch,
                    "event_type": observation.event_type,
                    "source": observation.source,
                    "evidence_ref": observation.evidence_ref,
                    "mode": observation.mode,
                    "action": observation.action,
                })
            except Exception as exc:
                raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            self._seen.add(event_key)
            self._seen_counts[device_key] = self._seen_counts.get(device_key, 0) + 1
            self._queues.setdefault(device_key, queue).append(observation)
            return observation

    def admit_batch(
        self,
        fixtures: list[Mapping[str, Any]], *, tenant_id: str, device_id: str,
        source: str, now_epoch: int,
    ) -> tuple[EndpointObservation, ...]:
        """Preflight and atomically admit a bounded batch through one Evidence write."""
        if not isinstance(fixtures, list) or not 1 <= len(fixtures) <= MAX_EVENT_BATCH:
            raise EndpointFixtureDenied("BATCH_INVALID")
        observations = tuple(
            normalize_fixture(fixture, tenant_id=tenant_id, device_id=device_id, source=source,
                              now_epoch=now_epoch, audit=lambda *_args: None)
            for fixture in fixtures
        )
        keys = [(item.tenant_id, item.device_id, item.event_id) for item in observations]
        if len(set(keys)) != len(keys):
            raise EndpointFixtureDenied("EVENT_ID_DUPLICATE")
        device_key = (tenant_id, device_id)
        with self._lock:
            queue = self._queues.get(device_key)
            if queue is None:
                queue = deque()
            if len(queue) + len(observations) > self._limit:
                raise EndpointFixtureDenied("EVENT_QUEUE_FULL")
            if any(key in self._seen for key in keys):
                raise EndpointFixtureDenied("EVENT_ID_DUPLICATE")
            if self._seen_counts.get(device_key, 0) + len(observations) > MAX_QUEUED_EVENTS_PER_DEVICE:
                raise EndpointFixtureDenied("EVENT_ID_CAPACITY")
            try:
                self._audit("endpoint_events_batch_admitted", {
                    "tenant_id": tenant_id, "device_id": device_id, "source": source,
                    "event_ids": [item.event_id for item in observations],
                    "count": len(observations), "mode": observations[0].mode, "action": observations[0].action,
                })
            except Exception as exc:
                raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            self._seen.update(keys)
            self._seen_counts[device_key] = self._seen_counts.get(device_key, 0) + len(observations)
            self._queues.setdefault(device_key, queue).extend(observations)
            return observations

    def peek_next(self, *, tenant_id: str, device_id: str) -> EndpointObservation | None:
        """Inspect the oldest event without removing it, for retry-safe recovery."""
        with self._lock:
            queue = self._queues.get((tenant_id, device_id))
            if not queue:
                return None
            return queue[0]

    def pending_events(
        self, *, tenant_id: str, device_id: str,
        limit: int = MAX_QUEUED_EVENTS_PER_DEVICE,
    ) -> tuple[EndpointObservation, ...]:
        """Return a bounded FIFO snapshot without acknowledging any event."""
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_QUEUED_EVENTS_PER_DEVICE:
            raise EndpointFixtureDenied("EVENT_SNAPSHOT_LIMIT_INVALID")
        with self._lock:
            queue = self._queues.get((tenant_id, device_id))
            if not queue:
                return ()
            return tuple(list(queue)[:limit])

    def correlate_pending(
        self, *, tenant_id: str, device_id: str,
        limit: int = MAX_CORRELATION_GROUPS,
    ) -> tuple[CorrelatedEventGroup, ...]:
        """Return bounded deterministic groups for shared fixture indicators.

        This is an in-memory observation over one tenant/device queue. It does
        not acknowledge, reorder, or otherwise mutate events.
        """
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= MAX_CORRELATION_GROUPS:
            raise EndpointFixtureDenied("CORRELATION_LIMIT_INVALID")
        with self._lock:
            queue = tuple(self._queues.get((tenant_id, device_id), ()))
            by_indicator: dict[str, list[EndpointObservation]] = {}
            for observation in queue:
                for indicator in set(observation.related_indicators):
                    by_indicator.setdefault(indicator, []).append(observation)
            grouped: dict[tuple[str, ...], list[str]] = {}
            for indicator in sorted(by_indicator):
                observations = by_indicator[indicator]
                if len(observations) < 2:
                    continue
                event_ids = tuple(item.event_id for item in observations)
                grouped.setdefault(event_ids, []).append(indicator)
            groups = [
                CorrelatedEventGroup(
                    tenant_id=tenant_id, device_id=device_id,
                    event_ids=event_ids, indicators=tuple(indicators),
                )
                for event_ids, indicators in sorted(grouped.items())
            ][:limit]
            try:
                self._audit("endpoint_events_correlated", {
                    "tenant_id": tenant_id, "device_id": device_id,
                    "groups": [
                        {"event_ids": list(group.event_ids), "indicators": list(group.indicators)}
                        for group in groups
                    ], "count": len(groups), "mode": "DRY_RUN", "action": "DETECT_ONLY",
                })
            except Exception as exc:
                raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            return tuple(groups)

    def acknowledge_batch(
        self, observations: tuple[EndpointObservation, ...],
    ) -> tuple[EndpointObservation, ...]:
        """Write one completion Evidence record before removing an exact FIFO prefix."""
        if not isinstance(observations, tuple) or not 1 <= len(observations) <= MAX_EVENT_BATCH:
            raise EndpointFixtureDenied("EVENT_ACK_BATCH_INVALID")
        if any(not isinstance(item, EndpointObservation) for item in observations):
            raise EndpointFixtureDenied("EVENT_ACK_BATCH_INVALID")
        device_key = (observations[0].tenant_id, observations[0].device_id)
        if any((item.tenant_id, item.device_id) != device_key for item in observations):
            raise EndpointFixtureDenied("EVENT_ACK_TENANT_OR_DEVICE_MISMATCH")
        with self._lock:
            queue = self._queues.get(device_key)
            if not queue or tuple(list(queue)[:len(observations)]) != observations:
                raise EndpointFixtureDenied("EVENT_NOT_QUEUE_PREFIX")
            try:
                self._audit("endpoint_events_batch_acknowledged", {
                    "event_ids": [item.event_id for item in observations],
                    "tenant_id": device_key[0], "device_id": device_key[1],
                    "count": len(observations), "mode": observations[0].mode, "action": observations[0].action,
                })
            except Exception as exc:
                raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            for _ in observations:
                queue.popleft()
            if not queue:
                self._queues.pop(device_key, None)
            return observations

    def acknowledge(self, observation: EndpointObservation) -> EndpointObservation:
        """Write completion Evidence, then remove the exact queue head."""
        device_key = (observation.tenant_id, observation.device_id)
        with self._lock:
            queue = self._queues.get(device_key)
            if not queue or queue[0] != observation:
                raise EndpointFixtureDenied("EVENT_NOT_QUEUE_HEAD")
            try:
                self._audit("endpoint_event_acknowledged", {
                    "event_id": observation.event_id,
                    "tenant_id": observation.tenant_id,
                    "device_id": observation.device_id,
                    "observed_at_epoch": observation.observed_at_epoch,
                    "event_type": observation.event_type,
                    "source": observation.source,
                    "evidence_ref": observation.evidence_ref,
                    "mode": observation.mode,
                    "action": observation.action,
                })
            except Exception as exc:
                raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            queue.popleft()
            if not queue:
                self._queues.pop(device_key, None)
            return observation

    def dequeue(self, *, tenant_id: str, device_id: str) -> EndpointObservation | None:
        """Compatibility helper that acknowledges the oldest event before removal."""
        with self._lock:
            observation = self.peek_next(tenant_id=tenant_id, device_id=device_id)
            return self.acknowledge(observation) if observation is not None else None

    def queued_count(self, *, tenant_id: str, device_id: str) -> int:
        with self._lock:
            return len(self._queues.get((tenant_id, device_id), ()))
