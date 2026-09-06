"""Canonical bounded normalized-event owner for caller-supplied fixtures.

This module owns only the stateful handoff after the existing fixture seam has
validated an observation.  It has no platform, filesystem, process, network,
credential, deployment, quarantine, remediation, or response access.
"""
from __future__ import annotations

from collections import deque
from threading import RLock
from typing import Any, Mapping

from .asoc import AuditSink
from .endpoint_fixtures import EndpointFixtureDenied, EndpointObservation, normalize_fixture


MAX_QUEUED_EVENTS_PER_DEVICE = 1024


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

    @property
    def max_queued_events_per_device(self) -> int:
        return self._limit

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
            queue = self._queues.setdefault(device_key, deque())
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
            queue.append(observation)
            return observation

    def admit_batch(
        self,
        fixtures: list[Mapping[str, Any]], *, tenant_id: str, device_id: str,
        source: str, now_epoch: int,
    ) -> tuple[EndpointObservation, ...]:
        """Preflight and atomically admit a bounded batch through one Evidence write."""
        if not isinstance(fixtures, list) or not fixtures:
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
            queue = self._queues.setdefault(device_key, deque())
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
                    "count": len(observations), "mode": "DRY_RUN", "action": "DETECT_ONLY",
                })
            except Exception as exc:
                raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
            self._seen.update(keys)
            self._seen_counts[device_key] = self._seen_counts.get(device_key, 0) + len(observations)
            queue.extend(observations)
            return observations

    def peek_next(self, *, tenant_id: str, device_id: str) -> EndpointObservation | None:
        """Inspect the oldest event without removing it, for retry-safe recovery."""
        with self._lock:
            queue = self._queues.get((tenant_id, device_id))
            if not queue:
                return None
            return queue[0]

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
