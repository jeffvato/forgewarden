"""Pure caller-supplied macOS endpoint record mapping.

This fixture seam performs no platform, filesystem, process, network, or
response operation. It only maps explicit records into NormalizedEventStore.
"""
from __future__ import annotations

from typing import Any, Mapping

from .normalized_events import MAX_EVENT_BATCH, NormalizedEventStore

MACOS_SOURCE = "MACOS_FIXTURE"
_EVENT_TYPES = frozenset({
    "FILE_LIFECYCLE", "PROCESS_START", "PROCESS_EXIT",
    "NETWORK_CONNECT", "RUNTIME_INDICATOR", "DEVICE_POSTURE",
})
_REQUIRED = frozenset({
    "event_id", "tenant_id", "device_id", "observed_at_epoch", "event_type",
    "source", "metadata", "process_ancestry", "related_indicators",
    "evidence_ref",
})


class MacOSFixtureDenied(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def adapt_macos_record(
    record: Mapping[str, Any], *, tenant_id: str, device_id: str,
) -> dict[str, Any]:
    """Map one explicit macOS-shaped record to the canonical fixture envelope."""
    if not isinstance(record, Mapping) or set(record) != _REQUIRED:
        raise MacOSFixtureDenied("RECORD_INVALID")
    if record.get("source") != MACOS_SOURCE:
        raise MacOSFixtureDenied("SOURCE_MISMATCH")
    if record.get("tenant_id") != tenant_id or record.get("device_id") != device_id:
        raise MacOSFixtureDenied("TENANT_OR_DEVICE_MISMATCH")
    event_type = record.get("event_type")
    if event_type not in _EVENT_TYPES:
        raise MacOSFixtureDenied("EVENT_TYPE_INVALID")
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping) or not metadata:
        raise MacOSFixtureDenied("METADATA_INVALID")
    if any(record.get(key) is None for key in ("process_ancestry", "related_indicators", "evidence_ref")):
        raise MacOSFixtureDenied("RECORD_INVALID")
    fixture: dict[str, Any] = {
        "event_id": record["event_id"],
        "tenant_id": tenant_id,
        "device_id": device_id,
        "observed_at_epoch": record["observed_at_epoch"],
        "event_type": event_type,
        "source": MACOS_SOURCE,
        "process": dict(metadata) if event_type in {"PROCESS_START", "PROCESS_EXIT"} else None,
        "artifact": dict(metadata) if event_type not in {"PROCESS_START", "PROCESS_EXIT"} else None,
        "process_ancestry": record["process_ancestry"],
        "related_indicators": record["related_indicators"],
        "evidence_ref": record["evidence_ref"],
    }
    return {key: value for key, value in fixture.items() if value is not None}


def ingest_macos_fixture(
    store: NormalizedEventStore, record: Mapping[str, Any], *, tenant_id: str,
    device_id: str, now_epoch: int,
):
    """Normalize and enqueue one macOS fixture through the canonical store."""
    if not isinstance(store, NormalizedEventStore):
        raise MacOSFixtureDenied("STORE_INVALID")
    fixture = adapt_macos_record(record, tenant_id=tenant_id, device_id=device_id)
    return store.admit_fixture(
        fixture, tenant_id=tenant_id, device_id=device_id,
        source=MACOS_SOURCE, now_epoch=now_epoch,
    )


def ingest_macos_batch(
    store: NormalizedEventStore, records: list[Mapping[str, Any]], *,
    tenant_id: str, device_id: str, now_epoch: int,
) -> tuple[Any, ...]:
    """Atomically admit a bounded, deterministically ordered macOS batch."""
    if not isinstance(store, NormalizedEventStore):
        raise MacOSFixtureDenied("STORE_INVALID")
    if not isinstance(records, list) or not 1 <= len(records) <= MAX_EVENT_BATCH:
        raise MacOSFixtureDenied("BATCH_INVALID")
    fixtures = [
        adapt_macos_record(record, tenant_id=tenant_id, device_id=device_id)
        for record in records
    ]
    if len({fixture["event_id"] for fixture in fixtures}) != len(fixtures):
        raise MacOSFixtureDenied("EVENT_ID_DUPLICATE")
    fixtures.sort(key=lambda fixture: (fixture["observed_at_epoch"], fixture["event_id"]))
    return store.admit_batch(
        fixtures, tenant_id=tenant_id, device_id=device_id,
        source=MACOS_SOURCE, now_epoch=now_epoch,
    )
