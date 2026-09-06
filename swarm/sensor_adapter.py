"""Pure caller-supplied Windows/Linux record mapping.

The mapper performs no platform access.  It converts an explicit native-shaped
record into the fixture envelope consumed by ``NormalizedEventStore``.
"""
from __future__ import annotations

from typing import Any, Mapping


_SOURCES = frozenset({"WINDOWS_SENSOR", "LINUX_SENSOR"})
_EVENT_TYPES = frozenset({"FILE_LIFECYCLE", "PROCESS_START", "PROCESS_EXIT", "NETWORK_CONNECT", "RUNTIME_INDICATOR"})
_RECORD_KEYS = frozenset({
    "event_id", "tenant_id", "device_id", "observed_at_epoch", "event_type",
    "source", "metadata", "process_ancestry", "related_indicators", "evidence_ref",
})


class SensorAdapterDenied(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def adapt_record(record: Mapping[str, Any], *, source: str) -> dict[str, Any]:
    """Map one explicit record to the canonical fixture envelope."""
    if not isinstance(record, Mapping) or source not in _SOURCES:
        raise SensorAdapterDenied("RECORD_INVALID")
    if set(record) != _RECORD_KEYS or record.get("source") != source:
        raise SensorAdapterDenied("RECORD_INVALID")
    event_type = record.get("event_type")
    if event_type not in _EVENT_TYPES:
        raise SensorAdapterDenied("EVENT_TYPE_INVALID")
    metadata = record.get("metadata")
    if not isinstance(metadata, Mapping) or not metadata:
        raise SensorAdapterDenied("METADATA_INVALID")
    if any(record.get(key) is None for key in ("process_ancestry", "related_indicators", "evidence_ref")):
        raise SensorAdapterDenied("RECORD_INVALID")
    # The canonical fixture seam owns field-level bounds and tenant/device
    # validation; this mapper only selects the correct metadata branch.
    fixture: dict[str, Any] = {
        "event_id": record["event_id"],
        "tenant_id": record["tenant_id"],
        "device_id": record["device_id"],
        "observed_at_epoch": record["observed_at_epoch"],
        "event_type": event_type,
        "source": source,
        "process": dict(metadata) if event_type in {"PROCESS_START", "PROCESS_EXIT"} else None,
        "artifact": dict(metadata) if event_type not in {"PROCESS_START", "PROCESS_EXIT"} else None,
        "process_ancestry": record["process_ancestry"],
        "related_indicators": record["related_indicators"],
        "evidence_ref": record["evidence_ref"],
    }
    return {key: value for key, value in fixture.items() if value is not None}
