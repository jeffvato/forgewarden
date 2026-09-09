"""Pure caller-supplied Android metadata/event mapping.

This is a fixture-only seam. It does not call Android APIs, inspect a device,
read files, collect processes/network data, or perform any response action.
"""
from __future__ import annotations

from typing import Any, Mapping

from .normalized_events import NormalizedEventStore

ANDROID_SOURCE = "ANDROID_FIXTURE"
_REQUIRED = frozenset({
    "event_id", "tenant_id", "device_id", "observed_at_epoch", "event_type",
    "package_name", "app_label", "version_name", "version_code", "permissions",
    "related_indicators", "evidence_ref",
})
_EVENT_TYPES = frozenset({"APP_STATE", "APP_PERMISSION", "DEVICE_POSTURE"})
MAX_ANDROID_PERMISSIONS = 64


class AndroidFixtureDenied(ValueError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def adapt_android_record(record: Mapping[str, Any], *, tenant_id: str, device_id: str) -> dict[str, Any]:
    """Map one explicit Android-shaped record to the canonical fixture envelope."""
    if not isinstance(record, Mapping) or set(record) != _REQUIRED:
        raise AndroidFixtureDenied("RECORD_INVALID")
    if record.get("tenant_id") != tenant_id or record.get("device_id") != device_id:
        raise AndroidFixtureDenied("TENANT_OR_DEVICE_MISMATCH")
    if record.get("event_type") not in _EVENT_TYPES:
        raise AndroidFixtureDenied("EVENT_TYPE_INVALID")
    permissions = record.get("permissions")
    if not isinstance(permissions, (list, tuple)) or not permissions or len(permissions) > MAX_ANDROID_PERMISSIONS:
        raise AndroidFixtureDenied("PERMISSIONS_INVALID")
    if any(not isinstance(permission, str) or not permission.strip() for permission in permissions):
        raise AndroidFixtureDenied("PERMISSIONS_INVALID")
    return {
        "event_id": record["event_id"], "tenant_id": tenant_id, "device_id": device_id,
        "observed_at_epoch": record["observed_at_epoch"], "event_type": record["event_type"],
        "source": ANDROID_SOURCE,
        "artifact": {
            "package_name": record["package_name"], "name": record["app_label"],
            "version_name": record["version_name"], "version_code": record["version_code"],
            "permissions": ";".join(permissions),
        },
        "process_ancestry": [], "related_indicators": record["related_indicators"],
        "evidence_ref": record["evidence_ref"],
    }


def ingest_android_fixture(
    store: NormalizedEventStore, record: Mapping[str, Any], *, tenant_id: str,
    device_id: str, now_epoch: int,
):
    """Normalize and enqueue one Android fixture through the canonical store."""
    if not isinstance(store, NormalizedEventStore):
        raise AndroidFixtureDenied("STORE_INVALID")
    fixture = adapt_android_record(record, tenant_id=tenant_id, device_id=device_id)
    return store.admit_fixture(fixture, tenant_id=tenant_id, device_id=device_id, source=ANDROID_SOURCE, now_epoch=now_epoch)
