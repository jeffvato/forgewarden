"""Bounded, caller-supplied Windows/Linux endpoint fixture normalization.

This module deliberately has no platform, filesystem, process, network, or
response access.  It is a test seam until a canonical normalized-event owner
is implemented; it returns only an immutable observation after Evidence is
written successfully.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, Mapping

from .asoc import AuditSink


MAX_FIXTURE_BYTES = 64 * 1024
MAX_METADATA_STRING_BYTES = 256
MAX_PROCESS_ANCESTRY = 32
MAX_RELATED_INDICATORS = 64
_SOURCES = frozenset({"WINDOWS_SENSOR", "LINUX_SENSOR", "ANDROID_FIXTURE", "MACOS_FIXTURE"})
_EVENT_TYPES = frozenset({"FILE_LIFECYCLE", "PROCESS_START", "PROCESS_EXIT", "NETWORK_CONNECT", "RUNTIME_INDICATOR", "APP_STATE", "APP_PERMISSION", "DEVICE_POSTURE"})
_FIXTURE_KEYS = frozenset({
    "event_id", "tenant_id", "device_id", "observed_at_epoch", "event_type", "source",
    "artifact", "process", "process_ancestry", "related_indicators", "evidence_ref",
})
_METADATA_KEYS = frozenset({"path", "name", "digest", "pid", "parent_pid", "command_line", "destination", "operation", "exit_code", "package_name", "app_label", "version_name", "version_code", "permissions"})


class EndpointFixtureDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _bounded_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip() or len(value.encode("utf-8")) > MAX_METADATA_STRING_BYTES:
        raise EndpointFixtureDenied(f"{field}_INVALID")
    return value.strip()


def _metadata(value: Any, field: str) -> tuple[tuple[str, str], ...]:
    if not isinstance(value, Mapping) or not value:
        raise EndpointFixtureDenied(f"{field}_INVALID")
    if any(key not in _METADATA_KEYS for key in value) or len(value) > len(_METADATA_KEYS):
        raise EndpointFixtureDenied(f"{field}_INVALID")
    return tuple(sorted((_bounded_text(key, f"{field}_key"), _bounded_text(item, field)) for key, item in value.items()))


@dataclass(frozen=True)
class EndpointObservation:
    event_id: str
    tenant_id: str
    device_id: str
    observed_at_epoch: int
    event_type: str
    source: str
    metadata: tuple[tuple[str, str], ...]
    process_ancestry: tuple[str, ...]
    related_indicators: tuple[str, ...]
    evidence_ref: str
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"


def normalize_fixture(
    fixture: Mapping[str, Any], *, tenant_id: str, device_id: str, source: str,
    now_epoch: int, audit: AuditSink,
) -> EndpointObservation:
    """Normalize one explicit fixture after writing canonical Evidence."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise EndpointFixtureDenied("FIXTURE_INVALID")
    try:
        if len(json.dumps(fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")) > MAX_FIXTURE_BYTES:
            raise EndpointFixtureDenied("FIXTURE_TOO_LARGE")
    except (TypeError, ValueError, OverflowError) as exc:
        raise EndpointFixtureDenied("FIXTURE_INVALID") from exc
    if source not in _SOURCES or not isinstance(now_epoch, int) or now_epoch < 0:
        raise EndpointFixtureDenied("FIXTURE_INVALID")
    expected_tenant = _bounded_text(tenant_id, "tenant_id")
    expected_device = _bounded_text(device_id, "device_id")
    if set(fixture) - _FIXTURE_KEYS:
        raise EndpointFixtureDenied("FIXTURE_INVALID")
    if fixture.get("source") != source:
        raise EndpointFixtureDenied("SOURCE_MISMATCH")
    event_id = _bounded_text(fixture.get("event_id"), "event_id")
    if fixture.get("tenant_id") != expected_tenant or fixture.get("device_id") != expected_device:
        raise EndpointFixtureDenied("TENANT_OR_DEVICE_MISMATCH")
    observed = fixture.get("observed_at_epoch")
    if not isinstance(observed, int) or observed < 0 or observed > now_epoch:
        raise EndpointFixtureDenied("OBSERVED_AT_INVALID")
    event_type = fixture.get("event_type")
    if event_type not in _EVENT_TYPES:
        raise EndpointFixtureDenied("EVENT_TYPE_INVALID")
    evidence_ref = _bounded_text(fixture.get("evidence_ref"), "evidence_ref")
    if fixture.get("artifact") is not None and fixture.get("process") is not None:
        raise EndpointFixtureDenied("METADATA_INVALID")
    metadata_value = fixture.get("artifact") if fixture.get("artifact") is not None else fixture.get("process")
    metadata = _metadata(metadata_value, "metadata")
    ancestry_value = fixture.get("process_ancestry", ())
    indicators_value = fixture.get("related_indicators", ())
    if not isinstance(ancestry_value, (list, tuple)) or len(ancestry_value) > MAX_PROCESS_ANCESTRY:
        raise EndpointFixtureDenied("PROCESS_ANCESTRY_INVALID")
    if not isinstance(indicators_value, (list, tuple)) or len(indicators_value) > MAX_RELATED_INDICATORS:
        raise EndpointFixtureDenied("RELATED_INDICATORS_INVALID")
    ancestry = tuple(_bounded_text(item, "process_ancestry") for item in ancestry_value)
    indicators = tuple(_bounded_text(item, "related_indicator") for item in indicators_value)
    try:
        audit("endpoint_fixture_normalized", {
            "event_id": event_id, "tenant_id": expected_tenant, "device_id": expected_device,
            "observed_at_epoch": observed, "event_type": event_type, "source": source,
            "evidence_ref": evidence_ref, "mode": "DRY_RUN", "action": "DETECT_ONLY",
        })
    except Exception as exc:
        raise EndpointFixtureDenied("EVIDENCE_WRITE_FAILED") from exc
    return EndpointObservation(event_id, expected_tenant, expected_device, observed, event_type, source, metadata, ancestry, indicators, evidence_ref)
