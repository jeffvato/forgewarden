"""Bounded caller-supplied FW-ASM metadata contracts.

This module performs no discovery, DNS lookup, scan, connection, cloud query,
certificate retrieval, or response action.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any, Callable, Mapping


MAX_ASM_FIXTURE_BYTES = 32 * 1024
_TEXT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/@+-]{0,255}$")
_TENANT = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_OWNER_REF = re.compile(
    r"^fw-(asset|exposure|evid)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/+-]{0,191}$"
)
_ASSET_TYPES = frozenset({
    "API", "CLOUD_RESOURCE", "DATABASE", "DEVELOPMENT_SYSTEM", "DOMAIN",
    "PUBLIC_IP", "REMOTE_ACCESS", "VPN_ENDPOINT", "WEBSITE",
})
_SERVICES = frozenset({"API", "DATABASE", "DNS", "HTTP", "REMOTE_ACCESS", "VPN"})
_PROTOCOLS = frozenset({"DNS", "HTTP", "HTTPS", "RDP", "SSH", "TCP", "TLS", "UDP", "VPN"})
_OWNERSHIP = frozenset({"KNOWN", "UNKNOWN"})
_VISIBILITY = frozenset({"PUBLIC", "RESTRICTED", "UNEXPECTED"})
_REQUIRED = frozenset({
    "event_id", "tenant_id", "observed_at_epoch", "asset_type", "asset_ref",
    "exposure_ref", "service", "protocol", "port", "ownership_state",
    "visibility_state", "evidence_ref",
})


class AttackSurfaceObservationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _TEXT.fullmatch(value):
        raise AttackSurfaceObservationDenied(f"{field}_INVALID")
    return value


def _owner_ref(value: Any, kind: str, tenant_id: str, field: str) -> str:
    match = _OWNER_REF.fullmatch(value) if isinstance(value, str) else None
    if match is None or match.group(1) != kind or match.group(2) != tenant_id:
        raise AttackSurfaceObservationDenied(f"{field}_INVALID")
    return value


@dataclass(frozen=True)
class AttackSurfaceObservation:
    event_id: str
    tenant_id: str
    observed_at_epoch: int
    asset_type: str
    asset_ref: str
    exposure_ref: str
    service: str
    protocol: str
    port: int
    ownership_state: str
    visibility_state: str
    evidence_ref: str
    trust: str = "UNTRUSTED_DATA"
    mode: str = "DRY_RUN"
    action: str = "DETECT_ONLY"
    authority_granted: bool = False


def normalize_attack_surface_observation(
    fixture: Mapping[str, Any], *, tenant_id: str, now_epoch: int,
    audit: Callable[[str, dict[str, Any]], None],
) -> AttackSurfaceObservation:
    """Validate one exact external-asset fixture and record Evidence first."""
    if not isinstance(fixture, Mapping) or not callable(audit):
        raise AttackSurfaceObservationDenied("FIXTURE_INVALID")
    try:
        encoded = json.dumps(fixture, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise AttackSurfaceObservationDenied("FIXTURE_INVALID") from exc
    if len(encoded) > MAX_ASM_FIXTURE_BYTES or set(fixture) != _REQUIRED:
        raise AttackSurfaceObservationDenied("FIXTURE_INVALID")
    if not isinstance(tenant_id, str) or not _TENANT.fullmatch(tenant_id):
        raise AttackSurfaceObservationDenied("TENANT_INVALID")
    if fixture.get("tenant_id") != tenant_id:
        raise AttackSurfaceObservationDenied("TENANT_MISMATCH")
    observed = fixture.get("observed_at_epoch")
    if (
        not isinstance(observed, int) or isinstance(observed, bool)
        or not isinstance(now_epoch, int) or isinstance(now_epoch, bool)
        or observed < 0 or observed > now_epoch
    ):
        raise AttackSurfaceObservationDenied("OBSERVED_AT_INVALID")
    asset_type, service = fixture.get("asset_type"), fixture.get("service")
    protocol, ownership = fixture.get("protocol"), fixture.get("ownership_state")
    visibility, port = fixture.get("visibility_state"), fixture.get("port")
    if asset_type not in _ASSET_TYPES:
        raise AttackSurfaceObservationDenied("ASSET_TYPE_INVALID")
    if service not in _SERVICES:
        raise AttackSurfaceObservationDenied("SERVICE_INVALID")
    if protocol not in _PROTOCOLS:
        raise AttackSurfaceObservationDenied("PROTOCOL_INVALID")
    if ownership not in _OWNERSHIP:
        raise AttackSurfaceObservationDenied("OWNERSHIP_STATE_INVALID")
    if visibility not in _VISIBILITY:
        raise AttackSurfaceObservationDenied("VISIBILITY_STATE_INVALID")
    if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
        raise AttackSurfaceObservationDenied("PORT_INVALID")
    event_id = _text(fixture.get("event_id"), "EVENT_ID")
    asset_ref = _owner_ref(fixture.get("asset_ref"), "asset", tenant_id, "ASSET_REF")
    exposure_ref = _owner_ref(fixture.get("exposure_ref"), "exposure", tenant_id, "EXPOSURE_REF")
    evidence_ref = _owner_ref(fixture.get("evidence_ref"), "evid", tenant_id, "EVIDENCE_REF")
    try:
        audit("attack_surface_observation_normalized", {
            "event_id": event_id, "tenant_id": tenant_id,
            "observed_at_epoch": observed, "asset_type": asset_type,
            "service": service, "protocol": protocol, "port": port,
            "ownership_state": ownership, "visibility_state": visibility,
            "evidence_ref": evidence_ref, "trust": "UNTRUSTED_DATA",
            "mode": "DRY_RUN", "action": "DETECT_ONLY",
            "deployment": "DISABLED", "response_executed": False,
            "authority_granted": False,
        })
    except Exception as exc:
        raise AttackSurfaceObservationDenied("EVIDENCE_WRITE_FAILED") from exc
    return AttackSurfaceObservation(
        event_id, tenant_id, observed, asset_type, asset_ref, exposure_ref,
        service, protocol, port, ownership, visibility, evidence_ref,
    )
