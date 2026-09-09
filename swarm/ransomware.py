"""Bounded ransomware activity evaluation over normalized fixture events.

The evaluator consumes caller-supplied in-memory observations only. It has no
filesystem, process, endpoint, network, credential, quarantine, remediation,
recovery, or deployment authority.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .asoc import AuditSink
from .endpoint_fixtures import EndpointObservation

MAX_RANSOM_EVENTS = 128
MAX_RANSOM_WINDOW_SECONDS = 300
_FILE_OPERATIONS = frozenset({"WRITE", "RENAME", "DELETE"})
_STRONG_INDICATORS = frozenset({"EXTENSION_CHANGE", "HIGH_ENTROPY", "RANSOM_NOTE", "SHADOW_COPY_TAMPER"})


class RansomwareEvaluationDenied(PermissionError):
    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


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
