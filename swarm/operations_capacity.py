"""Bounded FW-OPS capacity and backpressure assessment."""
from __future__ import annotations

import re
from dataclasses import dataclass
from threading import Lock
from typing import Any, Callable

from .operations import OperationalHealthProjection, OperationsContractError


_ID = re.compile(r"^[a-z][a-z0-9_.:/-]{0,191}$")
_EVIDENCE = re.compile(r"^fw-evid/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
MAX_WINDOW = 8


@dataclass(frozen=True)
class CapacityPolicy:
    warning_basis_points: int = 8000
    critical_basis_points: int = 10000
    consecutive_warning_count: int = 2

    def __post_init__(self) -> None:
        values = (self.warning_basis_points, self.critical_basis_points, self.consecutive_warning_count)
        if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
            raise OperationsContractError("capacity policy values must be integers")
        if not 1 <= self.warning_basis_points < self.critical_basis_points <= 10000:
            raise OperationsContractError("capacity thresholds are invalid")
        if not 1 <= self.consecutive_warning_count <= MAX_WINDOW:
            raise OperationsContractError("capacity warning window is invalid")


@dataclass(frozen=True)
class CapacityAssessment:
    assessment_id: str
    tenant_id: str
    pressure: str
    sample_count: int
    consecutive_warning_count: int
    peak_queue_basis_points: int
    peak_budget_basis_points: int
    evidence_reference: str
    assessed_at_epoch: int
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    action: str = "OBSERVE_ONLY"
    throttle_executed: bool = False
    recovery_invoked: bool = False
    authority_granted: bool = False


def _valid_projection(item: OperationalHealthProjection, tenant_id: str) -> bool:
    match = _EVIDENCE.fullmatch(item.evidence_reference) if isinstance(item.evidence_reference, str) else None
    return (
        isinstance(item, OperationalHealthProjection)
        and item.tenant_id == tenant_id
        and item.health in {"HEALTHY", "DEGRADED", "UNHEALTHY"}
        and isinstance(item.assessed_at_epoch, int)
        and not isinstance(item.assessed_at_epoch, bool)
        and item.assessed_at_epoch >= 0
        and isinstance(item.peak_queue_basis_points, int)
        and isinstance(item.peak_budget_basis_points, int)
        and 0 <= item.peak_queue_basis_points <= 10000
        and 0 <= item.peak_budget_basis_points <= 10000
        and item.mode == "DRY_RUN"
        and item.deployment == "DISABLED"
        and item.action == "OBSERVE_ONLY"
        and item.recovery_invoked is False
        and item.authority_granted is False
        and match is not None
        and match.group(1) == tenant_id
    )


class CapacityAssessmentRegistry:
    """Assess supplied canonical projections without mutating capacity."""

    def __init__(self, evidence_sink: Callable[[str, dict[str, Any]], str], policy: CapacityPolicy = CapacityPolicy()) -> None:
        if not callable(evidence_sink) or not isinstance(policy, CapacityPolicy):
            raise OperationsContractError("capacity assessment dependencies are invalid")
        self._evidence = evidence_sink
        self._policy = policy
        self._accepted: set[str] = set()
        self._pending: set[str] = set()
        self._lock = Lock()

    def assess(
        self,
        assessment_id: str,
        tenant_id: str,
        projections: tuple[OperationalHealthProjection, ...],
        *,
        now_epoch: int,
        max_age_seconds: int,
    ) -> CapacityAssessment:
        if (
            not isinstance(assessment_id, str)
            or not _ID.fullmatch(assessment_id)
            or not isinstance(tenant_id, str)
            or not _ID.fullmatch(tenant_id)
            or not isinstance(projections, tuple)
            or not 1 <= len(projections) <= MAX_WINDOW
            or not isinstance(now_epoch, int)
            or isinstance(now_epoch, bool)
            or not isinstance(max_age_seconds, int)
            or isinstance(max_age_seconds, bool)
            or max_age_seconds <= 0
        ):
            raise OperationsContractError("capacity assessment input is malformed or excessive")
        if not all(_valid_projection(item, tenant_id) for item in projections):
            raise OperationsContractError("capacity projection binding is invalid")
        timestamps = [item.assessed_at_epoch for item in projections]
        snapshot_ids = [item.snapshot_id for item in projections]
        if timestamps != sorted(timestamps) or len(timestamps) != len(set(timestamps)) or len(snapshot_ids) != len(set(snapshot_ids)):
            raise OperationsContractError("capacity projection chronology is invalid")
        if timestamps[-1] > now_epoch or now_epoch - timestamps[0] > max_age_seconds:
            raise OperationsContractError("capacity projection window is stale")
        key = f"{tenant_id}:{assessment_id}"
        with self._lock:
            if key in self._accepted or key in self._pending:
                raise OperationsContractError("capacity assessment replay denied")
            self._pending.add(key)
        try:
            warning_run = 0
            longest_warning_run = 0
            critical = False
            for item in projections:
                utilization = max(item.peak_queue_basis_points, item.peak_budget_basis_points)
                if item.health == "UNHEALTHY" or utilization >= self._policy.critical_basis_points:
                    critical = True
                if item.health != "HEALTHY" or utilization >= self._policy.warning_basis_points:
                    warning_run += 1
                    longest_warning_run = max(longest_warning_run, warning_run)
                else:
                    warning_run = 0
            if critical:
                pressure = "CRITICAL"
            elif longest_warning_run >= self._policy.consecutive_warning_count:
                pressure = "SUSTAINED"
            elif longest_warning_run:
                pressure = "ELEVATED"
            else:
                pressure = "NORMAL"
            peak_queue = max(item.peak_queue_basis_points for item in projections)
            peak_budget = max(item.peak_budget_basis_points for item in projections)
            payload = {
                "assessment_id": assessment_id,
                "tenant_id": tenant_id,
                "pressure": pressure,
                "sample_count": len(projections),
                "consecutive_warning_count": longest_warning_run,
                "peak_queue_basis_points": peak_queue,
                "peak_budget_basis_points": peak_budget,
                "assessed_at_epoch": now_epoch,
                "mode": "DRY_RUN",
                "deployment": "DISABLED",
                "action": "OBSERVE_ONLY",
                "throttle_executed": False,
                "recovery_invoked": False,
                "authority_granted": False,
            }
            try:
                reference = self._evidence("fw_ops_capacity_assessed", payload)
            except Exception as exc:
                raise OperationsContractError("capacity Evidence write failed") from exc
            match = _EVIDENCE.fullmatch(reference) if isinstance(reference, str) else None
            if match is None or match.group(1) != tenant_id:
                raise OperationsContractError("capacity Evidence reference is invalid")
            result = CapacityAssessment(
                assessment_id, tenant_id, pressure, len(projections), longest_warning_run,
                peak_queue, peak_budget, reference, now_epoch,
            )
            with self._lock:
                self._accepted.add(key)
            return result
        finally:
            with self._lock:
                self._pending.discard(key)
