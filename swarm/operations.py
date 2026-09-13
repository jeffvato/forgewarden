"""Canonical tenant-bound read-only operational health projection."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from threading import Lock
from typing import Any, Callable, Mapping, Sequence

from .policy_gate import PolicyInvariantError, validate_safety_evidence


class OperationsContractError(ValueError):
    """Operational facts cannot be projected safely."""


_COMPONENT_STATES = frozenset({"HEALTHY", "DEGRADED", "UNHEALTHY", "UNAVAILABLE"})
_FIELDS = frozenset({
    "schema_version", "snapshot_id", "tenant_id", "observed_at_epoch",
    "expires_at_epoch", "components", "mode", "deployment", "kill_switch",
})
_COMPONENT_FIELDS = frozenset({
    "component_id", "tenant_id", "state", "queue_depth", "queue_limit",
    "budget_used", "budget_limit",
})
_ID = re.compile(r"^[a-z][a-z0-9_.:/-]{0,191}$")
_EVIDENCE = re.compile(r"^fw-evid/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
_SECRET = re.compile(
    r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|"
    r"ya29\.[a-z0-9._-]{8,}|api[_-]?key\s*[:=]|(?:access|refresh)[_-]?"
    r"token\s*[:=]|client[_-]?secret\s*[:=]|password\s*[:=]|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----)"
)
MAX_COMPONENTS = 32


def _text(value: Any, field: str, maximum: int = 192) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value.encode("utf-8")) > maximum
        or _SECRET.search(value)
    ):
        raise OperationsContractError(f"{field} is invalid or secret-bearing")
    return value


def _counter(value: Any, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise OperationsContractError(f"{field} is invalid")
    return value


@dataclass(frozen=True)
class OperationalComponentObservation:
    component_id: str
    tenant_id: str
    state: str
    queue_depth: int
    queue_limit: int
    budget_used: int
    budget_limit: int

    def __post_init__(self) -> None:
        if not _ID.fullmatch(_text(self.component_id, "component_id")):
            raise OperationsContractError("component_id is invalid")
        if not _ID.fullmatch(_text(self.tenant_id, "tenant_id", 128)):
            raise OperationsContractError("tenant_id is invalid")
        if self.state not in _COMPONENT_STATES:
            raise OperationsContractError("component state is invalid")
        for field in ("queue_depth", "queue_limit", "budget_used", "budget_limit"):
            _counter(getattr(self, field), field)
        if self.queue_limit <= 0 or self.budget_limit <= 0:
            raise OperationsContractError("operational limits must be positive")
        if self.queue_depth > self.queue_limit or self.budget_used > self.budget_limit:
            raise OperationsContractError("operational usage exceeds declared limit")


@dataclass(frozen=True)
class OperationalHealthSnapshot:
    schema_version: str
    snapshot_id: str
    tenant_id: str
    observed_at_epoch: int
    expires_at_epoch: int
    components: tuple[OperationalComponentObservation, ...]
    mode: str
    deployment: str
    kill_switch: str

    def __post_init__(self) -> None:
        if self.schema_version != "1":
            raise OperationsContractError("unsupported operations schema version")
        if not _ID.fullmatch(_text(self.snapshot_id, "snapshot_id")):
            raise OperationsContractError("snapshot_id is invalid")
        if not _ID.fullmatch(_text(self.tenant_id, "tenant_id", 128)):
            raise OperationsContractError("tenant_id is invalid")
        if (
            not isinstance(self.observed_at_epoch, int)
            or isinstance(self.observed_at_epoch, bool)
            or not isinstance(self.expires_at_epoch, int)
            or isinstance(self.expires_at_epoch, bool)
            or self.observed_at_epoch < 0
            or self.expires_at_epoch <= self.observed_at_epoch
        ):
            raise OperationsContractError("snapshot lifetime is invalid")
        if (
            not isinstance(self.components, tuple)
            or not 1 <= len(self.components) <= MAX_COMPONENTS
            or not all(isinstance(item, OperationalComponentObservation) for item in self.components)
        ):
            raise OperationsContractError("component observations are malformed or excessive")
        ids = [item.component_id for item in self.components]
        if len(ids) != len(set(ids)):
            raise OperationsContractError("component observations contain duplicates")
        if any(item.tenant_id != self.tenant_id for item in self.components):
            raise OperationsContractError("cross-tenant component observation denied")
        try:
            validate_safety_evidence(
                {"mode": self.mode, "deployment": self.deployment, "kill_switch": self.kill_switch},
                require_kill_switch=True,
            )
        except PolicyInvariantError as exc:
            raise OperationsContractError("operations safety state is invalid") from exc


@dataclass(frozen=True)
class OperationalHealthProjection:
    snapshot_id: str
    tenant_id: str
    health: str
    component_count: int
    healthy_count: int
    degraded_count: int
    unhealthy_count: int
    unavailable_count: int
    peak_queue_basis_points: int
    peak_budget_basis_points: int
    evidence_reference: str
    assessed_at_epoch: int
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    action: str = "OBSERVE_ONLY"
    recovery_invoked: bool = False
    authority_granted: bool = False


def validate_operational_snapshot(value: Mapping[str, Any]) -> OperationalHealthSnapshot:
    """Validate an exact untrusted version-1 snapshot."""
    if not isinstance(value, Mapping) or set(value) != _FIELDS:
        raise OperationsContractError("operations snapshot field set is invalid")
    raw_components = value["components"]
    if not isinstance(raw_components, Sequence) or isinstance(raw_components, (str, bytes)):
        raise OperationsContractError("component observations are malformed")
    components: list[OperationalComponentObservation] = []
    for item in raw_components:
        if not isinstance(item, Mapping) or set(item) != _COMPONENT_FIELDS:
            raise OperationsContractError("component observation field set is invalid")
        components.append(OperationalComponentObservation(**{field: item[field] for field in _COMPONENT_FIELDS}))
    return OperationalHealthSnapshot(
        schema_version=value["schema_version"],
        snapshot_id=value["snapshot_id"],
        tenant_id=value["tenant_id"],
        observed_at_epoch=value["observed_at_epoch"],
        expires_at_epoch=value["expires_at_epoch"],
        components=tuple(components),
        mode=value["mode"],
        deployment=value["deployment"],
        kill_switch=value["kill_switch"],
    )


def _basis_points(used: int, limit: int) -> int:
    return (used * 10_000) // limit


class OperationalHealthRegistry:
    """Evidence-first, create-once projection registry with no control authority."""

    def __init__(self, evidence_sink: Callable[[str, dict[str, Any]], str]) -> None:
        if not callable(evidence_sink):
            raise OperationsContractError("canonical Evidence sink is required")
        self._evidence = evidence_sink
        self._accepted: set[str] = set()
        self._pending: set[str] = set()
        self._lock = Lock()

    def project(self, snapshot: OperationalHealthSnapshot, *, tenant_id: str, now_epoch: int) -> OperationalHealthProjection:
        if (
            not isinstance(snapshot, OperationalHealthSnapshot)
            or tenant_id != snapshot.tenant_id
            or not isinstance(now_epoch, int)
            or isinstance(now_epoch, bool)
        ):
            raise OperationsContractError("operational projection binding is invalid")
        if not snapshot.observed_at_epoch <= now_epoch < snapshot.expires_at_epoch:
            raise OperationsContractError("operational snapshot is stale or expired")
        key = f"{snapshot.tenant_id}:{snapshot.snapshot_id}"
        with self._lock:
            if key in self._accepted or key in self._pending:
                raise OperationsContractError("operational snapshot replay denied")
            self._pending.add(key)
        try:
            counts = {state: sum(item.state == state for item in snapshot.components) for state in _COMPONENT_STATES}
            peak_queue = max(_basis_points(item.queue_depth, item.queue_limit) for item in snapshot.components)
            peak_budget = max(_basis_points(item.budget_used, item.budget_limit) for item in snapshot.components)
            if counts["UNHEALTHY"] or peak_queue >= 10_000 or peak_budget >= 10_000:
                health = "UNHEALTHY"
            elif counts["DEGRADED"] or counts["UNAVAILABLE"] or peak_queue >= 8_000 or peak_budget >= 8_000:
                health = "DEGRADED"
            else:
                health = "HEALTHY"
            payload = {
                "snapshot_id": snapshot.snapshot_id,
                "tenant_id": snapshot.tenant_id,
                "health": health,
                "component_count": len(snapshot.components),
                "component_states": {key.lower(): counts[key] for key in sorted(counts)},
                "peak_queue_basis_points": peak_queue,
                "peak_budget_basis_points": peak_budget,
                "assessed_at_epoch": now_epoch,
                "mode": "DRY_RUN",
                "deployment": "DISABLED",
                "action": "OBSERVE_ONLY",
                "recovery_invoked": False,
                "authority_granted": False,
            }
            try:
                evidence_reference = self._evidence("fw_ops_health_projected", payload)
            except Exception as exc:
                raise OperationsContractError("operations Evidence write failed") from exc
            match = _EVIDENCE.fullmatch(evidence_reference) if isinstance(evidence_reference, str) else None
            if match is None or match.group(1) != snapshot.tenant_id:
                raise OperationsContractError("operations Evidence reference is invalid")
            result = OperationalHealthProjection(
                snapshot.snapshot_id,
                snapshot.tenant_id,
                health,
                len(snapshot.components),
                counts["HEALTHY"],
                counts["DEGRADED"],
                counts["UNHEALTHY"],
                counts["UNAVAILABLE"],
                peak_queue,
                peak_budget,
                evidence_reference,
                now_epoch,
            )
            with self._lock:
                self._accepted.add(key)
            return result
        finally:
            with self._lock:
                self._pending.discard(key)
