"""Deterministic context packets and resource admission for FW-HARNESS."""

from __future__ import annotations

import hashlib
import json
import math
import re
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Mapping

from .harness_task import HarnessTask, task_to_record


_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_WORKER = re.compile(r"^[A-Z][A-Z0-9_-]{0,63}$")
_KINDS = frozenset({"requirement", "architecture_constraint", "relevant_file", "dependency_contract", "recent_commit", "task_state", "failed_attempt", "review_finding", "test_failure", "required_interface", "forbidden_change"})


class HarnessContextError(ValueError):
    """Context or budget evidence is malformed, excessive, or unauthorized."""


@dataclass(frozen=True)
class ContextItem:
    kind: str
    reference: str
    content: str


@dataclass(frozen=True)
class ContextPacket:
    schema_version: int
    task_id: str
    requirement_id: str
    items: tuple[ContextItem, ...]
    selected_references: tuple[str, ...]
    byte_count: int
    sha256: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _relative_path(value: str) -> bool:
    path = Path(value)
    return bool(value) and not path.is_absolute() and ".." not in path.parts


def build_context_packet(task: HarnessTask, items: tuple[ContextItem, ...], *, max_items: int = 64, max_bytes: int = 24_000, max_item_bytes: int = 8_000) -> ContextPacket:
    """Build a bounded packet solely from explicit caller-supplied material."""
    if not isinstance(task, HarnessTask):
        raise HarnessContextError("context requires a validated canonical task")
    if not 1 <= max_items <= 256 or not 1 <= max_item_bytes <= max_bytes <= 262_144:
        raise HarnessContextError("context limits are invalid")
    if not items or len(items) > max_items:
        raise HarnessContextError("context item count is outside the approved bound")
    seen: set[tuple[str, str]] = set()
    relevant = set(task.relevant_files)
    forbidden = False
    architecture = False
    normalized: list[ContextItem] = []
    for item in items:
        if not isinstance(item, ContextItem) or item.kind not in _KINDS:
            raise HarnessContextError("context item kind is not allowed")
        if not item.reference.strip() or not item.content.strip():
            raise HarnessContextError("context references and content must be non-empty")
        identity = (item.kind, item.reference)
        if identity in seen:
            raise HarnessContextError("duplicate context selection")
        seen.add(identity)
        if len(item.content.encode("utf-8")) > max_item_bytes:
            raise HarnessContextError("context item exceeds its byte bound")
        if item.kind == "relevant_file" and (not _relative_path(item.reference) or item.reference not in relevant):
            raise HarnessContextError("context file is outside the task relevant-file scope")
        if item.kind == "recent_commit" and not _SHA.fullmatch(item.reference):
            raise HarnessContextError("context commit must be an exact Git hash")
        if item.kind == "requirement" and item.reference != task.requirement_id:
            raise HarnessContextError("context requirement does not match the task")
        if item.kind == "task_state" and item.reference != task.task_id:
            raise HarnessContextError("context task state does not match the task")
        forbidden = forbidden or item.kind == "forbidden_change"
        architecture = architecture or item.kind == "architecture_constraint"
        normalized.append(item)
    if not forbidden or not architecture:
        raise HarnessContextError("context requires architecture constraints and explicit forbidden changes")
    payload = {
        "schema_version": 1,
        "task_id": task.task_id,
        "requirement_id": task.requirement_id,
        "task_record_sha256": hashlib.sha256(_canonical(task_to_record(task))).hexdigest(),
        "items": [asdict(item) for item in normalized],
        "selected_references": [f"{item.kind}:{item.reference}" for item in normalized],
    }
    encoded = _canonical(payload)
    if len(encoded) > max_bytes:
        raise HarnessContextError("context packet exceeds its byte bound")
    digest = hashlib.sha256(encoded).hexdigest()
    return ContextPacket(1, task.task_id, task.requirement_id, tuple(normalized), tuple(payload["selected_references"]), len(encoded), digest)


@dataclass(frozen=True)
class BudgetLimits:
    model_calls: int
    tokens: int
    retries: int
    elapsed_seconds: float
    tool_calls: int = 0
    cost_microunits: int = 0

    def __post_init__(self) -> None:
        values = (self.model_calls, self.tokens, self.retries, self.tool_calls, self.cost_microunits)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in values):
            raise HarnessContextError("budget limits must be non-negative integers")
        if not isinstance(self.elapsed_seconds, (int, float)) or isinstance(self.elapsed_seconds, bool) or not math.isfinite(self.elapsed_seconds) or self.elapsed_seconds < 0:
            raise HarnessContextError("elapsed budget must be finite and non-negative")


@dataclass(frozen=True)
class BudgetUsage:
    model_calls: int = 0
    tokens: int = 0
    retries: int = 0
    elapsed_seconds: float = 0.0
    tool_calls: int = 0
    cost_microunits: int = 0


@dataclass(frozen=True)
class BudgetRequest:
    model_calls: int = 1
    tokens: int = 0
    retries: int = 0
    elapsed_seconds: float = 0.0
    tool_calls: int = 0
    cost_microunits: int = 0

    def __post_init__(self) -> None:
        BudgetLimits(self.model_calls, self.tokens, self.retries, self.elapsed_seconds, self.tool_calls, self.cost_microunits)


@dataclass(frozen=True)
class BudgetAdmission:
    task_id: str
    worker_id: str
    task_usage: BudgetUsage
    session_usage: BudgetUsage


def _add(left: BudgetUsage, right: BudgetRequest) -> BudgetUsage:
    return BudgetUsage(left.model_calls + right.model_calls, left.tokens + right.tokens, left.retries + right.retries, left.elapsed_seconds + right.elapsed_seconds, left.tool_calls + right.tool_calls, left.cost_microunits + right.cost_microunits)


def _exceeded(usage: BudgetUsage, limits: BudgetLimits) -> tuple[str, ...]:
    return tuple(name for name in ("model_calls", "tokens", "retries", "elapsed_seconds", "tool_calls", "cost_microunits") if getattr(usage, name) > getattr(limits, name))


class BudgetLedger:
    """Atomic deterministic admission; exhaustion never partially consumes budget."""

    def __init__(self, session_limits: BudgetLimits, task_limits: Mapping[str, BudgetLimits]):
        if not task_limits or any(not isinstance(key, str) or not key for key in task_limits):
            raise HarnessContextError("task budget registry is required")
        self._session_limits = session_limits
        self._task_limits = MappingProxyType(dict(task_limits))
        self._session_usage = BudgetUsage()
        self._task_usage = {task_id: BudgetUsage() for task_id in task_limits}
        self._lock = threading.Lock()

    def admit(self, task_id: str, worker_id: str, request: BudgetRequest) -> BudgetAdmission:
        if task_id not in self._task_limits or not _WORKER.fullmatch(worker_id) or not isinstance(request, BudgetRequest):
            raise HarnessContextError("budget request identity is not registered")
        with self._lock:
            task_next = _add(self._task_usage[task_id], request)
            session_next = _add(self._session_usage, request)
            task_exceeded = _exceeded(task_next, self._task_limits[task_id])
            session_exceeded = _exceeded(session_next, self._session_limits)
            if task_exceeded or session_exceeded:
                reasons = tuple(f"task:{name}" for name in task_exceeded) + tuple(f"session:{name}" for name in session_exceeded)
                raise HarnessContextError("budget exhausted: " + ",".join(reasons))
            self._task_usage[task_id] = task_next
            self._session_usage = session_next
            return BudgetAdmission(task_id, worker_id, task_next, session_next)

    def snapshot(self) -> Mapping[str, object]:
        with self._lock:
            return MappingProxyType({"session": self._session_usage, "tasks": MappingProxyType(dict(self._task_usage))})
