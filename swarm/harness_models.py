"""Exact Approved Model Registry admission for FW-HARNESS workers."""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping

from .harness_context import ContextPacket
from .harness_task import HarnessTask
from .harness_worker import WorkerRegistration, WorkerRole


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")


class HarnessModelError(ValueError):
    """The existing model registry did not admit the exact worker binding."""


@dataclass(frozen=True)
class HarnessModelRequest:
    request_id: str
    tenant_id: str
    task_id: str
    subject_agent_id: str
    worker_id: str
    provider: str
    model_id: str
    deployment: str
    model_version: str
    approval_version: str
    role: WorkerRole
    data_classification: str
    tool_permissions: tuple[str, ...]
    context_sha256: str
    context_bytes: int
    token_budget: int
    cost_budget_microunits: int
    fallback_rank: int = 0
    fallback_for: str | None = None


@dataclass(frozen=True)
class HarnessModelAdmission:
    request_id: str
    tenant_id: str
    task_id: str
    subject_agent_id: str
    worker_id: str
    provider: str
    model_id: str
    deployment: str
    model_version: str
    approval_version: str
    role: WorkerRole
    data_classification: str
    tool_permissions: tuple[str, ...]
    context_sha256: str
    context_bytes: int
    token_budget: int
    cost_budget_microunits: int
    fallback_rank: int
    fallback_for: str | None
    registry_evidence_reference: str
    valid_until: int
    reliability_score: float
    reliability_samples: int
    approved: bool = True
    deployment_authority: str = "DISABLED"


_EXTRA_FIELDS = {"registry_evidence_reference", "valid_until", "reliability_score", "reliability_samples", "approved", "deployment_authority"}


def admit_harness_model(
    task: HarnessTask, context: ContextPacket, worker: WorkerRegistration,
    request: HarnessModelRequest, *, now: int,
    model_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]],
    primary_admission: HarnessModelAdmission | None = None,
) -> HarnessModelAdmission:
    """Validate one exact external registry decision without routing a call."""
    if not all(isinstance(value, expected) for value, expected in ((task, HarnessTask), (context, ContextPacket), (worker, WorkerRegistration), (request, HarnessModelRequest))):
        raise HarnessModelError("model admission input is malformed")
    identifiers = (request.request_id, request.tenant_id, request.task_id, request.subject_agent_id, request.worker_id, request.provider, request.model_id, request.deployment, request.model_version, request.approval_version, request.data_classification)
    if any(not isinstance(value, str) or not _ID.fullmatch(value) for value in identifiers) or not isinstance(request.role, WorkerRole):
        raise HarnessModelError("model admission identity is malformed")
    if request.task_id != task.task_id or context.task_id != task.task_id or request.context_sha256 != context.sha256 or request.context_bytes != context.byte_count:
        raise HarnessModelError("task and context binding mismatch")
    assigned_model_matches = task.assigned_model == worker.model_id if request.fallback_rank == 0 else True
    if request.worker_id != worker.worker_id or request.provider != worker.provider or request.model_id != worker.model_id or not assigned_model_matches or request.role not in worker.allowed_roles:
        raise HarnessModelError("worker, provider, model, or role binding mismatch")
    if not isinstance(request.tool_permissions, tuple) or len(request.tool_permissions) > 64 or len(set(request.tool_permissions)) != len(request.tool_permissions) or any(tool not in task.authorized_capabilities for tool in request.tool_permissions):
        raise HarnessModelError("model tool permissions exceed task authority")
    integers = (request.context_bytes, request.token_budget, request.cost_budget_microunits, request.fallback_rank)
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in integers):
        raise HarnessModelError("model resource budget is malformed")
    if request.token_budget > task.token_budget or request.cost_budget_microunits > round(task.cost_budget * 1_000_000):
        raise HarnessModelError("model resource budget exceeds task budget")
    if request.fallback_rank == 0:
        if request.fallback_for is not None or primary_admission is not None:
            raise HarnessModelError("primary model cannot claim fallback metadata")
    else:
        if primary_admission is None or request.fallback_for != primary_admission.request_id or request.fallback_rank != primary_admission.fallback_rank + 1 or task.assigned_model != primary_admission.model_id:
            raise HarnessModelError("fallback requires the preceding exact approved admission")
        stable = ("tenant_id", "task_id", "subject_agent_id", "role", "data_classification", "tool_permissions", "context_sha256", "context_bytes", "token_budget", "cost_budget_microunits")
        if any(getattr(request, field) != getattr(primary_admission, field) for field in stable) or (request.provider, request.model_id) == (primary_admission.provider, primary_admission.model_id):
            raise HarnessModelError("fallback is not an explicit equivalent binding")
    if not callable(model_resolver):
        raise HarnessModelError("Approved Model Registry resolver is unavailable")
    wire = asdict(request)
    wire["role"] = request.role.value
    try:
        decision = model_resolver(wire)
    except Exception as exc:
        raise HarnessModelError("Approved Model Registry resolver failed") from exc
    if not isinstance(decision, Mapping) or set(decision) != set(wire) | _EXTRA_FIELDS:
        raise HarnessModelError("Approved Model Registry decision schema is invalid")
    for field, value in wire.items():
        expected = list(value) if isinstance(value, tuple) else value
        if decision[field] != expected and decision[field] != value:
            raise HarnessModelError("Approved Model Registry decision binding mismatch")
    if decision["approved"] is not True or decision["deployment_authority"] != "DISABLED":
        raise HarnessModelError("model is not approved within the deployment boundary")
    if not isinstance(now, int) or isinstance(now, bool) or not isinstance(decision["valid_until"], int) or isinstance(decision["valid_until"], bool) or decision["valid_until"] <= now:
        raise HarnessModelError("model approval is stale")
    score, samples = decision["reliability_score"], decision["reliability_samples"]
    if not isinstance(score, (int, float)) or isinstance(score, bool) or not math.isfinite(score) or not 0 <= score <= 1 or not isinstance(samples, int) or isinstance(samples, bool) or samples < 0:
        raise HarnessModelError("model reliability metadata is malformed")
    if not isinstance(decision["registry_evidence_reference"], str) or not _REF.fullmatch(decision["registry_evidence_reference"]):
        raise HarnessModelError("model registry Evidence reference is invalid")
    normalized = dict(decision)
    normalized["role"] = WorkerRole(normalized["role"])
    normalized["tool_permissions"] = tuple(normalized["tool_permissions"])
    return HarnessModelAdmission(**normalized)
