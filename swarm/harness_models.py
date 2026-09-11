"""Exact Approved Model Registry admission for FW-HARNESS workers."""
from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from typing import Any, Callable, Mapping

from .harness_context import ContextPacket
from .harness_risk import AssuranceTier, RiskDecision
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


@dataclass(frozen=True)
class ApprovedModelCandidate:
    """Bounded projection supplied by the existing Approved Model Registry."""
    candidate_id: str
    tenant_id: str
    provider: str
    model_id: str
    environment: str
    assurance_tier: AssuranceTier
    allowed_roles: tuple[WorkerRole, ...]
    allowed_data_classifications: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    estimated_cost_microunits: int
    registry_evidence_reference: str
    approved: bool
    available: bool

    def __post_init__(self) -> None:
        scalars = (self.candidate_id, self.tenant_id, self.provider, self.model_id,
                   self.environment, self.registry_evidence_reference)
        if any(not isinstance(value, str) or not _ID.fullmatch(value) for value in scalars):
            raise HarnessModelError("registry candidate identity is malformed")
        if not isinstance(self.assurance_tier, AssuranceTier):
            raise HarnessModelError("registry candidate tier is malformed")
        for values, maximum, name in (
            (self.allowed_roles, 8, "roles"),
            (self.allowed_data_classifications, 16, "data classes"),
            (self.allowed_tools, 64, "tools"),
        ):
            if not isinstance(values, tuple) or not values or len(values) > maximum or len(set(values)) != len(values):
                raise HarnessModelError(f"registry candidate {name} are malformed")
        if any(not isinstance(role, WorkerRole) for role in self.allowed_roles):
            raise HarnessModelError("registry candidate roles are malformed")
        if any(not isinstance(value, str) or not _ID.fullmatch(value)
               for value in self.allowed_data_classifications + self.allowed_tools):
            raise HarnessModelError("registry candidate constraints are malformed")
        if type(self.estimated_cost_microunits) is not int or self.estimated_cost_microunits < 0:
            raise HarnessModelError("registry candidate cost is malformed")
        if type(self.approved) is not bool or type(self.available) is not bool:
            raise HarnessModelError("registry candidate state is malformed")


@dataclass(frozen=True)
class ModelRoute:
    task_id: str
    tenant_id: str
    candidate_id: str
    provider: str
    model_id: str
    environment: str
    assurance_tier: AssuranceTier
    required_tier: AssuranceTier
    estimated_cost_microunits: int
    registry_evidence_reference: str
    fallback: bool
    invocation_authorized: bool = False
    deployment_authority: str = "DISABLED"


_NO_MODEL = "NO_APPROVED_MODEL_AVAILABLE_FOR_REQUIRED_ASSURANCE_LEVEL"


def route_approved_model(
    risk: RiskDecision,
    candidates: tuple[ApprovedModelCandidate, ...],
    *,
    task_id: str,
    tenant_id: str,
    role: WorkerRole,
    data_classification: str,
    required_tools: tuple[str, ...],
    environment: str,
    failed_candidate_ids: tuple[str, ...] = (),
) -> ModelRoute:
    """Select registry metadata only; provider invocation remains separately gated."""
    if not isinstance(risk, RiskDecision) or risk.task_id != task_id or risk.tenant_id != tenant_id:
        raise HarnessModelError("risk decision binding mismatch")
    if (risk.disposition != "CLASSIFIED" or risk.human_authorization_required
            or risk.tier is AssuranceTier.T4):
        raise HarnessModelError("risk decision does not permit model routing")
    if not isinstance(role, WorkerRole) or not _ID.fullmatch(data_classification) or not _ID.fullmatch(environment):
        raise HarnessModelError("routing constraints are malformed")
    if (not isinstance(required_tools, tuple) or len(required_tools) > 64
            or len(set(required_tools)) != len(required_tools)
            or any(not isinstance(tool, str) or not _ID.fullmatch(tool) for tool in required_tools)):
        raise HarnessModelError("required tools are malformed")
    if (not isinstance(candidates, tuple) or not candidates or len(candidates) > 128
            or any(not isinstance(item, ApprovedModelCandidate) for item in candidates)
            or len({item.candidate_id for item in candidates}) != len(candidates)):
        raise HarnessModelError("registry candidate set is malformed")
    if (not isinstance(failed_candidate_ids, tuple)
            or len(set(failed_candidate_ids)) != len(failed_candidate_ids)
            or any(value not in {item.candidate_id for item in candidates}
                   for value in failed_candidate_ids)):
        raise HarnessModelError("failed candidate set is malformed")
    required = set(required_tools)
    eligible = [
        item for item in candidates
        if item.approved and item.available and item.candidate_id not in failed_candidate_ids
        and item.tenant_id == tenant_id and item.environment == environment
        and item.assurance_tier >= risk.tier and role in item.allowed_roles
        and data_classification in item.allowed_data_classifications
        and required.issubset(item.allowed_tools)
    ]
    if not eligible:
        raise HarnessModelError(_NO_MODEL)
    selected = min(eligible, key=lambda item: (
        item.estimated_cost_microunits, int(item.assurance_tier), item.candidate_id
    ))
    return ModelRoute(
        task_id, tenant_id, selected.candidate_id, selected.provider,
        selected.model_id, selected.environment, selected.assurance_tier,
        risk.tier, selected.estimated_cost_microunits,
        selected.registry_evidence_reference, bool(failed_candidate_ids),
    )
