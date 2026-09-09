"""Narrow FW-HARNESS adapter for existing deterministic authority decisions."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Mapping

from .harness_task import HarnessTask
from .harness_worker import WorkerRegistration, WorkerRole


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,511}$")


class HarnessAuthorityError(ValueError):
    """Existing authority did not admit the exact harness request."""


class HarnessOperation(str, Enum):
    READ = "read"
    WRITE = "write"


@dataclass(frozen=True)
class HarnessAuthorityRequest:
    request_id: str
    tenant_id: str
    task_id: str
    agent_id: str
    worker_id: str
    provider: str
    model_id: str
    capability: str
    resource: str
    operation: HarnessOperation
    requested_tokens: int
    policy_version: str
    action_ticket_reference: str | None = None


@dataclass(frozen=True)
class HarnessAuthorityAdmission:
    request_id: str
    tenant_id: str
    task_id: str
    agent_id: str
    worker_id: str
    provider: str
    model_id: str
    lease_id: str
    capability: str
    resource: str
    operation: HarnessOperation
    expires_at: int
    policy_version: str
    evidence_reference: str
    action_ticket_reference: str | None
    ticket_consumed: bool
    requested_tokens: int
    admitted: bool = True
    kill_switch: str = "ENGAGED"
    deployment: str = "DISABLED"
    authority_expanded: bool = False


_DECISION_FIELDS = {
    "request_id", "tenant_id", "task_id", "agent_id", "worker_id", "provider", "model_id", "lease_id",
    "capability", "resource", "operation", "expires_at", "policy_version",
    "evidence_reference", "action_ticket_reference", "ticket_consumed",
    "requested_tokens", "admitted", "kill_switch", "deployment", "authority_expanded",
}


def _in_scope(resource: str, roots: tuple[str, ...]) -> bool:
    path = Path(resource)
    return bool(resource) and not path.is_absolute() and ".." not in path.parts and any(path == Path(root) or Path(root) in path.parents for root in roots)


def admit_harness_authority(
    task: HarnessTask, worker: WorkerRegistration, request: HarnessAuthorityRequest, *, now: int,
    authority_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]],
) -> HarnessAuthorityAdmission:
    """Validate a canonical ASOC/ROOT decision; never issue or store authority."""
    if not isinstance(task, HarnessTask) or not isinstance(worker, WorkerRegistration) or not isinstance(request, HarnessAuthorityRequest):
        raise HarnessAuthorityError("harness authority request is malformed")
    scalar_ids = (request.request_id, request.tenant_id, request.agent_id, request.worker_id, request.provider, request.model_id, request.capability, request.policy_version)
    if any(not isinstance(value, str) or not _ID.fullmatch(value) for value in scalar_ids) or not isinstance(request.operation, HarnessOperation):
        raise HarnessAuthorityError("harness authority identity is malformed")
    if not isinstance(now, int) or isinstance(now, bool) or now < 0 or not isinstance(request.requested_tokens, int) or isinstance(request.requested_tokens, bool) or request.requested_tokens < 0:
        raise HarnessAuthorityError("harness authority time or budget is malformed")
    if request.task_id != task.task_id or request.worker_id != worker.worker_id or request.provider != worker.provider or request.model_id != worker.model_id or task.assigned_model != worker.model_id:
        raise HarnessAuthorityError("task, worker, provider, or model binding mismatch")
    if request.capability not in task.authorized_capabilities or not _in_scope(request.resource, task.relevant_files):
        raise HarnessAuthorityError("requested capability or resource exceeds task scope")
    if request.requested_tokens > task.token_budget:
        raise HarnessAuthorityError("requested token budget exceeds task scope")
    mutating = request.operation == HarnessOperation.WRITE
    capability_mutates = request.capability.endswith((".write", ".mutate", ".execute"))
    if mutating != capability_mutates:
        raise HarnessAuthorityError("operation does not match the bounded capability class")
    if mutating and WorkerRole.CODE_WRITER not in worker.allowed_roles:
        raise HarnessAuthorityError("read-only worker cannot request mutation")
    if mutating and (not request.action_ticket_reference or not _REFERENCE.fullmatch(request.action_ticket_reference)):
        raise HarnessAuthorityError("mutating work requires an Action Ticket reference")
    if not mutating and request.action_ticket_reference is not None:
        raise HarnessAuthorityError("read-only work cannot consume an Action Ticket")
    if not callable(authority_resolver):
        raise HarnessAuthorityError("canonical authority resolver is unavailable")
    try:
        decision = authority_resolver(asdict(request))
    except Exception as exc:
        raise HarnessAuthorityError("canonical authority resolver failed") from exc
    if not isinstance(decision, Mapping) or set(decision) != _DECISION_FIELDS:
        raise HarnessAuthorityError("canonical authority decision schema is invalid")
    expected = asdict(request)
    expected["operation"] = request.operation.value
    for field in ("request_id", "tenant_id", "task_id", "agent_id", "worker_id", "provider", "model_id", "capability", "resource", "operation", "policy_version", "action_ticket_reference", "requested_tokens"):
        if decision[field] != expected[field]:
            raise HarnessAuthorityError("canonical authority decision binding mismatch")
    if decision["admitted"] is not True or decision["kill_switch"] != "ENGAGED" or decision["deployment"] != "DISABLED" or decision["authority_expanded"] is not False:
        raise HarnessAuthorityError("canonical authority decision violates safety state")
    if not isinstance(decision["lease_id"], str) or not _REFERENCE.fullmatch(decision["lease_id"]) or not isinstance(decision["evidence_reference"], str) or not _REFERENCE.fullmatch(decision["evidence_reference"]):
        raise HarnessAuthorityError("lease or Evidence reference is invalid")
    if not isinstance(decision["expires_at"], int) or isinstance(decision["expires_at"], bool) or decision["expires_at"] <= now:
        raise HarnessAuthorityError("authority lease is expired")
    if type(decision["ticket_consumed"]) is not bool or decision["ticket_consumed"] is not mutating:
        raise HarnessAuthorityError("Action Ticket consumption does not match the operation")
    try:
        return HarnessAuthorityAdmission(**{**dict(decision), "operation": HarnessOperation(decision["operation"])})
    except (TypeError, ValueError) as exc:
        raise HarnessAuthorityError("canonical authority decision is invalid") from exc
