"""Authority-free worker registry and invocation contracts for FW-HARNESS."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping

from .harness_context import BudgetAdmission, ContextPacket
from .harness_task import HarnessTask


_IDENTIFIER = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_EXECUTABLE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.+-]{0,127}$")
_SECRET_HANDLE = re.compile(r"^fwkeys://[a-zA-Z0-9_.-]{1,64}/[a-zA-Z0-9_.:/-]{1,192}$")
_ROUTE = re.compile(r"^[a-z][a-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_SECRET_NAMES = re.compile(r"(?i)(api[_-]?key|access[_-]?token|refresh[_-]?token|client[_-]?secret|authorization)")
_SECRET_VALUE = re.compile(r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|ya29\.[a-z0-9._-]{8,})")


class HarnessWorkerError(ValueError):
    """Worker identity, transport, request, or output failed deterministic admission."""


class WorkerTransport(str, Enum):
    CLI = "cli"
    API = "api"


class WorkerRole(str, Enum):
    CODE_WRITER = "code_writer"
    READ_ONLY_REVIEWER = "read_only_reviewer"
    ANALYST = "analyst"


@dataclass(frozen=True)
class WorkerRegistration:
    worker_id: str
    provider: str
    model_id: str
    transport: WorkerTransport
    allowed_roles: tuple[WorkerRole, ...]
    approved: bool
    executable: str | None = None
    route_id: str | None = None
    credential_class: str | None = None
    network_approved: bool = False
    configuration_hash: str | None = None

    def __post_init__(self) -> None:
        if not all(_IDENTIFIER.fullmatch(value) for value in (self.worker_id, self.provider, self.model_id)):
            raise HarnessWorkerError("worker/provider/model identity is malformed")
        if not self.allowed_roles or len(set(self.allowed_roles)) != len(self.allowed_roles) or any(not isinstance(role, WorkerRole) for role in self.allowed_roles):
            raise HarnessWorkerError("worker roles are missing or invalid")
        if self.configuration_hash is not None and not _SHA.fullmatch(self.configuration_hash):
            raise HarnessWorkerError("worker configuration hash is invalid")
        if self.transport == WorkerTransport.CLI:
            if not self.executable or not _EXECUTABLE.fullmatch(self.executable) or self.route_id is not None or self.credential_class is not None or self.network_approved:
                raise HarnessWorkerError("CLI workers require only a registered executable")
        elif self.transport == WorkerTransport.API:
            if self.executable is not None or not self.route_id or not _ROUTE.fullmatch(self.route_id) or not self.credential_class or not _IDENTIFIER.fullmatch(self.credential_class):
                raise HarnessWorkerError("API workers require route and credential-class references")
        else:
            raise HarnessWorkerError("unsupported worker transport")


@dataclass(frozen=True)
class WorkerRequest:
    task: HarnessTask
    context: ContextPacket
    budget: BudgetAdmission
    worker_id: str
    role: WorkerRole
    credential_handle: str | None = None


@dataclass(frozen=True)
class InvocationPlan:
    worker_id: str
    provider: str
    model_id: str
    transport: WorkerTransport
    role: WorkerRole
    task_id: str
    context_sha256: str
    executable: str | None
    route_id: str | None
    credential_handle: str | None
    stdin_contract: str
    environment_keys: tuple[str, ...]
    mutation_allowed: bool
    deployment: str = "DISABLED"


@dataclass(frozen=True)
class WorkerOutput:
    task_id: str
    worker_id: str
    context_sha256: str
    candidate_commit: str | None
    changed_files: tuple[str, ...]
    attempted_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    summary: str


class WorkerRegistry:
    """Immutable exact-identity registry; registration metadata grants no execution."""

    def __init__(self, registrations: tuple[WorkerRegistration, ...]):
        if not registrations or any(not isinstance(item, WorkerRegistration) for item in registrations):
            raise HarnessWorkerError("validated worker registrations are required")
        records = {item.worker_id: item for item in registrations}
        if len(records) != len(registrations):
            raise HarnessWorkerError("worker IDs must be unique")
        self._records = MappingProxyType(records)

    def get(self, worker_id: str) -> WorkerRegistration:
        try:
            return self._records[worker_id]
        except KeyError as exc:
            raise HarnessWorkerError("worker is not registered") from exc

    def snapshot(self) -> Mapping[str, WorkerRegistration]:
        return self._records


def default_cli_registrations(*, codex_model: str, claude_model: str, gemini_model: str) -> tuple[WorkerRegistration, ...]:
    """Return the explicit initial CLI identities; it does not discover executables."""
    return (
        WorkerRegistration("codex-cli", "openai", codex_model, WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex"),
        WorkerRegistration("claude-cli", "anthropic", claude_model, WorkerTransport.CLI, (WorkerRole.READ_ONLY_REVIEWER, WorkerRole.ANALYST), True, executable="claude"),
        WorkerRegistration("gemini-agy", "google", gemini_model, WorkerTransport.CLI, (WorkerRole.READ_ONLY_REVIEWER, WorkerRole.ANALYST), True, executable="agy"),
    )


def plan_invocation(registry: WorkerRegistry, request: WorkerRequest) -> InvocationPlan:
    """Validate an invocation contract without spawning a process or opening a route."""
    if not isinstance(request, WorkerRequest) or not isinstance(request.task, HarnessTask) or not isinstance(request.context, ContextPacket) or not isinstance(request.budget, BudgetAdmission):
        raise HarnessWorkerError("worker request is malformed")
    registration = registry.get(request.worker_id)
    if not registration.approved or request.role not in registration.allowed_roles:
        raise HarnessWorkerError("worker role is not approved")
    if request.task.task_id != request.context.task_id or request.task.requirement_id != request.context.requirement_id or request.task.task_id != request.budget.task_id:
        raise HarnessWorkerError("task, context, and budget bindings do not match")
    if request.budget.worker_id != request.worker_id:
        raise HarnessWorkerError("budget admission is bound to another worker")
    if request.task.assigned_model is not None and request.task.assigned_model != registration.model_id:
        raise HarnessWorkerError("registered model does not match the assigned model")
    if registration.transport == WorkerTransport.CLI:
        if request.credential_handle is not None:
            raise HarnessWorkerError("CLI request cannot carry a credential handle")
        return InvocationPlan(registration.worker_id, registration.provider, registration.model_id, registration.transport, request.role, request.task.task_id, request.context.sha256, registration.executable, None, None, "canonical-context-v1-over-stdin", ("HOME", "PATH", "LANG", "TMPDIR"), request.role == WorkerRole.CODE_WRITER)
    if not registration.network_approved:
        raise HarnessWorkerError("API network route is not approved")
    if request.credential_handle is None or not _SECRET_HANDLE.fullmatch(request.credential_handle):
        raise HarnessWorkerError("API request requires an opaque FW-KEYS handle")
    return InvocationPlan(registration.worker_id, registration.provider, registration.model_id, registration.transport, request.role, request.task.task_id, request.context.sha256, None, registration.route_id, request.credential_handle, "canonical-context-v1-request-body", (), request.role == WorkerRole.CODE_WRITER)


def validate_worker_output(request: WorkerRequest, payload: Mapping[str, Any]) -> WorkerOutput:
    """Treat model output as untrusted and accept only an exact bounded schema."""
    fields = {"task_id", "worker_id", "context_sha256", "candidate_commit", "changed_files", "attempted_actions", "denied_actions", "summary"}
    if not isinstance(payload, Mapping) or set(payload) != fields:
        raise HarnessWorkerError("worker output has an invalid field set")
    if payload["task_id"] != request.task.task_id or payload["worker_id"] != request.worker_id or payload["context_sha256"] != request.context.sha256:
        raise HarnessWorkerError("worker output binding mismatch")
    for field in ("changed_files", "attempted_actions", "denied_actions"):
        if not isinstance(payload[field], (list, tuple)) or len(payload[field]) > 256 or any(not isinstance(value, str) or not value or len(value.encode("utf-8")) > 1000 for value in payload[field]):
            raise HarnessWorkerError(f"worker output {field} is malformed")
    changed = tuple(payload["changed_files"])
    if len(set(changed)) != len(changed) or any(not _relative_in_scope(path, request.task.relevant_files) for path in changed):
        raise HarnessWorkerError("worker changed files escape task scope")
    candidate = payload["candidate_commit"]
    if candidate is not None and (not isinstance(candidate, str) or not _SHA.fullmatch(candidate)):
        raise HarnessWorkerError("worker candidate commit is invalid")
    if not isinstance(payload["summary"], str) or not payload["summary"].strip() or len(payload["summary"].encode("utf-8")) > 4000:
        raise HarnessWorkerError("worker summary is malformed")
    if any(_SECRET_NAMES.search(key) for key in payload):
        raise HarnessWorkerError("credential material is forbidden in worker output")
    text_values = (payload["summary"], *payload["attempted_actions"], *payload["denied_actions"])
    if any(_SECRET_VALUE.search(value) for value in text_values):
        raise HarnessWorkerError("credential-like values are forbidden in worker output")
    return WorkerOutput(request.task.task_id, request.worker_id, request.context.sha256, candidate, changed, tuple(payload["attempted_actions"]), tuple(payload["denied_actions"]), payload["summary"])


def _relative_in_scope(value: str, allowed: tuple[str, ...]) -> bool:
    path = Path(value)
    if not value or path.is_absolute() or ".." in path.parts:
        return False
    return any(path == Path(root) or Path(root) in path.parents for root in allowed)
