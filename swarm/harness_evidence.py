"""Canonical FW-EVID emission seam for governed harness lifecycle facts."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .harness_context import ContextPacket
from .harness_task import HarnessTask
from .harness_worker import WorkerOutput, WorkerRegistration


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@/-]{0,255}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_SECRET = re.compile(r"(?i)(bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{8,}|ya29\.[A-Za-z0-9._-]{8,}|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|refresh[_-]?token\s*[:=]|client[_-]?secret\s*[:=])")
_EVENTS = frozenset({"task_started", "worker_completed", "validation_completed", "review_completed", "task_accepted", "task_denied", "task_checkpointed", "task_recovered"})
_DECISIONS = frozenset({"PENDING", "PASSED", "DENIED", "REPAIR_REQUIRED", "BLOCKED", "ACCEPTED", "REJECTED"})


class HarnessEvidenceError(ValueError):
    """Harness lifecycle facts cannot safely enter canonical Evidence."""


@dataclass(frozen=True)
class HarnessLifecycleEvidence:
    schema_version: int
    event: str
    tenant_id: str
    task_id: str
    requirement_id: str
    actor_id: str
    worker_id: str | None
    provider: str | None
    model_id: str | None
    context_sha256: str
    authorized_capabilities: tuple[str, ...]
    attempted_actions: tuple[str, ...]
    denied_actions: tuple[str, ...]
    changed_files: tuple[str, ...]
    tests_executed: tuple[str, ...]
    test_results: tuple[str, ...]
    reviewer_findings: tuple[str, ...]
    policy_decision: str
    acceptance_decision: str
    timestamp: str
    resulting_commit: str | None
    checkpoint_references: tuple[str, ...]
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    authority_expanded: bool = False


def _bounded(values: tuple[str, ...], field: str, *, paths: bool = False) -> tuple[str, ...]:
    if not isinstance(values, tuple) or len(values) > 256 or len(set(values)) != len(values):
        raise HarnessEvidenceError(f"{field} is malformed or excessive")
    for value in values:
        if not isinstance(value, str) or not value.strip() or len(value.encode()) > 1000 or _SECRET.search(value):
            raise HarnessEvidenceError(f"{field} is malformed, excessive, or secret-bearing")
        if paths:
            path = Path(value)
            if path.is_absolute() or ".." in path.parts:
                raise HarnessEvidenceError(f"{field} escapes its bounded path scope")
    return values


def emit_harness_evidence(
    *, event: str, tenant_id: str, task_tenant_id: str, actor_id: str, task: HarnessTask,
    context: ContextPacket, evidence_sink: Callable[[str, dict[str, Any]], None],
    worker: WorkerRegistration | None = None, worker_output: WorkerOutput | None = None,
    tests_executed: tuple[str, ...] = (), test_results: tuple[str, ...] = (),
    reviewer_findings: tuple[str, ...] = (), policy_decision: str = "PENDING",
    acceptance_decision: str = "PENDING", timestamp: str,
    resulting_commit: str | None = None, checkpoint_references: tuple[str, ...] = (),
) -> HarnessLifecycleEvidence:
    """Validate once, write once, and return only after FW-EVID succeeds."""
    if event not in _EVENTS or not _ID.fullmatch(tenant_id) or task_tenant_id != tenant_id or not _ID.fullmatch(actor_id):
        raise HarnessEvidenceError("lifecycle event, tenant, or actor is invalid")
    if not isinstance(task, HarnessTask) or not isinstance(context, ContextPacket) or context.task_id != task.task_id or context.requirement_id != task.requirement_id:
        raise HarnessEvidenceError("task and context evidence do not match")
    if not callable(evidence_sink):
        raise HarnessEvidenceError("canonical FW-EVID sink is unavailable")
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise HarnessEvidenceError("evidence timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise HarnessEvidenceError("evidence timestamp requires a timezone")
    if policy_decision not in _DECISIONS or acceptance_decision not in _DECISIONS:
        raise HarnessEvidenceError("policy or acceptance decision is unsupported")
    commit = resulting_commit if resulting_commit is not None else task.resulting_commit
    if commit is not None and not _SHA.fullmatch(commit):
        raise HarnessEvidenceError("resulting commit is not exact")
    attempted: tuple[str, ...] = ()
    denied: tuple[str, ...] = ()
    changed: tuple[str, ...] = ()
    if worker is not None and worker.model_id != task.assigned_model:
        raise HarnessEvidenceError("worker model does not match the task")
    if worker_output is not None:
        if worker is None or not isinstance(worker_output, WorkerOutput) or worker_output.task_id != task.task_id or worker_output.worker_id != worker.worker_id or worker_output.context_sha256 != context.sha256:
            raise HarnessEvidenceError("worker lifecycle evidence binding does not match")
        attempted = _bounded(worker_output.attempted_actions, "attempted_actions")
        denied = _bounded(worker_output.denied_actions, "denied_actions")
        changed = _bounded(worker_output.changed_files, "changed_files", paths=True)
        if worker_output.candidate_commit is not None and worker_output.candidate_commit != commit:
            raise HarnessEvidenceError("worker candidate does not match the resulting commit")
        if any(not any(path == root or path.startswith(root.rstrip("/") + "/") for root in task.relevant_files) for path in changed):
            raise HarnessEvidenceError("changed file is outside the task scope")
    capabilities = _bounded(task.authorized_capabilities, "authorized_capabilities")
    evidence = HarnessLifecycleEvidence(
        1, event, tenant_id, task.task_id, task.requirement_id, actor_id,
        worker.worker_id if worker else None, worker.provider if worker else None,
        worker.model_id if worker else None, context.sha256, capabilities, attempted,
        denied, changed, _bounded(tests_executed, "tests_executed"),
        _bounded(test_results, "test_results"), _bounded(reviewer_findings, "reviewer_findings"),
        policy_decision, acceptance_decision, timestamp, commit,
        _bounded(checkpoint_references, "checkpoint_references", paths=True),
    )
    try:
        evidence_sink("fw_harness_lifecycle", asdict(evidence))
    except Exception as exc:
        raise HarnessEvidenceError("canonical FW-EVID write failed") from exc
    return evidence
