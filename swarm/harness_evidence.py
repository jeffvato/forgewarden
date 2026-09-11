"""Canonical FW-EVID emission seam for governed harness lifecycle facts."""
from __future__ import annotations

import re
import hashlib
import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from .harness_context import ContextPacket
from .harness_task import HarnessTask
from .harness_worker import WorkerOutput, WorkerRegistration
from .evidence import EvidenceContractError, EvidenceEnvelope, EvidenceLedger, EvidenceRecord


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


def harness_lifecycle_payload_sha256(evidence: HarnessLifecycleEvidence) -> str:
    """Hash the exact validated lifecycle payload with canonical JSON encoding."""
    validate_harness_lifecycle_evidence(evidence)
    encoded = json.dumps(asdict(evidence), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return hashlib.sha256(encoded).hexdigest()


def validate_harness_lifecycle_evidence(evidence: HarnessLifecycleEvidence) -> HarnessLifecycleEvidence:
    """Revalidate a lifecycle value before it crosses a producer boundary."""
    if not isinstance(evidence, HarnessLifecycleEvidence):
        raise HarnessEvidenceError("validated HarnessLifecycleEvidence is required")
    if evidence.schema_version != 1 or evidence.event not in _EVENTS:
        raise HarnessEvidenceError("lifecycle schema or event is invalid")
    if not _ID.fullmatch(evidence.tenant_id) or not _ID.fullmatch(evidence.task_id) or not _ID.fullmatch(evidence.requirement_id) or not _ID.fullmatch(evidence.actor_id):
        raise HarnessEvidenceError("lifecycle identity binding is invalid")
    try:
        parsed = datetime.fromisoformat(evidence.timestamp.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as exc:
        raise HarnessEvidenceError("evidence timestamp is invalid") from exc
    if parsed.tzinfo is None:
        raise HarnessEvidenceError("evidence timestamp requires a timezone")
    if evidence.policy_decision not in _DECISIONS or evidence.acceptance_decision not in _DECISIONS:
        raise HarnessEvidenceError("policy or acceptance decision is unsupported")
    if evidence.resulting_commit is not None and not _SHA.fullmatch(evidence.resulting_commit):
        raise HarnessEvidenceError("resulting commit is not exact")
    for field in ("authorized_capabilities", "attempted_actions", "denied_actions", "tests_executed", "test_results", "reviewer_findings"):
        _bounded(getattr(evidence, field), field)
    _bounded(evidence.changed_files, "changed_files", paths=True)
    _bounded(evidence.checkpoint_references, "checkpoint_references", paths=True)
    if evidence.mode != "DRY_RUN" or evidence.deployment != "DISABLED" or evidence.authority_expanded is not False:
        raise HarnessEvidenceError("harness Evidence cannot grant authority")
    return evidence


def append_harness_evidence(
    evidence: HarnessLifecycleEvidence, *, ledger: EvidenceLedger,
    classification: str = "INTERNAL", correlation_id: str | None = None,
    evidence_references: tuple[str, ...] = (),
) -> EvidenceRecord:
    """Bind one exact harness lifecycle fact to the tenant's canonical ledger."""
    validated = validate_harness_lifecycle_evidence(evidence)
    if not isinstance(ledger, EvidenceLedger) or ledger.tenant_id != validated.tenant_id:
        raise HarnessEvidenceError("canonical ledger tenant does not match lifecycle Evidence")
    prior = ledger.tenant_snapshot(validated.tenant_id)
    previous = prior[-1].record_sha256 if prior else None
    payload_sha256 = harness_lifecycle_payload_sha256(validated)
    envelope = EvidenceEnvelope(
        schema_version="1",
        evidence_id=f"fw-evid/{validated.tenant_id}/harness/{validated.task_id.lower()}/{validated.event}/{payload_sha256[:16]}",
        tenant_id=validated.tenant_id,
        event_type=f"harness.{validated.event}",
        actor_ref=f"fw-id/{validated.actor_id}",
        actor_tenant_id=validated.tenant_id,
        subject_ref=f"fw-task/{validated.task_id.lower()}",
        subject_tenant_id=validated.tenant_id,
        occurred_at=validated.timestamp,
        classification=classification,
        payload_schema_id="fw-schema/harness/lifecycle/v1",
        payload_sha256=payload_sha256,
        previous_record_sha256=previous,
        correlation_id=correlation_id,
        evidence_references=evidence_references,
        mode="DRY_RUN",
        deployment="DISABLED",
        authority_granted=False,
    )
    try:
        return ledger.append(envelope)
    except EvidenceContractError as exc:
        raise HarnessEvidenceError("canonical harness Evidence admission failed") from exc


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
    validate_harness_lifecycle_evidence(evidence)
    try:
        evidence_sink("fw_harness_lifecycle", asdict(evidence))
    except Exception as exc:
        raise HarnessEvidenceError("canonical FW-EVID write failed") from exc
    return evidence
