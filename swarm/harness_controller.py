"""Composition root for the accepted governed FW-HARNESS interfaces."""
from __future__ import annotations

from dataclasses import dataclass, replace
from typing import Any, Callable, Mapping

from .autonomous_loop import AutonomousOrchestrator, TaskSpec, WorkerLease, WorkerResult
from .harness_authority import HarnessAuthorityRequest, admit_harness_authority
from .harness_context import BudgetLedger, BudgetRequest, ContextItem, ContextPacket, build_context_packet
from .harness_evidence import emit_harness_evidence
from .harness_models import HarnessModelRequest, admit_harness_model
from .harness_task import HarnessTask, TaskStatus
from .harness_worker import WorkerOutput, WorkerRegistry, WorkerRequest, WorkerRole, plan_identity_bound_invocation, validate_worker_output
from .identity import DelegatedProviderIdentity, IdentityRegistry
from .mission_control import MissionControlView, project_mission_control
from .review_handoff import ReviewResult


class HarnessControllerError(RuntimeError):
    """The integrated lifecycle cannot safely continue."""


@dataclass(frozen=True)
class TaskExecution:
    context_items: tuple[ContextItem, ...]
    budget_request: BudgetRequest
    worker_id: str
    role: WorkerRole
    authority_request: HarnessAuthorityRequest
    model_request: HarnessModelRequest
    provider_binding: DelegatedProviderIdentity | None = None
    credential_handle: str | None = None


@dataclass(frozen=True)
class HarnessRunResult:
    durable_state: Mapping[str, Any]
    mission_control: MissionControlView


class GovernedHarnessController:
    """Use the existing durable scheduler while composing accepted gates."""

    def __init__(
        self, *, orchestrator: AutonomousOrchestrator, tasks: tuple[HarnessTask, ...],
        task_tenants: Mapping[str, str], executions: Mapping[str, TaskExecution],
        workers: WorkerRegistry, budgets: BudgetLedger,
        identity_registry: IdentityRegistry,
        authority_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        model_resolver: Callable[[Mapping[str, Any]], Mapping[str, Any]],
        evidence_sink: Callable[[str, dict[str, Any]], None], timestamp: Callable[[], str],
    ) -> None:
        self.orchestrator = orchestrator
        self.tasks = {task.task_id: task for task in tasks}
        if not tasks or len(self.tasks) != len(tasks) or set(self.tasks) != set(executions) or set(self.tasks) != set(task_tenants):
            raise HarnessControllerError("controller task, execution, and tenant registries must match")
        self.task_tenants, self.executions, self.workers, self.budgets, self.identity_registry = dict(task_tenants), dict(executions), workers, budgets, identity_registry
        self.authority_resolver, self.model_resolver, self.evidence_sink, self.timestamp = authority_resolver, model_resolver, evidence_sink, timestamp
        self._packets: dict[str, ContextPacket] = {}
        self._outputs: dict[str, WorkerOutput] = {}

    def run(
        self, *, worker_executor: Callable[[Any], Mapping[str, Any]],
        validator: Callable[[HarnessTask, WorkerOutput], bool],
        committer: Callable[[HarnessTask, WorkerOutput], str],
        reviewer: Callable[[HarnessTask, str], ReviewResult],
        max_steps: int | None = None, authorized: Callable[[], bool] | None = None,
    ) -> HarnessRunResult:
        def dispatch(spec: TaskSpec, lease: WorkerLease) -> WorkerResult:
            task, execution = self.tasks[spec.task_id], self.executions[spec.task_id]
            packet = build_context_packet(task, execution.context_items)
            budget = self.budgets.admit(task.task_id, execution.worker_id, execution.budget_request)
            worker = self.workers.get(execution.worker_id)
            admit_harness_authority(task, worker, execution.authority_request, now=int(lease.expires_at - self.orchestrator.lease_seconds), authority_resolver=self.authority_resolver)
            admit_harness_model(task, packet, worker, execution.model_request, now=int(lease.expires_at - self.orchestrator.lease_seconds), model_resolver=self.model_resolver)
            request = WorkerRequest(task, packet, budget, execution.worker_id, execution.role, execution.credential_handle)
            plan = plan_identity_bound_invocation(self.workers, request, identity_registry=self.identity_registry, tenant_id=self.task_tenants[task.task_id], now_epoch=int(lease.expires_at - self.orchestrator.lease_seconds), provider_binding=execution.provider_binding)
            emit_harness_evidence(event="task_started", tenant_id=self.task_tenants[task.task_id], task_tenant_id=self.task_tenants[task.task_id], actor_id="harness-controller", task=task, context=packet, evidence_sink=self.evidence_sink, worker=worker, policy_decision="PASSED", acceptance_decision="PENDING", timestamp=self.timestamp())
            output = validate_worker_output(request, worker_executor(plan))
            emit_harness_evidence(event="worker_completed", tenant_id=self.task_tenants[task.task_id], task_tenant_id=self.task_tenants[task.task_id], actor_id="harness-controller", task=task, context=packet, evidence_sink=self.evidence_sink, worker=worker, worker_output=output, policy_decision="PASSED", acceptance_decision="PENDING", timestamp=self.timestamp())
            self._packets[task.task_id], self._outputs[task.task_id] = packet, output
            return WorkerResult(None, output.changed_files, task.validation_requirements)

        def validate(spec: TaskSpec, _result: WorkerResult) -> bool:
            task, output, packet = self.tasks[spec.task_id], self._outputs[spec.task_id], self._packets[spec.task_id]
            passed = validator(task, output)
            emit_harness_evidence(event="validation_completed", tenant_id=self.task_tenants[task.task_id], task_tenant_id=self.task_tenants[task.task_id], actor_id="harness-controller", task=task, context=packet, evidence_sink=self.evidence_sink, worker=self.workers.get(self.executions[task.task_id].worker_id), worker_output=output, tests_executed=task.validation_requirements, test_results=("PASSED" if passed else "FAILED",), policy_decision="PASSED" if passed else "DENIED", acceptance_decision="PENDING", timestamp=self.timestamp())
            return passed

        def commit(spec: TaskSpec, _result: WorkerResult) -> str:
            return committer(self.tasks[spec.task_id], self._outputs[spec.task_id])

        def review(spec: TaskSpec, candidate: str, _lease: WorkerLease) -> Mapping[str, ReviewResult]:
            task, packet, output = self.tasks[spec.task_id], self._packets[spec.task_id], self._outputs[spec.task_id]
            result = reviewer(task, candidate)
            emit_harness_evidence(event="review_completed", tenant_id=self.task_tenants[task.task_id], task_tenant_id=self.task_tenants[task.task_id], actor_id="harness-controller", task=task, context=packet, evidence_sink=self.evidence_sink, worker=self.workers.get(self.executions[task.task_id].worker_id), worker_output=output, reviewer_findings=(f"{result.role}:{result.disposition}:{result.severity}",), policy_decision="PASSED", acceptance_decision="PENDING", timestamp=self.timestamp(), resulting_commit=candidate)
            return {result.role: result}

        def accepted(spec: TaskSpec, candidate: str) -> None:
            task, packet, output = self.tasks[spec.task_id], self._packets[spec.task_id], self._outputs[spec.task_id]
            emit_harness_evidence(event="task_accepted", tenant_id=self.task_tenants[task.task_id], task_tenant_id=self.task_tenants[task.task_id], actor_id="harness-controller", task=task, context=packet, evidence_sink=self.evidence_sink, worker=self.workers.get(self.executions[task.task_id].worker_id), worker_output=output, tests_executed=task.validation_requirements, test_results=("PASSED",), policy_decision="PASSED", acceptance_decision="ACCEPTED", timestamp=self.timestamp(), resulting_commit=candidate)

        state = self.orchestrator.run(dispatch=dispatch, validate=validate, commit=commit, review=review, max_steps=max_steps, authorized=authorized, accepted=accepted)
        projected: list[HarnessTask] = []
        for task_id, task in self.tasks.items():
            record = state["queued_tasks"][task_id]
            if record["state"] == "DONE":
                projected.append(replace(task, status=TaskStatus.COMPLETED, completed_at=self.timestamp(), resulting_commit=record["resulting_commit"]))
            elif record["state"] == "FAILED":
                projected.append(replace(task, status=TaskStatus.REJECTED, completed_at=self.timestamp()))
            else:
                projected.append(task)
        next_ready = next((item.task_id for item in sorted(projected, key=lambda value: (value.priority, value.task_id)) if state["queued_tasks"][item.task_id]["state"] == "READY"), None)
        view = project_mission_control(tuple(projected), tenant_id=next(iter(self.task_tenants.values())), task_tenants=self.task_tenants, current_task=None, validation_status=str(state.get("acceptance_result") or "not_started"), review_status="complete" if state.get("reviewer_result") else "not_started", recent_decisions=(str(state["next_action"]),), current_commit=state.get("repository_head_after"), next_task=next_ready)
        return HarnessRunResult(state, view)
