"""Bounded read-only Mission Control projection for FW-HARNESS."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from typing import Any, Mapping

from .harness_context import BudgetAdmission, BudgetUsage
from .harness_task import HarnessTask, TaskStatus
from .harness_worker import WorkerRegistration
from .normalized_events import AIWorkloadSecurityEvent
from .ai_agent_defense import AIAttackStory, AIContainmentProposal, AIThreatFinding


_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_SECRET = re.compile(r"(?i)(bearer\s+\S+|sk-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{8,}|ya29\.[A-Za-z0-9._-]{8,}|api[_-]?key\s*[:=]|access[_-]?token\s*[:=]|client[_-]?secret\s*[:=])")


class MissionControlError(ValueError):
    """Canonical harness state cannot be projected safely."""


@dataclass(frozen=True)
class MissionTaskView:
    task_id: str
    requirement_id: str
    title: str
    status: str
    priority: int
    dependencies: tuple[str, ...]
    blocker: str | None
    relevant_files: tuple[str, ...]
    retry_count: int
    retry_limit: int
    resulting_commit: str | None


@dataclass(frozen=True)
class MissionControlView:
    schema_version: int
    tenant_id: str
    phase: str
    current_requirement: str | None
    current_task: str | None
    active_worker: str | None
    active_provider: str | None
    active_model: str | None
    task_queue: tuple[MissionTaskView, ...]
    validation_status: str
    review_status: str
    budget_used: BudgetUsage | None
    recent_decisions: tuple[str, ...]
    current_commit: str | None
    next_task: str | None
    kill_switch: str
    deployment: str = "DISABLED"
    mutation_allowed: bool = False


def serialize_harness_activity(view: MissionControlView | None) -> dict[str, Any]:
    """Serialize a validated, authority-free Harness projection for the console."""
    base = {"schema_version": 1, "safety": {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED"}}
    if view is None:
        return {**base, "data_mode": "EMPTY", "data_label": "NO CANONICAL HARNESS ACTIVITY", "view": None}
    if not isinstance(view, MissionControlView) or view.schema_version != 1 or not _TENANT.fullmatch(view.tenant_id):
        raise MissionControlError("Harness activity projection is malformed")
    if view.mutation_allowed or view.deployment != "DISABLED" or view.kill_switch != "ENGAGED":
        raise MissionControlError("Harness activity safety boundary is invalid")
    if not 1 <= len(view.task_queue) <= 1024 or not all(isinstance(item, MissionTaskView) for item in view.task_queue):
        raise MissionControlError("Harness activity queue is malformed or excessive")
    task_ids = tuple(item.task_id for item in view.task_queue)
    if len(set(task_ids)) != len(task_ids) or any(dependency not in task_ids for item in view.task_queue for dependency in item.dependencies):
        raise MissionControlError("Harness activity dependencies are incomplete")
    if view.current_task is not None and view.current_task not in task_ids:
        raise MissionControlError("Harness activity current task is unknown")
    if view.next_task is not None and view.next_task not in task_ids:
        raise MissionControlError("Harness activity next task is unknown")
    if view.current_commit is not None and not _SHA.fullmatch(view.current_commit):
        raise MissionControlError("Harness activity commit is not exact")
    visible = (
        view.phase, view.validation_status, view.review_status, *view.recent_decisions,
        *(value for item in view.task_queue for value in (item.task_id, item.requirement_id, item.title, item.status, item.blocker or "", *item.dependencies, *item.relevant_files)),
    )
    if len(view.recent_decisions) > 32 or any(not isinstance(value, str) or len(value.encode()) > 1000 or _SECRET.search(value) for value in visible):
        raise MissionControlError("Harness activity is secret-bearing or excessive")
    return {**base, "data_mode": "CANONICAL", "data_label": "CANONICAL READ-ONLY HARNESS ACTIVITY", "view": asdict(view)}


def project_mission_control(
    tasks: tuple[HarnessTask, ...], *, tenant_id: str, task_tenants: Mapping[str, str],
    current_task: str | None, worker: WorkerRegistration | None = None,
    budget: BudgetAdmission | None = None, validation_status: str = "not_started",
    review_status: str = "not_started", recent_decisions: tuple[str, ...] = (),
    current_commit: str | None = None, next_task: str | None = None,
    kill_switch: str = "ENGAGED",
) -> MissionControlView:
    """Create one immutable operator view without changing canonical state."""
    if not _TENANT.fullmatch(tenant_id) or not tasks or len(tasks) > 1024 or any(not isinstance(task, HarnessTask) for task in tasks):
        raise MissionControlError("Mission Control input is malformed or excessive")
    records = {task.task_id: task for task in tasks}
    if len(records) != len(tasks) or set(task_tenants) != set(records) or any(value != tenant_id for value in task_tenants.values()):
        raise MissionControlError("Mission Control task tenancy is incomplete or mismatched")
    if any(dependency not in records for task in tasks for dependency in task.dependencies):
        raise MissionControlError("Mission Control dependency is outside the canonical queue")
    visible_task_text = tuple(value for task in tasks for value in (task.title, task.blocking_reason) if value is not None)
    if any(len(value.encode()) > 1000 or _SECRET.search(value) for value in visible_task_text):
        raise MissionControlError("operator task state is excessive or secret-bearing")
    if current_task is not None and current_task not in records:
        raise MissionControlError("current task is not in the canonical queue")
    if next_task is not None and next_task not in records:
        raise MissionControlError("next task is not in the canonical queue")
    if current_commit is not None and not _SHA.fullmatch(current_commit):
        raise MissionControlError("current commit is not exact")
    if kill_switch != "ENGAGED":
        raise MissionControlError("Mission Control requires the engaged kill switch")
    if budget is not None and (current_task is None or budget.task_id != current_task):
        raise MissionControlError("budget evidence is bound to another task")
    if worker is not None and current_task is None:
        raise MissionControlError("active worker requires a current task")
    active = records.get(current_task) if current_task else None
    if worker is not None and (active is None or active.assigned_model != worker.model_id or (budget is not None and budget.worker_id != worker.worker_id)):
        raise MissionControlError("worker, model, or budget identity does not match the current task")
    text = (validation_status, review_status, *recent_decisions)
    if len(recent_decisions) > 32 or any(not isinstance(value, str) or not value.strip() or len(value.encode()) > 1000 or _SECRET.search(value) for value in text):
        raise MissionControlError("operator status text is malformed, excessive, or secret-bearing")
    queue = tuple(
        MissionTaskView(
            task.task_id, task.requirement_id, task.title, task.status.value, task.priority,
            task.dependencies, task.blocking_reason, task.relevant_files,
            task.retry_count, task.retry_limit, task.resulting_commit,
        )
        for task in sorted(tasks, key=lambda item: (item.priority, item.task_id))
    )
    return MissionControlView(
        1, tenant_id, "ForgeWarden Core", active.requirement_id if active else None,
        current_task, worker.worker_id if worker else None, worker.provider if worker else None,
        worker.model_id if worker else None, queue, validation_status, review_status,
        budget.task_usage if budget else None, recent_decisions, current_commit, next_task,
        kill_switch,
    )


@dataclass(frozen=True)
class AIAgentSecurityView:
    event_id:str; agent_ref:str; model_ref:str; task_ref:str; session_ref:str; lease_ref:str; action_ticket_ref:str; threat_class:str; severity:str; confidence:int; anomalies:tuple[str,...]; decision:str; tool_category:str; mcp_server_ref:str; story_id:str; incident_ids:tuple[str,...]; evidence_references:tuple[str,...]; containment_proposal_id:str|None; containment_action:str|None; containment_state:str

@dataclass(frozen=True)
class AISecurityMissionView:
    schema_version:int; tenant_id:str; data_mode:str; data_label:str; agents:tuple[AIAgentSecurityView,...]; kill_switch:str="ENGAGED"; deployment:str="DISABLED"; mutation_allowed:bool=False

def project_ai_security(*,tenant_id:str,events:tuple[AIWorkloadSecurityEvent,...],findings:tuple[AIThreatFinding,...],stories:tuple[AIAttackStory,...],proposals:tuple[AIContainmentProposal,...]=(),data_mode:str="CANONICAL",kill_switch:str="ENGAGED")->AISecurityMissionView:
    """Project sanitized canonical facts without exposing any control callback."""
    if not _TENANT.fullmatch(tenant_id) or not 1<=len(events)<=128 or not all(isinstance(item,AIWorkloadSecurityEvent) and item.tenant_id==tenant_id for item in events): raise MissionControlError("AI Security events malformed or cross-tenant")
    if data_mode not in {"CANONICAL","DEMO"} or kill_switch!="ENGAGED": raise MissionControlError("AI Security mode or kill switch invalid")
    finding_by_event={item.source_event_id:item for item in findings if isinstance(item,AIThreatFinding) and item.tenant_id==tenant_id}
    story_by_event={item.source_event_id:item for item in stories if isinstance(item,AIAttackStory) and item.tenant_id==tenant_id}
    proposal_by_story={item.story_id:item for item in proposals if isinstance(item,AIContainmentProposal) and item.tenant_id==tenant_id}
    if len(finding_by_event)!=len(findings) or len(story_by_event)!=len(stories) or len(proposal_by_story)!=len(proposals): raise MissionControlError("AI Security facts duplicate, malformed, or cross-tenant")
    rows=[]
    for event in sorted(events,key=lambda item:(item.observed_at_epoch,item.event_id)):
        finding=finding_by_event.get(event.event_id); story=story_by_event.get(event.event_id)
        if finding is None or story is None or finding.finding_id!=story.finding_id or finding.agent_ref!=event.agent_ref or story.model_ref!=event.model_ref or story.task_ref!=event.task_ref: raise MissionControlError("AI Security fact binding incomplete")
        proposal=proposal_by_story.get(story.projection.story_id)
        evidence=tuple(sorted(set(event.evidence_references)|set(finding.evidence_references)|(set() if proposal is None else set(proposal.evidence_references))))
        visible=(event.agent_ref,event.model_ref,event.task_ref,event.session_ref,event.capability_lease_ref,event.action_ticket_ref,event.mcp_server_ref,story.projection.story_id,*evidence,*event.anomaly_indicators)
        if any(_SECRET.search(value) or len(value.encode())>1000 for value in visible): raise MissionControlError("AI Security projection secret-bearing or excessive")
        rows.append(AIAgentSecurityView(event.event_id,event.agent_ref,event.model_ref,event.task_ref,event.session_ref,event.capability_lease_ref,event.action_ticket_ref,finding.threat_class,finding.severity,finding.confidence,event.anomaly_indicators,event.decision,event.tool_category,event.mcp_server_ref,story.projection.story_id,story.projection.incident_ids,evidence,proposal.proposal_id if proposal else None,proposal.action_class if proposal else None,"PROPOSE_ONLY" if proposal else "NONE"))
    if set(finding_by_event)!=set(item.event_id for item in events) or set(story_by_event)!=set(item.event_id for item in events) or any(key not in {item.projection.story_id for item in stories} for key in proposal_by_story): raise MissionControlError("AI Security orphan fact")
    return AISecurityMissionView(1,tenant_id,data_mode,"DEMO / SIMULATED DATA" if data_mode=="DEMO" else "CANONICAL READ-ONLY DATA",tuple(rows),kill_switch)
