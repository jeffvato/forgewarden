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
from .asoc import MUTATING_ACTIONS, READ_ONLY_ACTIONS
from .evidence import EvidenceContractError, EvidenceEnvelope, EvidenceRecord, evidence_record_sha256, validate_evidence_envelope
from .action_ticket import ActionTicket, ActionTicketError
from .policy_gate import PolicyContext, PolicyDecision, PolicyInvariantError
from .harness_models import ApprovedModelCandidate, HarnessModelError
from .mcp_gateway import MCPGatewayError, MCPGatewaySafetyState, MCPToolCatalogEntry
from .soc import SOCAttackStoryProjection, SOCDryRunLifecycle, SOCIncidentProjection, SOCIncidentTimeline, SOCPlaybookProposal, SOCPlaybookStep, SOCTimelineEntry
from .operations import OperationalHealthProjection
from .operations_capacity import CapacityAssessment
from .recovery import ResumeAdmission, ResumeAdmissionDecision
from .saas_security import SaaSDryRunLifecycle


_TENANT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-fA-F]{40,64}$")
_OPS_EVIDENCE = re.compile(r"^fw-evid/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")
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


@dataclass(frozen=True)
class PolicyTicketActivity:
    """Read-only binding of one canonical policy result to an optional ticket."""

    context: PolicyContext
    decision: PolicyDecision
    ticket: ActionTicket | None
    observed_at_epoch: int
    kill_switch: str = "ENGAGED"
    deployment: str = "DISABLED"
    mutation_allowed: bool = False


@dataclass(frozen=True)
class ModelMCPActivity:
    """Read-only canonical registry/catalog facts for operator visibility."""

    tenant_id: str
    models: tuple[ApprovedModelCandidate, ...]
    tools: tuple[MCPToolCatalogEntry, ...]
    gateway_safety: MCPGatewaySafetyState
    kill_switch: str = "ENGAGED"
    deployment: str = "DISABLED"
    mutation_allowed: bool = False


def serialize_model_mcp_activity(activity: ModelMCPActivity | None) -> dict[str, Any]:
    """Serialize model and MCP metadata without routing or tool execution authority."""
    base = {"schema_version": 1, "safety": {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED", "model_invoked": False, "tool_executed": False}}
    if activity is None:
        return {**base, "data_mode": "EMPTY", "data_label": "NO CANONICAL MODEL OR MCP ACTIVITY", "view": None}
    if (
        not isinstance(activity, ModelMCPActivity) or not _TENANT.fullmatch(activity.tenant_id)
        or not isinstance(activity.models, tuple) or not 1 <= len(activity.models) <= 128
        or not isinstance(activity.tools, tuple) or len(activity.tools) > 128
        or not isinstance(activity.gateway_safety, MCPGatewaySafetyState)
        or activity.gateway_safety.health_state != "HEALTHY" or activity.gateway_safety.kill_switch_state != "ENGAGED"
        or activity.kill_switch != "ENGAGED" or activity.deployment != "DISABLED" or activity.mutation_allowed
    ):
        raise MissionControlError("model and MCP activity is malformed or unsafe")
    try:
        models = tuple(ApprovedModelCandidate(**asdict(item)) for item in activity.models)
        tools = tuple(MCPToolCatalogEntry(**asdict(item)) for item in activity.tools)
    except (HarnessModelError, MCPGatewayError, TypeError) as exc:
        raise MissionControlError("model or MCP canonical reconstruction failed") from exc
    if models != activity.models or tools != activity.tools:
        raise MissionControlError("model or MCP canonical reconstruction mismatch")
    if any(item.tenant_id != activity.tenant_id for item in models + tools):
        raise MissionControlError("model or MCP activity crosses tenants")
    if len({item.candidate_id for item in models}) != len(models) or len({item.tool for item in tools}) != len(tools):
        raise MissionControlError("model or MCP activity contains duplicate identities")
    visible = tuple(value for item in models for value in (item.candidate_id, item.provider, item.model_id, item.environment, item.registry_evidence_reference, *item.allowed_data_classifications, *item.allowed_tools)) + tuple(value for item in tools for value in (item.tool, item.capability, item.trust_level))
    if any(len(value.encode()) > 1000 or _SECRET.search(value) for value in visible):
        raise MissionControlError("model or MCP activity is secret-bearing or excessive")
    return {
        **base, "data_mode": "CANONICAL", "data_label": "CANONICAL READ-ONLY MODEL BROKER AND MCP ACTIVITY",
        "view": {"tenant_id": activity.tenant_id, "gateway_health": "HEALTHY", "gateway_kill_switch": "ENGAGED",
                 "models": tuple({"candidate_id": item.candidate_id, "provider": item.provider, "model_id": item.model_id,
                                  "environment": item.environment, "assurance_tier": item.assurance_tier.name,
                                  "registry_evidence_reference": item.registry_evidence_reference,
                                  "approval_status": "APPROVED" if item.approved else "UNAPPROVED",
                                  "availability": "AVAILABLE" if item.available else "UNAVAILABLE",
                                  "invocation_authorized": False} for item in models),
                 "tools": tuple({"tool": item.tool, "capability": item.capability, "trust_level": item.trust_level,
                                 "enabled": item.enabled, "lease_status": "NOT_PRESENT", "tool_executed": False} for item in tools),
                 "mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED",
                 "model_invoked": False, "tool_executed": False},
    }


def serialize_policy_ticket_activity(activity: PolicyTicketActivity | None) -> dict[str, Any]:
    """Explain canonical policy/ticket facts without evaluating or consuming them."""
    base = {"schema_version": 1, "safety": {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED", "ticket_consumed": False}}
    if activity is None:
        return {**base, "data_mode": "EMPTY", "data_label": "NO CANONICAL POLICY OR TICKET ACTIVITY", "view": None}
    if (
        not isinstance(activity, PolicyTicketActivity)
        or not isinstance(activity.context, PolicyContext)
        or not isinstance(activity.decision, PolicyDecision)
        or not isinstance(activity.observed_at_epoch, int)
        or isinstance(activity.observed_at_epoch, bool)
        or activity.observed_at_epoch < 0
        or activity.kill_switch != "ENGAGED"
        or activity.deployment != "DISABLED"
        or activity.mutation_allowed
    ):
        raise MissionControlError("policy and ticket activity is malformed or unsafe")
    context, decision, ticket = activity.context, activity.decision, activity.ticket
    try:
        if PolicyContext(**asdict(context)) != context or PolicyDecision(**asdict(decision)) != decision:
            raise MissionControlError("policy activity canonical reconstruction failed")
        if ticket is not None and ActionTicket(**asdict(ticket)) != ticket:
            raise MissionControlError("Action Ticket canonical reconstruction failed")
    except (ActionTicketError, PolicyInvariantError, TypeError) as exc:
        raise MissionControlError("policy or Action Ticket activity is invalid") from exc
    visible = (context.tenant_id, context.subject_agent_id, context.capability, context.resource, context.action_class, context.policy_version, decision.reason)
    if any(len(value.encode()) > 1000 or _SECRET.search(value) for value in visible):
        raise MissionControlError("policy and ticket activity is secret-bearing or excessive")
    ticket_view = None
    if decision.allowed:
        if not isinstance(ticket, ActionTicket):
            raise MissionControlError("allowed policy activity requires a canonical Action Ticket")
        if (
            ticket.tenant_id != context.tenant_id
            or ticket.subject_agent_id != context.subject_agent_id
            or ticket.capability != context.capability
            or ticket.resource != context.resource
            or ticket.action_class != context.action_class
            or ticket.policy_version != context.policy_version
            or not ticket.signature
            or ticket.consumed_at is not None
            or not ticket.issued_at <= activity.observed_at_epoch < ticket.expires_at
        ):
            raise MissionControlError("Action Ticket binding, signature presence, expiry, or usage state is invalid")
        ticket_text = (ticket.ticket_id, ticket.lease_id, ticket.issued_by, ticket.approval_reference, ticket.key_reference, ticket.signature)
        if any(len(value.encode()) > 1000 or _SECRET.search(value) for value in ticket_text):
            raise MissionControlError("Action Ticket activity is secret-bearing or excessive")
        ticket_view = {
            "ticket_id": ticket.ticket_id, "tenant_id": ticket.tenant_id, "subject_agent_id": ticket.subject_agent_id,
            "lease_id": ticket.lease_id, "capability": ticket.capability, "resource": ticket.resource,
            "action_class": ticket.action_class, "issued_by": ticket.issued_by, "approval_reference": ticket.approval_reference,
            "policy_version": ticket.policy_version, "issued_at": ticket.issued_at, "expires_at": ticket.expires_at,
            "key_reference": ticket.key_reference, "signature_status": "PRESENT_NOT_VERIFIED", "usage_status": "UNCONSUMED",
        }
    elif ticket is not None:
        raise MissionControlError("denied policy activity cannot expose an Action Ticket")
    return {
        **base, "data_mode": "CANONICAL", "data_label": "CANONICAL READ-ONLY POLICY AND ACTION TICKET",
        "view": {"tenant_id": context.tenant_id, "subject_agent_id": context.subject_agent_id, "capability": context.capability,
                 "resource": context.resource, "action_class": context.action_class, "policy_version": context.policy_version,
                 "decision": "ALLOW" if decision.allowed else "DENY", "reason": decision.reason,
                 "observed_at_epoch": activity.observed_at_epoch, "ticket": ticket_view,
                 "mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED", "ticket_consumed": False},
    }


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


def serialize_incident_activity(lifecycle: SOCDryRunLifecycle | None) -> dict[str, Any]:
    """Serialize canonical FW-SOC reference facts without adding case authority."""
    base = {
        "schema_version": 1,
        "safety": {
            "mutation_allowed": False,
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "response_executed": False,
        },
    }
    if lifecycle is None:
        return {**base, "data_mode": "EMPTY", "data_label": "NO CANONICAL INCIDENT ACTIVITY", "view": None}
    if not isinstance(lifecycle, SOCDryRunLifecycle):
        raise MissionControlError("incident activity projection is malformed")
    if (
        lifecycle.mode != "DRY_RUN"
        or lifecycle.deployment != "DISABLED"
        or lifecycle.kill_switch != "ENGAGED"
        or lifecycle.authority_expanded
        or not 2 <= len(lifecycle.incidents) <= 32
    ):
        raise MissionControlError("incident activity safety boundary is invalid")

    incidents = lifecycle.incidents
    tenant_ids = {item.tenant_id for item in incidents if isinstance(item, SOCIncidentProjection)}
    if len(tenant_ids) != 1 or len(incidents) != sum(isinstance(item, SOCIncidentProjection) for item in incidents):
        raise MissionControlError("incident activity tenancy is malformed")
    tenant_id = next(iter(tenant_ids))
    if not _TENANT.fullmatch(tenant_id):
        raise MissionControlError("incident activity tenant is malformed")
    incident_ids = tuple(item.incident_id for item in incidents)
    if len(set(incident_ids)) != len(incident_ids):
        raise MissionControlError("incident activity contains duplicate incidents")
    for item in incidents:
        if (
            item.trust != "UNTRUSTED_CASE_FACT"
            or item.mode != "DRY_RUN"
            or item.action != "RECORD_ONLY"
            or not item.affected_refs
            or not item.normalized_event_refs
            or not item.evidence_refs
            or len(item.affected_refs) > 64
            or len(item.normalized_event_refs) > 64
            or len(item.evidence_refs) > 64
            or item.severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
            or item.status not in {"OPEN", "TRIAGED", "INVESTIGATING", "RESOLVED", "CLOSED"}
            or item.disposition not in {"NONE", "TRUE_POSITIVE", "FALSE_POSITIVE", "MITIGATED", "ACCEPTED_RISK"}
            or (item.status in {"OPEN", "TRIAGED", "INVESTIGATING"}) != (item.disposition == "NONE")
            or not isinstance(item.created_at_epoch, int)
            or isinstance(item.created_at_epoch, bool)
            or not isinstance(item.updated_at_epoch, int)
            or isinstance(item.updated_at_epoch, bool)
            or not 0 <= item.created_at_epoch <= item.updated_at_epoch
            or any(len(set(refs)) != len(refs) for refs in (item.affected_refs, item.normalized_event_refs, item.evidence_refs))
        ):
            raise MissionControlError("incident activity contains unsafe case facts")

    story, timeline, playbook = lifecycle.attack_story, lifecycle.timeline, lifecycle.playbook
    if (
        not isinstance(story, SOCAttackStoryProjection)
        or not isinstance(timeline, SOCIncidentTimeline)
        or not isinstance(playbook, SOCPlaybookProposal)
        or story.tenant_id != tenant_id
        or story.trust != "UNTRUSTED_CASE_FACT"
        or story.mode != "DRY_RUN"
        or story.action != "CORRELATE_ONLY"
        or set(story.incident_ids) != set(incident_ids)
        or len(story.incident_ids) != len(incident_ids)
        or story.severity not in {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        or not isinstance(story.first_seen_epoch, int)
        or isinstance(story.first_seen_epoch, bool)
        or not isinstance(story.last_seen_epoch, int)
        or isinstance(story.last_seen_epoch, bool)
        or not 0 <= story.first_seen_epoch <= story.last_seen_epoch
        or timeline.tenant_id != tenant_id
        or timeline.incident_id not in set(incident_ids)
        or timeline.trust != "UNTRUSTED_CASE_FACT"
        or timeline.mode != "DRY_RUN"
        or timeline.action != "PROJECT_ONLY"
        or not 1 <= len(timeline.entries) <= 128
        or playbook.tenant_id != tenant_id
        or playbook.incident_id != timeline.incident_id
        or playbook.mode != "DRY_RUN"
        or playbook.deployment != "DISABLED"
        or playbook.kill_switch != "ENGAGED"
        or playbook.authority_expanded
        or playbook.action != "PROPOSE_ONLY"
        or not 1 <= len(playbook.steps) <= 32
    ):
        raise MissionControlError("incident activity lifecycle binding is invalid")

    primary = next(item for item in incidents if item.incident_id == timeline.incident_id)
    ordered_entries = tuple(sorted(timeline.entries, key=lambda item: (item.occurred_at_epoch, item.entry_id)))
    if timeline.entries != ordered_entries or len({item.entry_id for item in timeline.entries}) != len(timeline.entries):
        raise MissionControlError("incident activity chronology is invalid")
    if any(
        not isinstance(item, SOCTimelineEntry)
        or item.tenant_id != tenant_id
        or item.incident_id != primary.incident_id
        or not primary.created_at_epoch <= item.occurred_at_epoch <= primary.updated_at_epoch
        for item in timeline.entries
    ):
        raise MissionControlError("incident activity timeline binding is invalid")
    completed: set[str] = set()
    for step in playbook.steps:
        if (
            not isinstance(step, SOCPlaybookStep)
            or any(dependency not in completed for dependency in step.depends_on)
            or step.step_id in completed
            or step.action_class not in READ_ONLY_ACTIONS | MUTATING_ACTIONS
            or (step.action_class in MUTATING_ACTIONS and None in (step.approval_ref, step.action_ticket_ref, step.checkpoint_ref, step.rollback_ref))
            or (step.action_class in READ_ONLY_ACTIONS and any(value is not None for value in (step.approval_ref, step.action_ticket_ref, step.checkpoint_ref, step.rollback_ref)))
        ):
            raise MissionControlError("incident activity playbook dependency is invalid")
        completed.add(step.step_id)

    visible = tuple(
        value
        for value in (
            tenant_id,
            story.story_id,
            *(value for item in incidents for value in (item.incident_id, item.title, *item.affected_refs, *item.normalized_event_refs, *item.evidence_refs)),
            *(value for item in timeline.entries for value in (item.entry_id, item.actor_ref, item.source_ref, item.evidence_ref)),
            *(value for item in playbook.steps for value in (item.step_id, item.capability, item.resource_ref, item.policy_decision_ref, item.approval_ref or "", item.action_ticket_ref or "", item.checkpoint_ref or "", item.rollback_ref or "")),
        )
    )
    if any(not isinstance(value, str) or len(value.encode()) > 1000 or _SECRET.search(value) for value in visible):
        raise MissionControlError("incident activity is secret-bearing or excessive")
    return {
        **base,
        "data_mode": "CANONICAL",
        "data_label": "CANONICAL READ-ONLY INCIDENT ACTIVITY",
        "view": {
            "tenant_id": tenant_id,
            "primary_incident_id": primary.incident_id,
            "incidents": [asdict(item) for item in incidents],
            "attack_story": asdict(story),
            "timeline": asdict(timeline),
            "response_proposal": asdict(playbook),
            "mutation_allowed": False,
            "deployment": "DISABLED",
            "kill_switch": "ENGAGED",
            "response_executed": False,
        },
    }


def serialize_evidence_activity(records: tuple[EvidenceRecord, ...] | None) -> dict[str, Any]:
    """Project an already-admitted FW-EVID chain without append or signing authority."""
    base = {"schema_version": 1, "safety": {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED", "signing_performed": False}}
    if records is None or records == ():
        return {**base, "data_mode": "EMPTY", "data_label": "NO CANONICAL EVIDENCE ACTIVITY", "view": None}
    if not isinstance(records, tuple) or not 1 <= len(records) <= 256 or not all(isinstance(item, EvidenceRecord) for item in records):
        raise MissionControlError("Evidence activity projection is malformed or excessive")
    tenant_id = records[0].envelope.tenant_id
    if not _TENANT.fullmatch(tenant_id):
        raise MissionControlError("Evidence activity tenant is malformed")
    previous: str | None = None
    evidence_ids: set[str] = set()
    record_hashes: set[str] = set()
    projected: list[dict[str, Any]] = []
    for position, record in enumerate(records, start=1):
        envelope = record.envelope
        try:
            validated = validate_evidence_envelope(asdict(envelope)) if isinstance(envelope, EvidenceEnvelope) else None
        except EvidenceContractError as exc:
            raise MissionControlError("Evidence activity envelope is invalid or secret-bearing") from exc
        if (
            validated != envelope
            or envelope.tenant_id != tenant_id
            or envelope.actor_tenant_id != tenant_id
            or envelope.subject_tenant_id != tenant_id
            or envelope.previous_record_sha256 != previous
            or record.record_sha256 != evidence_record_sha256(envelope)
            or envelope.evidence_id in evidence_ids
            or record.record_sha256 in record_hashes
            or envelope.mode != "DRY_RUN"
            or envelope.deployment != "DISABLED"
            or envelope.authority_granted
        ):
            raise MissionControlError("Evidence activity chain or authority binding is invalid")
        visible = (envelope.evidence_id, envelope.event_type, envelope.actor_ref, envelope.subject_ref, envelope.payload_schema_id, envelope.correlation_id or "", *envelope.evidence_references)
        if any(len(value.encode()) > 1000 or _SECRET.search(value) for value in visible):
            raise MissionControlError("Evidence activity is secret-bearing or excessive")
        projected.append({
            "position": position, "evidence_id": envelope.evidence_id, "occurred_at": envelope.occurred_at,
            "event_type": envelope.event_type, "actor_ref": envelope.actor_ref, "subject_ref": envelope.subject_ref,
            "classification": envelope.classification, "payload_schema_id": envelope.payload_schema_id,
            "payload_sha256": envelope.payload_sha256, "record_sha256": record.record_sha256,
            "previous_record_sha256": envelope.previous_record_sha256, "correlation_id": envelope.correlation_id,
            "evidence_references": envelope.evidence_references,
        })
        evidence_ids.add(envelope.evidence_id)
        record_hashes.add(record.record_sha256)
        previous = record.record_sha256
    return {
        **base, "data_mode": "CANONICAL", "data_label": "CANONICAL FW-EVID · DIGEST AND CHAIN VALIDATED",
        "view": {"tenant_id": tenant_id, "record_count": len(projected), "head_record_sha256": previous,
                 "chain_status": "DIGEST_AND_CHAIN_VALIDATED", "signature_status": "NOT_PRESENT",
                 "verification_scope": "LOCAL_CANONICAL_ENVELOPE_AND_CHAIN", "records": tuple(projected),
                 "mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED", "signing_performed": False},
    }


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


@dataclass(frozen=True)
class SaaSSecurityMissionView:
    schema_version: int
    tenant_id: str
    event_id: str
    provider: str
    confidence: str
    signals: tuple[str, ...]
    soc_incident_ref: str
    aid_finding_ref: str
    proposal_action: str
    proposal_state: str
    target_ref: str
    policy_decision_ref: str
    action_ticket_ref: str
    evidence_refs: tuple[str, ...]
    data_mode: str = "CANONICAL"
    data_label: str = "CANONICAL READ-ONLY SAAS SECURITY LIFECYCLE"
    kill_switch: str = "ENGAGED"
    deployment: str = "DISABLED"
    mutation_allowed: bool = False
    response_executed: bool = False


def project_saas_security(
    lifecycle: SaaSDryRunLifecycle, *, tenant_id: str,
    data_mode: str = "CANONICAL",
) -> SaaSSecurityMissionView:
    """Project one canonical SaaS lifecycle without provider or ticket authority."""
    if not isinstance(lifecycle, SaaSDryRunLifecycle) or not _TENANT.fullmatch(tenant_id):
        raise MissionControlError("SaaS lifecycle malformed")
    observation = lifecycle.observation
    finding = lifecycle.finding
    correlation = lifecycle.correlation
    proposal = lifecycle.proposal
    if (
        data_mode not in {"CANONICAL", "DEMO"}
        or lifecycle.mode != "DRY_RUN"
        or lifecycle.deployment != "DISABLED"
        or lifecycle.kill_switch != "ENGAGED"
        or lifecycle.authority_granted
        or lifecycle.response_executed
        or any(item.tenant_id != tenant_id for item in (observation, finding, correlation, proposal))
        or len({item.event_id for item in (observation, finding, correlation, proposal)}) != 1
        or finding.provider != observation.provider
        or correlation.provider != finding.provider
        or correlation.confidence != finding.confidence
        or correlation.signals != finding.signals
        or proposal.soc_incident_ref != correlation.soc_incident_ref
        or proposal.aid_finding_ref != correlation.aid_finding_ref
        or observation.mode != "DRY_RUN" or observation.action != "DETECT_ONLY"
        or finding.mode != "DRY_RUN" or finding.action != "DETECT_ONLY"
        or correlation.mode != "DRY_RUN" or correlation.action != "CORRELATE_ONLY"
        or proposal.mode != "DRY_RUN" or proposal.disposition != "PROPOSE_ONLY"
        or proposal.deployment != "DISABLED" or proposal.kill_switch != "ENGAGED"
        or proposal.authority_granted or proposal.response_executed
    ):
        raise MissionControlError("SaaS lifecycle binding or authority invalid")
    visible = (
        observation.event_id, observation.provider, *finding.signals,
        correlation.soc_incident_ref, correlation.aid_finding_ref,
        proposal.target_ref, proposal.policy_decision_ref,
        proposal.action_ticket_ref, *correlation.evidence_refs,
    )
    if any(not isinstance(value, str) or len(value.encode()) > 1000 or _SECRET.search(value) for value in visible):
        raise MissionControlError("SaaS lifecycle secret-bearing or excessive")
    return SaaSSecurityMissionView(
        1, tenant_id, observation.event_id, observation.provider,
        finding.confidence, finding.signals, correlation.soc_incident_ref,
        correlation.aid_finding_ref, proposal.action_class, proposal.disposition,
        proposal.target_ref, proposal.policy_decision_ref,
        proposal.action_ticket_ref, correlation.evidence_refs, data_mode,
        "DEMO / SIMULATED DATA" if data_mode == "DEMO" else "CANONICAL READ-ONLY SAAS SECURITY LIFECYCLE",
    )


@dataclass(frozen=True)
class OperationsContinuityView:
    """Read-only FW-OPS/FW-REC status for Mission Control."""

    schema_version: int
    tenant_id: str
    health: str
    pressure: str
    resume_decision: str
    checkpoint_id: str
    current_commit: str
    health_evidence_reference: str
    capacity_evidence_reference: str
    observed_at_epoch: int
    mode: str = "DRY_RUN"
    deployment: str = "DISABLED"
    mutation_allowed: bool = False
    recovery_executed: bool = False
    authority_granted: bool = False


def project_operations_continuity(
    health: OperationalHealthProjection,
    capacity: CapacityAssessment,
    admission: ResumeAdmission,
    *,
    tenant_id: str,
) -> OperationsContinuityView:
    """Bind canonical operations and resume facts without executing recovery."""
    if (
        not isinstance(health, OperationalHealthProjection)
        or not isinstance(capacity, CapacityAssessment)
        or not isinstance(admission, ResumeAdmission)
        or not _TENANT.fullmatch(tenant_id)
        or health.tenant_id != tenant_id
        or capacity.tenant_id != tenant_id
        or admission.tenant_id != tenant_id
    ):
        raise MissionControlError("operations continuity facts are malformed or cross-tenant")
    if (
        health.mode != capacity.mode
        or health.mode != admission.mode
        or health.mode != "DRY_RUN"
        or health.deployment != capacity.deployment
        or health.deployment != admission.deployment
        or health.deployment != "DISABLED"
        or health.action != "OBSERVE_ONLY"
        or capacity.action != "OBSERVE_ONLY"
        or health.authority_granted
        or capacity.authority_granted
        or admission.authority_granted
        or health.recovery_invoked
        or capacity.recovery_invoked
        or capacity.throttle_executed
    ):
        raise MissionControlError("operations continuity safety state is invalid")
    health_evidence = _OPS_EVIDENCE.fullmatch(health.evidence_reference) if isinstance(health.evidence_reference, str) else None
    capacity_evidence = _OPS_EVIDENCE.fullmatch(capacity.evidence_reference) if isinstance(capacity.evidence_reference, str) else None
    if (
        health.health not in {"HEALTHY", "DEGRADED", "UNHEALTHY"}
        or capacity.pressure not in {"NORMAL", "ELEVATED", "SUSTAINED", "CRITICAL"}
        or not isinstance(health.assessed_at_epoch, int)
        or isinstance(health.assessed_at_epoch, bool)
        or not isinstance(capacity.assessed_at_epoch, int)
        or isinstance(capacity.assessed_at_epoch, bool)
        or capacity.assessed_at_epoch < health.assessed_at_epoch
        or health_evidence is None
        or health_evidence.group(1) != tenant_id
        or capacity_evidence is None
        or capacity_evidence.group(1) != tenant_id
        or not admission.checkpoint_id.startswith(f"fw-rec/{tenant_id}/")
        or not _SHA.fullmatch(admission.current_commit)
        or not isinstance(admission.decision, ResumeAdmissionDecision)
    ):
        raise MissionControlError("operations continuity binding is invalid")
    return OperationsContinuityView(
        1,
        tenant_id,
        health.health,
        capacity.pressure,
        admission.decision.value,
        admission.checkpoint_id,
        admission.current_commit,
        health.evidence_reference,
        capacity.evidence_reference,
        capacity.assessed_at_epoch,
    )
