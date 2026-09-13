from dataclasses import replace

import pytest

from swarm.harness_context import BudgetAdmission, BudgetUsage
from swarm.harness_task import HarnessTask, TaskStatus
from swarm.harness_models import ApprovedModelCandidate
from swarm.harness_risk import AssuranceTier
from swarm.mcp_gateway import MCPGatewaySafetyState, MCPToolCatalogEntry
from swarm.harness_worker import WorkerRegistration, WorkerRole, WorkerTransport
from swarm.mission_control import MissionControlError, ModelMCPActivity, PolicyTicketActivity, project_ai_security, project_attack_surface, project_data_security, project_high_assurance, project_mission_control, project_network_security, project_saas_security, project_supply_chain, serialize_evidence_activity, serialize_harness_activity, serialize_incident_activity, serialize_model_mcp_activity, serialize_policy_ticket_activity
from tests.test_high_assurance import admission as gov_admission, admitted_profile as gov_profile
from swarm.high_assurance import bind_high_assurance_evidence
from swarm.action_ticket import ActionTicket
from swarm.policy_gate import PolicyContext, PolicyDecision
from swarm.evidence import EvidenceRecord, evidence_record_sha256, validate_evidence_envelope
from tests.test_fw_aid import classified_source, cross_fact, proposal_args
from tests.test_soc import incident, timeline_entry, playbook_step, mutating_step
from swarm.ai_agent_defense import AICrossDomainCorrelator, AIContainmentProposalRegistry
from swarm.soc import project_soc_dry_run_lifecycle
from tests.test_saas_security import saas_lifecycle
from tests.test_supply_chain import supply_lifecycle
from tests.test_network_security import network_lifecycle
from tests.test_attack_surface import attack_surface_lifecycle
from tests.test_data_security import data_security_lifecycle


def task(task_id="FWQ-0001", status=TaskStatus.READY, **changes):
    value = HarnessTask(
        task_id, "FW-HARNESS-008", "Mission view", "bounded view", status, 1,
        "CODEX", "gpt-approved", "/repo", "2026-09-09T00:00:00Z",
        relevant_files=("swarm/mission_control.py",), retry_limit=2,
    )
    return replace(value, **changes)


def worker():
    return WorkerRegistration("codex-cli", "openai", "gpt-approved", WorkerTransport.CLI, (WorkerRole.CODE_WRITER,), True, executable="codex")


def project(tasks=None, **changes):
    values = tasks or (task(), task("FWQ-0002", dependencies=("FWQ-0001",), priority=2))
    args = dict(
        tenant_id="tenant-one", task_tenants={item.task_id: "tenant-one" for item in values},
        current_task="FWQ-0001", worker=worker(),
        budget=BudgetAdmission("FWQ-0001", "codex-cli", BudgetUsage(model_calls=1, tokens=20), BudgetUsage(model_calls=1, tokens=20)),
        validation_status="passed", review_status="awaiting_review", recent_decisions=("worker admitted",),
        current_commit="a" * 40, next_task="FWQ-0002", kill_switch="ENGAGED",
    )
    args.update(changes)
    return project_mission_control(values, **args)


def test_projection_exposes_bounded_operator_state_without_authority():
    view = project()
    assert view.current_requirement == "FW-HARNESS-008"
    assert view.active_worker == "codex-cli" and view.active_model == "gpt-approved"
    assert view.task_queue[1].dependencies == ("FWQ-0001",)
    assert view.budget_used.tokens == 20 and view.next_task == "FWQ-0002"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert view.mutation_allowed is False


def test_projection_does_not_mutate_canonical_tasks():
    original = task()
    before = repr(original)
    project((original,), task_tenants={original.task_id: "tenant-one"}, next_task=None)
    assert repr(original) == before


@pytest.mark.parametrize("changes,match", [
    ({"task_tenants": {"FWQ-0001": "tenant-two", "FWQ-0002": "tenant-one"}}, "tenancy"),
    ({"current_task": "FWQ-9999"}, "current task"),
    ({"next_task": "FWQ-9999"}, "next task"),
    ({"current_commit": "mutable-head"}, "commit"),
    ({"kill_switch": "DISENGAGED"}, "kill switch"),
])
def test_inconsistent_or_cross_tenant_state_denies(changes, match):
    with pytest.raises(MissionControlError, match=match):
        project(**changes)


def test_budget_must_bind_current_task():
    bad = BudgetAdmission("FWQ-0002", "codex-cli", BudgetUsage(), BudgetUsage())
    with pytest.raises(MissionControlError, match="budget evidence"):
        project(budget=bad)


def test_worker_model_and_budget_identity_must_match_current_task():
    wrong_model = replace(worker(), model_id="other-model")
    with pytest.raises(MissionControlError, match="worker, model"):
        project(worker=wrong_model)
    wrong_budget = BudgetAdmission("FWQ-0001", "other-worker", BudgetUsage(), BudgetUsage())
    with pytest.raises(MissionControlError, match="worker, model"):
        project(budget=wrong_budget)


@pytest.mark.parametrize("text", ["Bearer abc.def", "api_key=secret-value", "access_token: value"])
def test_secret_bearing_status_is_rejected(text):
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project(recent_decisions=(text,))


def test_projection_rejects_unbounded_decision_history():
    with pytest.raises(MissionControlError, match="excessive"):
        project(recent_decisions=tuple(f"decision {index}" for index in range(33)))


def test_projection_rejects_secret_bearing_task_title():
    value = task(title="api_key=secret-value")
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project((value,), task_tenants={value.task_id: "tenant-one"}, next_task=None)


def test_projection_rejects_dependency_outside_canonical_queue():
    value = task(dependencies=("FWQ-9999",))
    with pytest.raises(MissionControlError, match="dependency"):
        project((value,), task_tenants={value.task_id: "tenant-one"}, next_task=None)


def test_idle_projection_has_no_worker_or_budget():
    view = project(current_task=None, worker=None, budget=None, next_task="FWQ-0001", current_commit=None)
    assert view.current_task is None and view.active_worker is None and view.budget_used is None


def test_harness_activity_serializes_canonical_and_empty_views_without_authority():
    canonical = serialize_harness_activity(project())
    assert canonical["data_mode"] == "CANONICAL"
    assert canonical["view"]["current_task"] == "FWQ-0001"
    assert canonical["view"]["task_queue"][1]["dependencies"] == ("FWQ-0001",)
    assert canonical["safety"] == {"mutation_allowed": False, "deployment": "DISABLED", "kill_switch": "ENGAGED"}
    assert serialize_harness_activity(None)["data_mode"] == "EMPTY"


def test_harness_activity_revalidates_forged_or_secret_bearing_views():
    with pytest.raises(MissionControlError):
        serialize_harness_activity(replace(project(), mutation_allowed=True))
    with pytest.raises(MissionControlError, match="secret-bearing"):
        serialize_harness_activity(replace(project(), recent_decisions=("api_key=secret-value",)))
    with pytest.raises(MissionControlError, match="dependencies"):
        bad_task = replace(project().task_queue[0], dependencies=("FWQ-9999",))
        serialize_harness_activity(replace(project(), task_queue=(bad_task, project().task_queue[1])))


def test_harness_activity_rejects_invalid_commit_and_unbounded_queue():
    with pytest.raises(MissionControlError, match="commit"):
        serialize_harness_activity(replace(project(), current_commit="mutable-head"))
    row = project().task_queue[0]
    oversized = tuple(replace(row, task_id=f"FWQ-{index:04d}", dependencies=()) for index in range(1025))
    with pytest.raises(MissionControlError, match="excessive"):
        serialize_harness_activity(replace(project(), task_queue=oversized))


def incident_lifecycle():
    return project_soc_dry_run_lifecycle(
        (incident(), incident(incident_id="incident-2", evidence_refs=["evidence/record-2"])),
        primary_incident_id="incident-1", story_id="story-1",
        timeline_entries=(timeline_entry(),), playbook_id="playbook-1",
        playbook_steps=(playbook_step(), mutating_step()), tenant_id="tenant-a",
        now_epoch=120, accepted_policy_decision_refs=("policy/decision-1",),
        accepted_action_ticket_refs=("ticket/one",), kill_switch_state="ENGAGED",
        deployment_state="DISABLED", audit=lambda *_args: None,
    )


def test_incident_activity_serializes_canonical_reference_only_lifecycle():
    lifecycle = incident_lifecycle()
    payload = serialize_incident_activity(lifecycle)
    assert payload["data_mode"] == "CANONICAL"
    assert payload["view"]["primary_incident_id"] == "incident-1"
    assert payload["view"]["attack_story"]["incident_ids"] == ("incident-1", "incident-2")
    assert payload["view"]["response_proposal"]["action"] == "PROPOSE_ONLY"
    assert payload["safety"]["response_executed"] is False
    assert serialize_incident_activity(None)["data_mode"] == "EMPTY"


def test_incident_activity_revalidates_tenant_safety_secrets_and_dependencies():
    lifecycle = incident_lifecycle()
    with pytest.raises(MissionControlError, match="safety"):
        serialize_incident_activity(replace(lifecycle, kill_switch="CLEARED"))
    foreign = replace(lifecycle.incidents[1], tenant_id="tenant-b")
    with pytest.raises(MissionControlError, match="tenancy"):
        serialize_incident_activity(replace(lifecycle, incidents=(lifecycle.incidents[0], foreign)))
    secret = replace(lifecycle.incidents[0], title="api_key=secret-value")
    with pytest.raises(MissionControlError, match="secret-bearing"):
        serialize_incident_activity(replace(lifecycle, incidents=(secret, lifecycle.incidents[1])))
    bad_step = replace(lifecycle.playbook.steps[1], depends_on=("missing-step",))
    with pytest.raises(MissionControlError, match="dependency"):
        serialize_incident_activity(replace(lifecycle, playbook=replace(lifecycle.playbook, steps=(lifecycle.playbook.steps[0], bad_step))))
    with pytest.raises(MissionControlError, match="binding"):
        serialize_incident_activity(replace(lifecycle, timeline=object()))


def evidence_record(*, evidence_id="fw-evid/tenant-a/task/0001", previous=None, tenant="tenant-a", actor_ref="fw-id/tenant-a/worker"):
    envelope = validate_evidence_envelope({
        "schema_version": "1", "evidence_id": evidence_id, "tenant_id": tenant,
        "event_type": "task.completed", "actor_ref": actor_ref, "actor_tenant_id": tenant,
        "subject_ref": f"fw-task/{tenant}/fw-ux-009", "subject_tenant_id": tenant,
        "occurred_at": "2026-09-12T18:00:00Z", "classification": "INTERNAL",
        "payload_schema_id": "fw-schema/harness/task-v1", "payload_sha256": "a" * 64,
        "previous_record_sha256": previous, "correlation_id": f"fw-corr/{tenant}/fw-ux-009",
        "evidence_references": (), "mode": "DRY_RUN", "deployment": "DISABLED", "authority_granted": False,
    })
    return EvidenceRecord(envelope, evidence_record_sha256(envelope))


def test_evidence_activity_projects_validated_chain_without_signing_authority():
    first = evidence_record()
    second = evidence_record(evidence_id="fw-evid/tenant-a/task/0002", previous=first.record_sha256)
    payload = serialize_evidence_activity((first, second))
    assert payload["data_mode"] == "CANONICAL"
    assert payload["view"]["record_count"] == 2
    assert payload["view"]["head_record_sha256"] == second.record_sha256
    assert payload["view"]["chain_status"] == "DIGEST_AND_CHAIN_VALIDATED"
    assert payload["view"]["signature_status"] == "NOT_PRESENT"
    assert payload["safety"]["signing_performed"] is False
    assert serialize_evidence_activity(None)["data_mode"] == "EMPTY"
    assert serialize_evidence_activity(())["data_mode"] == "EMPTY"


def test_evidence_activity_fails_closed_for_tamper_replay_cross_tenant_and_secrets():
    first = evidence_record()
    with pytest.raises(MissionControlError, match="chain"):
        serialize_evidence_activity((EvidenceRecord(first.envelope, "b" * 64),))
    with pytest.raises(MissionControlError, match="chain"):
        serialize_evidence_activity((first, first))
    foreign = evidence_record(evidence_id="fw-evid/tenant-b/task/0002", previous=first.record_sha256, tenant="tenant-b", actor_ref="fw-id/tenant-b/worker")
    with pytest.raises(MissionControlError, match="chain"):
        serialize_evidence_activity((first, foreign))
    forged = object.__new__(type(first.envelope))
    for name in first.envelope.__dataclass_fields__:
        object.__setattr__(forged, name, getattr(first.envelope, name))
    object.__setattr__(forged, "actor_ref", "api_key=secret-value")
    forged_record = EvidenceRecord(forged, evidence_record_sha256(forged))
    with pytest.raises(MissionControlError, match="secret-bearing"):
        serialize_evidence_activity((forged_record,))


def test_evidence_activity_rejects_malformed_and_unbounded_inputs():
    with pytest.raises(MissionControlError, match="malformed"):
        serialize_evidence_activity([evidence_record()])
    with pytest.raises(MissionControlError, match="excessive"):
        serialize_evidence_activity(tuple(evidence_record(evidence_id=f"fw-evid/tenant-a/task/{index:04d}") for index in range(257)))


def policy_ticket_activity(*, allowed=True, ticket=True, now=150):
    context = PolicyContext("tenant-a", "agent-a", "endpoint.isolate.request", "endpoint-1", "ISOLATE_ENDPOINT", "policy-v1")
    value = ActionTicket("ticket-1", "tenant-a", "agent-a", "lease-1", "endpoint.isolate.request", "endpoint-1", "ISOLATE_ENDPOINT", "root-operator", "approval-1", "policy-v1", 100, 200, "fw-keys/ticket", "signed-value") if ticket else None
    return PolicyTicketActivity(context, PolicyDecision(allowed, "RULE_MATCH" if allowed else "RULE_NOT_FOUND"), value, now)


def test_policy_ticket_activity_serializes_allow_deny_and_empty_without_authority():
    allowed = serialize_policy_ticket_activity(policy_ticket_activity())
    assert allowed["data_mode"] == "CANONICAL" and allowed["view"]["decision"] == "ALLOW"
    assert allowed["view"]["ticket"]["signature_status"] == "PRESENT_NOT_VERIFIED"
    assert allowed["view"]["ticket"]["usage_status"] == "UNCONSUMED"
    assert allowed["safety"]["ticket_consumed"] is False
    denied = serialize_policy_ticket_activity(policy_ticket_activity(allowed=False, ticket=False))
    assert denied["view"]["decision"] == "DENY" and denied["view"]["ticket"] is None
    assert serialize_policy_ticket_activity(None)["data_mode"] == "EMPTY"


@pytest.mark.parametrize("change,match", [
    ({"kill_switch": "CLEARED"}, "unsafe"), ({"deployment": "ENABLED"}, "unsafe"),
    ({"mutation_allowed": True}, "unsafe"), ({"observed_at_epoch": 200}, "expiry"),
])
def test_policy_ticket_activity_rejects_unsafe_or_expired_state(change, match):
    with pytest.raises(MissionControlError, match=match):
        serialize_policy_ticket_activity(replace(policy_ticket_activity(), **change))


def test_policy_ticket_activity_rejects_missing_mismatched_consumed_or_denied_ticket():
    with pytest.raises(MissionControlError, match="requires"):
        serialize_policy_ticket_activity(policy_ticket_activity(ticket=False))
    value = policy_ticket_activity()
    with pytest.raises(MissionControlError, match="binding"):
        serialize_policy_ticket_activity(replace(value, ticket=replace(value.ticket, tenant_id="tenant-b")))
    with pytest.raises(MissionControlError, match="usage"):
        serialize_policy_ticket_activity(replace(value, ticket=replace(value.ticket, consumed_at=160)))
    with pytest.raises(MissionControlError, match="denied"):
        serialize_policy_ticket_activity(replace(value, decision=PolicyDecision(False, "RULE_NOT_FOUND")))


def model_candidate(candidate_id="model-one", tenant="tenant-a", approved=True, available=True):
    return ApprovedModelCandidate(candidate_id, tenant, "provider-a", "model-a", "local", AssuranceTier.T1, (WorkerRole.CODE_WRITER,), ("INTERNAL",), ("repo.read",), 100, "fw-evid/model-one", approved, available)


def model_mcp_activity():
    return ModelMCPActivity("tenant-a", (model_candidate(), model_candidate("model-two", available=False)), (MCPToolCatalogEntry("tenant-a", "repo.read", "repo.read", "TRUSTED_READ_ONLY", True),), MCPGatewaySafetyState("HEALTHY", "ENGAGED"))


def test_model_mcp_activity_projects_registry_and_catalog_without_authority():
    payload = serialize_model_mcp_activity(model_mcp_activity())
    assert payload["data_mode"] == "CANONICAL"
    assert payload["view"]["models"][0]["approval_status"] == "APPROVED"
    assert payload["view"]["models"][1]["availability"] == "UNAVAILABLE"
    assert payload["view"]["tools"][0]["lease_status"] == "NOT_PRESENT"
    assert payload["safety"]["model_invoked"] is False
    assert payload["safety"]["tool_executed"] is False
    assert serialize_model_mcp_activity(None)["data_mode"] == "EMPTY"


def test_model_mcp_activity_rejects_unsafe_cross_tenant_duplicates_and_secrets():
    value = model_mcp_activity()
    with pytest.raises(MissionControlError, match="unsafe"):
        serialize_model_mcp_activity(replace(value, gateway_safety=MCPGatewaySafetyState("UNHEALTHY", "ENGAGED")))
    with pytest.raises(MissionControlError, match="crosses tenants"):
        serialize_model_mcp_activity(replace(value, tools=(MCPToolCatalogEntry("tenant-b", "repo.read", "repo.read", "TRUSTED_READ_ONLY", True),)))
    with pytest.raises(MissionControlError, match="duplicate"):
        serialize_model_mcp_activity(replace(value, models=(value.models[0], value.models[0])))
    forged = object.__new__(ApprovedModelCandidate)
    for name in value.models[0].__dataclass_fields__:
        object.__setattr__(forged, name, getattr(value.models[0], name))
    object.__setattr__(forged, "provider", "api_key=secret-value")
    with pytest.raises(MissionControlError, match="reconstruction"):
        serialize_model_mcp_activity(replace(value, models=(forged,)))


def test_model_mcp_activity_bounds_registry_and_catalog():
    value = model_mcp_activity()
    with pytest.raises(MissionControlError, match="unsafe"):
        serialize_model_mcp_activity(replace(value, models=tuple(model_candidate(f"model-{index}") for index in range(129))))
    with pytest.raises(MissionControlError, match="unsafe"):
        serialize_model_mcp_activity(replace(value, tools=tuple(MCPToolCatalogEntry("tenant-a", f"tool-{index}", "repo.read", "TRUSTED_READ_ONLY", True) for index in range(129))))


def ai_bundle():
 event,finding=classified_source(); facts=(cross_fact("ENDPOINT",1),cross_fact("IDENTITY",2),cross_fact("NETWORK",3)); story=AICrossDomainCorrelator("tenant-a",lambda *_:None).correlate(finding,event,facts,story_id="story-1",ai_incident_id="incident-ai",domain_incident_id="incident-domain"); proposal=AIContainmentProposalRegistry("tenant-a",lambda *_:None).propose(finding,story,**proposal_args()); return event,finding,story,proposal

def test_ai_security_projection_is_sanitized_tenant_bound_and_read_only():
 event,finding,story,proposal=ai_bundle(); view=project_ai_security(tenant_id="tenant-a",events=(event,),findings=(finding,),stories=(story,),proposals=(proposal,),data_mode="CANONICAL")
 row=view.agents[0]; assert row.agent_ref==event.agent_ref and row.model_ref==event.model_ref and row.task_ref==event.task_ref
 assert row.threat_class==finding.threat_class and row.story_id=="story-1" and row.incident_ids==("incident-ai","incident-domain")
 assert row.containment_action=="REVOKE_LEASE" and row.containment_state=="PROPOSE_ONLY"
 assert view.data_label=="CANONICAL READ-ONLY DATA" and view.kill_switch=="ENGAGED" and view.deployment=="DISABLED" and not view.mutation_allowed
 assert not hasattr(view,"execute") and not hasattr(view,"approve")

def test_ai_security_demo_label_is_explicit_and_ordering_deterministic():
 event,finding,story,proposal=ai_bundle(); view=project_ai_security(tenant_id="tenant-a",events=(event,),findings=(finding,),stories=(story,),proposals=(proposal,),data_mode="DEMO")
 assert view.data_label=="DEMO / SIMULATED DATA"

def test_ai_security_projection_rejects_cross_tenant_orphan_duplicate_secret_and_kill_switch():
 from dataclasses import replace
 event,finding,story,proposal=ai_bundle()
 bad=(dict(tenant_id="tenant-b"),dict(findings=()),dict(findings=(finding,finding)),dict(stories=()),dict(kill_switch="CLEARED"))
 base=dict(tenant_id="tenant-a",events=(event,),findings=(finding,),stories=(story,),proposals=(proposal,))
 for change in bad:
  args=base|change
  with pytest.raises(MissionControlError): project_ai_security(**args)
 forged=object.__new__(type(event))
 for name in event.__dataclass_fields__: object.__setattr__(forged,name,getattr(event,name))
 object.__setattr__(forged,"mcp_server_ref","api_key=secret-value")
 with pytest.raises(MissionControlError): project_ai_security(tenant_id="tenant-a",events=(forged,),findings=(finding,),stories=(story,),proposals=(proposal,))

def test_ai_security_projection_does_not_mutate_sources_and_bounds_events():
 event,finding,story,proposal=ai_bundle(); before=(repr(event),repr(finding),repr(story),repr(proposal)); project_ai_security(tenant_id="tenant-a",events=(event,),findings=(finding,),stories=(story,),proposals=(proposal,)); assert before==(repr(event),repr(finding),repr(story),repr(proposal))
 with pytest.raises(MissionControlError): project_ai_security(tenant_id="tenant-a",events=(),findings=(),stories=())


def test_ai_security_projection_supports_no_containment_proposal_without_type_error():
 event,finding,story,_=ai_bundle(); view=project_ai_security(tenant_id="tenant-a",events=(event,),findings=(finding,),stories=(story,),proposals=())
 assert view.agents[0].containment_proposal_id is None and view.agents[0].containment_state=="NONE"


def test_saas_security_projection_exposes_bound_lifecycle_without_authority():
    lifecycle = saas_lifecycle()
    view = project_saas_security(lifecycle, tenant_id="tenant-a")
    assert view.event_id == "saas-1" and view.confidence == "HIGH"
    assert view.soc_incident_ref == "fw-incident/tenant-a/saas-1"
    assert view.aid_finding_ref == "fw-finding/tenant-a/saas-1"
    assert view.proposal_action == "SAAS_APP_DISABLE_PROPOSAL"
    assert view.proposal_state == "PROPOSE_ONLY"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert view.mutation_allowed is False and view.response_executed is False
    assert not hasattr(view, "execute") and not hasattr(view, "approve")


def test_saas_security_projection_labels_demo_and_rejects_tamper_or_cross_tenant():
    lifecycle = saas_lifecycle()
    demo = project_saas_security(lifecycle, tenant_id="tenant-a", data_mode="DEMO")
    assert demo.data_label == "DEMO / SIMULATED DATA"
    with pytest.raises(MissionControlError, match="binding"):
        project_saas_security(replace(lifecycle, kill_switch="CLEARED"), tenant_id="tenant-a")
    with pytest.raises(MissionControlError, match="binding"):
        project_saas_security(lifecycle, tenant_id="tenant-b")
    tampered = replace(lifecycle, proposal=replace(lifecycle.proposal, event_id="saas-2"))
    with pytest.raises(MissionControlError, match="binding"):
        project_saas_security(tampered, tenant_id="tenant-a")
    secret = replace(lifecycle, proposal=replace(lifecycle.proposal, policy_decision_ref="api_key=secret-value"))
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project_saas_security(secret, tenant_id="tenant-a")


def test_supply_chain_projection_exposes_lifecycle_without_authority():
    lifecycle = supply_lifecycle()
    view = project_supply_chain(lifecycle, tenant_id="tenant-a")
    assert view.event_id == "supply-1" and view.risk == "CRITICAL"
    assert view.vulnerability_refs == ("fw-vuln/tenant-a/osv-1",)
    assert view.proposal_action == "BLOCK_COMPONENT_PROPOSAL"
    assert view.proposal_state == "PROPOSE_ONLY"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert view.mutation_allowed is False and view.response_executed is False
    assert not hasattr(view, "execute") and not hasattr(view, "approve")


def test_supply_chain_projection_labels_demo_and_rejects_tamper_or_secret():
    lifecycle = supply_lifecycle()
    assert project_supply_chain(
        lifecycle, tenant_id="tenant-a", data_mode="DEMO",
    ).data_label == "DEMO / SIMULATED DATA"
    for invalid in (
        replace(lifecycle, kill_switch="CLEARED"),
        replace(lifecycle, proposal=replace(lifecycle.proposal, event_id="supply-2")),
    ):
        with pytest.raises(MissionControlError, match="binding"):
            project_supply_chain(invalid, tenant_id="tenant-a")
    with pytest.raises(MissionControlError, match="binding"):
        project_supply_chain(lifecycle, tenant_id="tenant-b")
    secret = replace(
        lifecycle,
        proposal=replace(lifecycle.proposal, policy_decision_ref="api_key=secret"),
    )
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project_supply_chain(secret, tenant_id="tenant-a")


def test_network_security_projection_exposes_lifecycle_without_authority():
    lifecycle = network_lifecycle()
    view = project_network_security(lifecycle, tenant_id="tenant-a")
    assert view.event_id == "network-1" and view.risk == "HIGH"
    assert view.endpoint_event_ref == "fw-endpoint/tenant-a/network-1"
    assert view.proposal_action == "NETWORK_CONTAINMENT_PROPOSAL"
    assert view.proposal_state == "PROPOSE_ONLY"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert view.mutation_allowed is False and view.response_executed is False
    assert not hasattr(view, "execute") and not hasattr(view, "approve")


def test_network_security_projection_labels_demo_and_rejects_tamper_or_secret():
    lifecycle = network_lifecycle()
    assert project_network_security(
        lifecycle, tenant_id="tenant-a", data_mode="DEMO",
    ).data_label == "DEMO / SIMULATED DATA"
    for invalid in (
        replace(lifecycle, kill_switch="CLEARED"),
        replace(lifecycle, proposal=replace(lifecycle.proposal, event_id="network-2")),
        replace(lifecycle, binding=replace(lifecycle.binding, risk="CRITICAL")),
        replace(
            lifecycle,
            binding=replace(
                lifecycle.binding,
                endpoint_event_ref="fw-endpoint/tenant-b/network-1",
            ),
        ),
    ):
        with pytest.raises(MissionControlError, match="binding"):
            project_network_security(invalid, tenant_id="tenant-a")
    with pytest.raises(MissionControlError, match="binding"):
        project_network_security(lifecycle, tenant_id="tenant-b")
    secret = replace(
        lifecycle,
        proposal=replace(lifecycle.proposal, policy_decision_ref="api_key=secret"),
    )
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project_network_security(secret, tenant_id="tenant-a")
    excessive = replace(
        lifecycle,
        binding=replace(lifecycle.binding, evidence_refs=("x" * 1001,)),
    )
    with pytest.raises(MissionControlError, match="excessive"):
        project_network_security(excessive, tenant_id="tenant-a")


def test_attack_surface_projection_exposes_lifecycle_without_authority():
    lifecycle = attack_surface_lifecycle()
    view = project_attack_surface(lifecycle, tenant_id="tenant-a")
    assert view.event_id == "asm-1" and view.risk == "CRITICAL"
    assert view.asset_ref == "fw-asset/tenant-a/site-1"
    assert view.network_ref == "fw-network/tenant-a/exposure-1"
    assert view.proposal_action == "ASM_RISK_REDUCTION_PROPOSAL"
    assert view.proposal_state == "PROPOSE_ONLY"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert view.mutation_allowed is False and view.response_executed is False
    assert not hasattr(view, "execute") and not hasattr(view, "approve")


def test_attack_surface_projection_labels_demo_and_rejects_tamper_or_secret():
    lifecycle = attack_surface_lifecycle()
    assert project_attack_surface(
        lifecycle, tenant_id="tenant-a", data_mode="DEMO",
    ).data_label == "DEMO / SIMULATED DATA"
    for invalid in (
        replace(lifecycle, kill_switch="CLEARED"),
        replace(lifecycle, binding=replace(lifecycle.binding, risk="HIGH")),
        replace(lifecycle, proposal=replace(lifecycle.proposal, event_id="asm-2")),
    ):
        with pytest.raises(MissionControlError, match="binding"):
            project_attack_surface(invalid, tenant_id="tenant-a")
    with pytest.raises(MissionControlError, match="binding"):
        project_attack_surface(lifecycle, tenant_id="tenant-b")
    secret = replace(
        lifecycle,
        proposal=replace(lifecycle.proposal, policy_decision_ref="api_key=secret"),
    )
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project_attack_surface(secret, tenant_id="tenant-a")


def test_attack_surface_projection_rejects_invalid_type_mode_and_excessive_value():
    with pytest.raises(MissionControlError, match="malformed"):
        project_attack_surface(None, tenant_id="tenant-a")
    lifecycle = attack_surface_lifecycle()
    with pytest.raises(MissionControlError, match="binding"):
        project_attack_surface(lifecycle, tenant_id="tenant-a", data_mode="UNKNOWN")
    excessive = replace(
        lifecycle, binding=replace(lifecycle.binding, network_ref="x" * 1001),
    )
    with pytest.raises(MissionControlError, match="excessive"):
        project_attack_surface(excessive, tenant_id="tenant-a")


def test_data_security_projection_exposes_lifecycle_without_authority():
    lifecycle = data_security_lifecycle()
    view = project_data_security(lifecycle, tenant_id="tenant-a")
    assert view.event_id == "dspm-1" and view.risk == "HIGH"
    assert view.data_asset_ref == "fw-data/tenant-a/customer-records"
    assert view.owner_identity_ref == "fw-id/tenant-a.data-owner"
    assert view.proposal_action == "DSPM_DLP_PROPOSAL"
    assert view.proposal_state == "PROPOSE_ONLY"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert view.mutation_allowed is False and view.response_executed is False
    assert not hasattr(view, "execute") and not hasattr(view, "approve")


def test_data_security_projection_labels_demo_and_rejects_tamper_or_secret():
    lifecycle = data_security_lifecycle()
    assert project_data_security(
        lifecycle, tenant_id="tenant-a", data_mode="DEMO",
    ).data_label == "DEMO / SIMULATED DATA"
    for invalid in (
        replace(lifecycle, kill_switch="CLEARED"),
        replace(lifecycle, binding=replace(lifecycle.binding, risk="CRITICAL")),
        replace(lifecycle, proposal=replace(lifecycle.proposal, event_id="dspm-2")),
    ):
        with pytest.raises(MissionControlError, match="binding"):
            project_data_security(invalid, tenant_id="tenant-a")
    with pytest.raises(MissionControlError, match="binding"):
        project_data_security(lifecycle, tenant_id="tenant-b")
    secret = replace(
        lifecycle,
        binding=replace(lifecycle.binding, policy_decision_ref="api_key=secret"),
        proposal=replace(lifecycle.proposal, policy_decision_ref="api_key=secret"),
    )
    with pytest.raises(MissionControlError, match="secret-bearing"):
        project_data_security(secret, tenant_id="tenant-a")


def test_data_security_projection_rejects_invalid_type_mode_and_excessive_value():
    with pytest.raises(MissionControlError, match="malformed"):
        project_data_security(None, tenant_id="tenant-a")
    lifecycle = data_security_lifecycle()
    with pytest.raises(MissionControlError, match="binding"):
        project_data_security(lifecycle, tenant_id="tenant-a", data_mode="UNKNOWN")
    excessive = replace(
        lifecycle, binding=replace(lifecycle.binding, saas_ref="x" * 1001),
    )
    with pytest.raises(MissionControlError, match="excessive"):
        project_data_security(excessive, tenant_id="tenant-a")


def test_data_security_projection_directly_denies_event_risk_and_mode_drift():
    lifecycle = data_security_lifecycle()
    with pytest.raises(MissionControlError, match="binding"):
        project_data_security(
            replace(lifecycle, finding=replace(lifecycle.finding, event_id="dspm-2")),
            tenant_id="tenant-a",
        )
    with pytest.raises(MissionControlError, match="binding"):
        project_data_security(
            replace(lifecycle, binding=replace(lifecycle.binding, risk="CRITICAL")),
            tenant_id="tenant-a",
        )
    with pytest.raises(MissionControlError, match="binding"):
        project_data_security(lifecycle, tenant_id="tenant-a", data_mode="UNKNOWN")


def gov_binding():
    profile = gov_profile(); admission = gov_admission(profile_value=profile)
    return bind_high_assurance_evidence(profile, admission, tenant_id="tenant-a", evidence_refs=(profile.evidence_ref, admission.registry_evidence_ref), audit=lambda *_: None)


def test_high_assurance_projection_is_read_only_and_honestly_labeled():
    view = project_high_assurance(gov_binding(), tenant_id="tenant-a")
    assert view.profile_id == "fw-gov-profile/tenant-a/reviewer-prod"
    assert view.selected_candidate_id == "approved-reviewer"
    assert view.data_label == "CANONICAL READ-ONLY HIGH-ASSURANCE DECISION"
    assert view.kill_switch == "ENGAGED" and view.deployment == "DISABLED"
    assert not view.mutation_allowed and not view.invocation_authorized and not view.authority_granted
    assert project_high_assurance(gov_binding(), tenant_id="tenant-a", data_mode="DEMO").data_label == "DEMO / SIMULATED DATA"


def test_high_assurance_projection_denies_cross_tenant_tamper_secret_and_unknown_mode():
    binding = gov_binding()
    for changed in (
        replace(binding, tenant_id="tenant-b"),
        replace(binding, invocation_authorized=True),
        replace(binding, evidence_refs=("fw-evid/tenant-b/other",)),
        replace(binding, model_id="api_key=secret-value"),
    ):
        with pytest.raises(MissionControlError):
            project_high_assurance(changed, tenant_id="tenant-a")
    with pytest.raises(MissionControlError):
        project_high_assurance(binding, tenant_id="tenant-a", data_mode="UNKNOWN")
