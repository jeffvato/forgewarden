from dataclasses import replace
import pytest

from swarm.ai_agent_defense import (AICrossDomainCorrelator, AIContainmentProposalRegistry, AIThreatClassificationError, CrossDomainSecurityFact, DeterministicAIThreatClassifier, HarnessAIDMonitorAdapter, HarnessMonitorBinding)
from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.harness_evidence import HarnessLifecycleEvidence
from swarm.mission_control import MissionControlError, project_ai_security
from swarm.normalized_events import NormalizedEventStore


def lifecycle(tenant="tenant-a"):
    return HarnessLifecycleEvidence(1,"task_denied",tenant,"FW-AID-010","FW-AID-010","controller","codex-worker","openai","gpt-approved","a"*64,("source.write",),("secret.read",),("secret.read",),("swarm/ai_agent_defense.py",),(),(),(),"DENIED","DENIED","2026-09-12T02:00:00Z",None,())


def endpoint_fixture(tenant="tenant-a"):
    return {"event_id":"endpoint-1","tenant_id":tenant,"device_id":"device-a","observed_at_epoch":100,"event_type":"PROCESS_START","source":"LINUX_SENSOR","process":{"pid":"42"},"evidence_ref":"evidence-endpoint","process_ancestry":[],"related_indicators":["ai-origin"]}


def binding():
    return HarnessMonitorBinding("fw-event/tenant-a/lifecycle-1","fw-session/tenant-a/session-1","fw-lease/tenant-a/lease-1","fw-action/tenant-a/ticket-1","registered-mcp","fw-resource/tenant-a/repository",("fw-evid/tenant-a/harness-1",))


def test_integrated_ai_intrusion_lifecycle_is_tenant_bound_inert_and_evidence_ordered():
    evidence=[]; sink=lambda *args:evidence.append(args); store=NormalizedEventStore(sink)
    store.admit_fixture(endpoint_fixture(),tenant_id="tenant-a",device_id="device-a",source="LINUX_SENSOR",now_epoch=150)
    attribution=store.admit_ai_endpoint_attribution({"schema_version":"1","tenant_id":"tenant-a","device_id":"device-a","endpoint_event_id":"endpoint-1","agent_ref":"fw-id/tenant-a/codex-worker","session_ref":"fw-session/tenant-a/session-1","task_ref":"fw-task/tenant-a/fw-aid-010","capability_lease_ref":"fw-lease/tenant-a/lease-1","action_ticket_ref":"fw-action/tenant-a/ticket-1","observed_at_epoch":100,"evidence_references":["fw-evid/tenant-a/endpoint-1"],"mode":"DRY_RUN","action":"CORRELATE_ONLY","authority_granted":False})
    event=HarnessAIDMonitorAdapter("tenant-a",store).observe(lifecycle(),binding())
    finding=DeterministicAIThreatClassifier("tenant-a",sink).classify(event,finding_id="fw-finding/tenant-a/secrets-1")
    facts=(CrossDomainSecurityFact("tenant-a","ENDPOINT","fw-fact/tenant-a/ENDPOINT/endpoint-1","device/device-a",100,"fw-evid/tenant-a/endpoint-1"),CrossDomainSecurityFact("tenant-a","IDENTITY","fw-fact/tenant-a/IDENTITY/identity-1","fw-id/tenant-a/codex-worker",110,"fw-evid/tenant-a/identity-1"),CrossDomainSecurityFact("tenant-a","MCP","fw-fact/tenant-a/MCP/mcp-1","mcp/registered-mcp",120,"fw-evid/tenant-a/mcp-1"))
    story=AICrossDomainCorrelator("tenant-a",sink).correlate(finding,event,facts,story_id="story-aid-lifecycle",ai_incident_id="incident-ai",domain_incident_id="incident-endpoint")
    proposal=AIContainmentProposalRegistry("tenant-a",sink).propose(finding,story,proposal_id="fw-proposal/tenant-a/p-1",target_ref="fw-resource/tenant-a/agent",blast_radius=1,policy_decision_ref="fw-policy/tenant-a/d-1",capability_lease_ref="fw-lease/tenant-a/lease-1",action_ticket_ref="fw-action/tenant-a/ticket-1",approval_ref="fw-approval/tenant-a/a-1",checkpoint_ref="fw-checkpoint/tenant-a/c-1",rollback_ref="fw-rollback/tenant-a/r-1",evidence_references=("fw-evid/tenant-a/story-1",),created_at_epoch=200,lease_expires_at_epoch=500)
    view=project_ai_security(tenant_id="tenant-a",events=(event,),findings=(finding,),stories=(story,),proposals=(proposal,))
    assert attribution.agent_ref==event.agent_ref and attribution.session_ref==event.session_ref and attribution.task_ref==event.task_ref
    assert view.data_label=="CANONICAL READ-ONLY DATA" and view.kill_switch=="ENGAGED" and view.deployment=="DISABLED" and view.mutation_allowed is False
    assert proposal.disposition=="PROPOSE_ONLY" and proposal.response_executed is False and proposal.authority_granted is False
    kinds=[item[0] for item in evidence]
    assert kinds==["endpoint_event_admitted","ai_endpoint_attribution_admitted","ai_security_event_admitted","ai_threat_finding_admitted","soc_incident_projected","soc_incident_projected","soc_attack_story_projected","ai_containment_proposal_recorded"]


def test_integrated_lifecycle_rejects_cross_tenant_replay_and_orphans_without_hidden_advance():
    evidence=[]; store=NormalizedEventStore(lambda *args:evidence.append(args)); monitor=HarnessAIDMonitorAdapter("tenant-a",store)
    with pytest.raises(AIThreatClassificationError,match="binding"): monitor.observe(lifecycle("tenant-b"),binding())
    event=monitor.observe(lifecycle(),binding())
    before=len(evidence)
    with pytest.raises(AIThreatClassificationError,match="admission"): monitor.observe(lifecycle(),binding())
    assert len(evidence)==before
    finding=DeterministicAIThreatClassifier("tenant-a",lambda *_:None).classify(event,finding_id="fw-finding/tenant-a/f-1")
    with pytest.raises(MissionControlError,match="binding incomplete"): project_ai_security(tenant_id="tenant-a",events=(event,),findings=(finding,),stories=())
    with pytest.raises(MissionControlError): project_ai_security(tenant_id="tenant-b",events=(event,),findings=(finding,),stories=())