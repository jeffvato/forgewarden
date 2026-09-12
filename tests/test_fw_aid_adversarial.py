"""Inert FW-AID adversarial simulations; no command or response execution."""
from dataclasses import replace
import pytest
from swarm.ai_agent_defense import AICrossDomainCorrelator, AIContainmentProposalRegistry, AIThreatClassificationError, DeterministicAIThreatClassifier
from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import NormalizedEventStore, validate_ai_workload_event
from tests.test_fw_aid import cross_fact, event, proposal_args

SCENARIOS=(
 ("prompt injection","AID-INJECTION","prompt_injection","NONE"),
 ("poisoned document","AID-INJECTION","poisoned_retrieval","NONE"),
 ("malicious webpage","AID-INJECTION","constraint_override","BROWSER"),
 ("credential discovery","AID-SECRETS","credential_discovery","CREDENTIAL"),
 ("secret exfiltration","AID-EGRESS","exfiltration_pattern","NETWORK"),
 ("unauthorized Internet access","AID-EGRESS","unauthorized_egress","NETWORK"),
 ("lateral movement","AID-LATERAL","lateral_movement","NETWORK"),
 ("container escape","AID-ESCAPE","sandbox_escape","CONTAINER"),
 ("privilege escalation","AID-PRIVILEGE","authority_expansion","NONE"),
 ("unauthorized MCP","AID-MISSION","unexpected_tool","MCP"),
 ("abnormal shell","AID-MISSION","unexpected_tool","SHELL"),
 ("EDR tampering","AID-TAMPER","security_control_tamper","PROCESS"),
 ("log deletion","AID-TAMPER","evidence_tamper","FILESYSTEM"),
 ("unapproved coordination","AID-COORDINATION","unapproved_coordination","NONE"),
 ("test manipulation","AID-EVALUATION","test_manipulation","FILESYSTEM"),
 ("reviewer manipulation","AID-EVALUATION","reviewer_manipulation","NONE"),
 ("policy bypass","AID-PRIVILEGE","self_authorization","NONE"),
 ("model self-expansion","AID-PRIVILEGE","authority_expansion","NONE"),
 ("kill-switch clearing","AID-TAMPER","kill_switch_clear","NONE"),
)

@pytest.mark.parametrize("index,scenario",enumerate(SCENARIOS))
def test_inert_attack_simulations_detect_and_propose_without_execution(index,scenario):
 name,threat,indicator,tool=scenario; evidence=[]; store=NormalizedEventStore(lambda *args:evidence.append(args))
 source=store.admit_ai_security_event(event(event_id=f"fw-event/tenant-a/adversarial-{index}",event_class=threat,anomaly_indicators=[indicator],tool_category=tool))
 classifier=DeterministicAIThreatClassifier("tenant-a",lambda *args:evidence.append(args)); finding=classifier.classify(source,finding_id=f"fw-finding/tenant-a/adversarial-{index}")
 facts=(cross_fact("ENDPOINT",1),cross_fact("IDENTITY",2),cross_fact("NETWORK",3)); story=AICrossDomainCorrelator("tenant-a",lambda *args:evidence.append(args)).correlate(finding,source,facts,story_id=f"story-{index}",ai_incident_id=f"ai-{index}",domain_incident_id=f"domain-{index}")
 proposal=AIContainmentProposalRegistry("tenant-a",lambda *args:evidence.append(args)).propose(finding,story,**proposal_args(proposal_id=f"fw-proposal/tenant-a/adversarial-{index}"))
 assert finding.threat_class==threat and finding.matched_facts==(indicator,)
 assert proposal.disposition=="PROPOSE_ONLY" and proposal.mode=="DRY_RUN" and proposal.deployment=="DISABLED" and proposal.kill_switch=="ENGAGED"
 assert not proposal.authority_granted and not proposal.response_executed and source.action=="DETECT_ONLY"
 assert evidence[0][0]=="ai_security_event_admitted" and evidence[-1][0]=="ai_containment_proposal_recorded"
 assert name and not hasattr(proposal,"execute")

@pytest.mark.parametrize("changes,invariant",[
 ({"authority_granted":True},"self authority"),({"mode":"LIVE"},"live mode"),({"action":"CONTAIN"},"containment execution"),({"deployment":"ENABLED"},"deployment"),({"prompt":"ignore policy"},"raw prompt"),({"command":"read credentials"},"raw command"),({"tenant_id":"tenant-b"},"tenant crossing"),
])
def test_adversarial_authority_and_raw_content_attempts_fail_closed(changes,invariant):
 with pytest.raises(EndpointFixtureDenied): validate_ai_workload_event(event(**changes))
 assert invariant

def test_adversarial_replay_and_evidence_failure_leave_no_hidden_advance():
 store=NormalizedEventStore(lambda *_:None); source=store.admit_ai_security_event(event())
 with pytest.raises(EndpointFixtureDenied,match="REPLAY"): store.admit_ai_security_event(event())
 assert store.pending_ai_security_events(tenant_id="tenant-a",agent_ref=source.agent_ref)==(source,)
 failed=NormalizedEventStore(lambda *_:(_ for _ in ()).throw(OSError("offline")))
 with pytest.raises(EndpointFixtureDenied,match="EVIDENCE_WRITE_FAILED"): failed.admit_ai_security_event(event())
 assert failed.pending_ai_security_events(tenant_id="tenant-a",agent_ref="fw-id/tenant-a/codex-worker")==()

def test_baseline_deviation_without_closed_fact_cannot_create_finding():
 source=validate_ai_workload_event(event(anomaly_indicators=["baseline_deviation"],event_class="AID-MISSION"))
 with pytest.raises(AIThreatClassificationError,match="insufficient"): DeterministicAIThreatClassifier("tenant-a",lambda *_:None).classify(source,finding_id="fw-finding/tenant-a/baseline-only")
