import copy
from dataclasses import replace
import pytest
from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import AI_EVENT_CLASSES, NormalizedEventStore, validate_ai_workload_event
from swarm.ai_agent_defense import *
from swarm.harness_evidence import HarnessLifecycleEvidence

def event(**changes):
 value={"schema_version":"1","event_id":"fw-event/tenant-a/aid-1","tenant_id":"tenant-a","event_class":"AID-PRIVILEGE","source":"harness.fixture","classification":"INTERNAL","observed_at_epoch":100,"agent_ref":"fw-id/tenant-a/codex-worker","model_ref":"fw-model/tenant-a/codex","session_ref":"fw-session/tenant-a/session-1","task_ref":"fw-task/tenant-a/task-1","initiating_user_ref":"fw-id/tenant-a/operator","purpose_sha256":"a"*64,"capability_lease_ref":"fw-lease/tenant-a/lease-1","action_ticket_ref":"fw-action/tenant-a/ticket-1","tool_category":"MCP","mcp_server_ref":"registered-mcp","target_resource_ref":"fw-resource/tenant-a/repository","decision":"DENIED","anomaly_indicators":["authority_expansion","repeated_denial"],"evidence_references":["fw-evid/tenant-a/harness-1"],"mode":"DRY_RUN","action":"DETECT_ONLY","authority_granted":False}; value.update(changes); return value

def test_all_ten_ai_threat_classes_normalize_without_authority():
 for threat in AI_EVENT_CLASSES:
  item=validate_ai_workload_event(event(event_class=threat,event_id=f"fw-event/tenant-a/{threat.lower()}"))
  assert item.event_class==threat and item.mode=="DRY_RUN" and item.action=="DETECT_ONLY" and not item.authority_granted

def test_store_admits_evidence_first_and_projects_only_same_tenant_agent():
 calls=[]; store=NormalizedEventStore(lambda *args:calls.append(args)); item=store.admit_ai_security_event(event())
 assert calls[0][0]=="ai_security_event_admitted" and "prompt" not in calls[0][1] and "command" not in calls[0][1]
 assert store.pending_ai_security_events(tenant_id="tenant-a",agent_ref=item.agent_ref)==(item,)
 assert store.pending_ai_security_events(tenant_id="tenant-b",agent_ref="fw-id/tenant-b/codex-worker")==()
 with pytest.raises(EndpointFixtureDenied,match="REPLAY"): store.admit_ai_security_event(event())

@pytest.mark.parametrize("change",[{"prompt":"ignore safeguards"},{"command":"cat secrets"},{"api_key":"sk-secretvalue"},{"tenant_id":"tenant-b"},{"agent_ref":"fw-id/tenant-b/worker"},{"model_ref":"fw-model/tenant-b/model"},{"task_ref":"fw-task/tenant-b/task"},{"evidence_references":["fw-evid/tenant-b/proof"]},{"purpose_sha256":"bad"},{"event_class":"AID-UNKNOWN"},{"classification":"TOP_SECRET"},{"tool_category":"ARBITRARY_SHELL"},{"decision":"AUTHORIZED"},{"anomaly_indicators":["password=secretvalue"]},{"anomaly_indicators":[str(i) for i in range(33)]},{"mode":"LIVE"},{"action":"CONTAIN"},{"authority_granted":True}])
def test_ai_event_rejects_unknown_raw_secret_cross_tenant_malformed_and_authority(change):
 with pytest.raises(EndpointFixtureDenied): validate_ai_workload_event(event(**change))

def test_ai_event_evidence_failure_does_not_enqueue_and_is_retryable():
 store=NormalizedEventStore(lambda *_:(_ for _ in ()).throw(OSError("offline")))
 with pytest.raises(EndpointFixtureDenied,match="EVIDENCE_WRITE_FAILED"): store.admit_ai_security_event(event())
 assert store.pending_ai_security_events(tenant_id="tenant-a",agent_ref="fw-id/tenant-a/codex-worker")==()
 retry=NormalizedEventStore(lambda *_:None); assert retry.admit_ai_security_event(event()).event_id.endswith("aid-1")

def test_ai_event_collections_are_unique_sorted_bounded_and_snapshot_is_bounded():
 for bad in (["z","a"],["a","a"],"a"):
  with pytest.raises(EndpointFixtureDenied): validate_ai_workload_event(event(anomaly_indicators=bad))
 store=NormalizedEventStore(lambda *_:None); store.admit_ai_security_event(event())
 for limit in (0,129,True):
  with pytest.raises(EndpointFixtureDenied): store.pending_ai_security_events(tenant_id="tenant-a",agent_ref="fw-id/tenant-a/codex-worker",limit=limit)


RULE_FACTS={"AID-ESCAPE":"sandbox_escape","AID-EGRESS":"unauthorized_egress","AID-SECRETS":"secret_access","AID-PRIVILEGE":"authority_expansion","AID-LATERAL":"cross_tenant_target","AID-INJECTION":"prompt_injection","AID-MISSION":"mission_deviation","AID-COORDINATION":"unapproved_coordination","AID-EVALUATION":"test_manipulation","AID-TAMPER":"security_control_tamper"}

def test_closed_classifier_covers_all_ten_threat_classes_without_model_authority():
 evidence=[]; classifier=DeterministicAIThreatClassifier("tenant-a",lambda *args:evidence.append(args))
 for index,(threat,fact) in enumerate(sorted(RULE_FACTS.items())):
  source=validate_ai_workload_event(event(event_id=f"fw-event/tenant-a/class-{index}",event_class=threat,anomaly_indicators=[fact]))
  finding=classifier.classify(source,finding_id=f"fw-finding/tenant-a/finding-{index}")
  assert finding.threat_class==threat and finding.matched_facts==(fact,) and finding.severity in {"HIGH","CRITICAL"}
  assert finding.confidence==80 and finding.action=="DETECT_ONLY" and finding.disposition=="ADVISORY" and not finding.authority_granted
 assert len(classifier.snapshot("tenant-a"))==10 and len(evidence)==10

def test_classifier_requires_matching_canonical_facts_and_does_not_mutate_source():
 classifier=DeterministicAIThreatClassifier("tenant-a",lambda *_:None)
 source=validate_ai_workload_event(event(event_class="AID-EGRESS",anomaly_indicators=["authority_expansion"]))
 before=source
 with pytest.raises(AIThreatClassificationError,match="insufficient"): classifier.classify(source,finding_id="fw-finding/tenant-a/no-match")
 assert source==before and classifier.snapshot("tenant-a")==()

def test_classifier_is_tenant_bound_replay_safe_and_evidence_first():
 calls=[]; classifier=DeterministicAIThreatClassifier("tenant-a",lambda *args:calls.append(args)); source=validate_ai_workload_event(event(anomaly_indicators=["authority_expansion","repeated_denial"]))
 finding=classifier.classify(source,finding_id="fw-finding/tenant-a/privilege-1")
 assert finding.confidence==90 and calls[0][0]=="ai_threat_finding_admitted"
 with pytest.raises(AIThreatClassificationError,match="duplicate"): classifier.classify(source,finding_id=finding.finding_id)
 with pytest.raises(AIThreatClassificationError,match="tenant"): classifier.snapshot("tenant-b")
 cross=validate_ai_workload_event(event(tenant_id="tenant-b",event_id="fw-event/tenant-b/e",agent_ref="fw-id/tenant-b/a",model_ref="fw-model/tenant-b/m",session_ref="fw-session/tenant-b/s",task_ref="fw-task/tenant-b/t",initiating_user_ref="fw-id/tenant-b/u",capability_lease_ref="fw-lease/tenant-b/l",action_ticket_ref="fw-action/tenant-b/a",target_resource_ref="fw-resource/tenant-b/r",evidence_references=["fw-evid/tenant-b/e"]))
 with pytest.raises(AIThreatClassificationError,match="tenant"): classifier.classify(cross,finding_id="fw-finding/tenant-a/cross")
 assert classifier.snapshot("tenant-a")== (finding,) and len(calls)==1

def test_classifier_evidence_failure_is_retryable_and_reentrancy_denied():
 source=validate_ai_workload_event(event(anomaly_indicators=["authority_expansion"])); holder={}
 def reenter(*_): holder["classifier"].classify(source,finding_id="fw-finding/tenant-a/f")
 classifier=DeterministicAIThreatClassifier("tenant-a",reenter); holder["classifier"]=classifier
 with pytest.raises(AIThreatClassificationError,match="Evidence failed"): classifier.classify(source,finding_id="fw-finding/tenant-a/f")
 assert classifier.snapshot("tenant-a")==()
 retry=DeterministicAIThreatClassifier("tenant-a",lambda *_:None); assert retry.classify(source,finding_id="fw-finding/tenant-a/f").finding_id.endswith("/f")

@pytest.mark.parametrize("changes",[{"schema_version":"2"},{"finding_id":"fw-finding/tenant-b/f"},{"threat_class":"UNKNOWN"},{"severity":"LOW"},{"confidence":101},{"confidence":True},{"matched_facts":()},{"matched_facts":("secret_access",)},{"disposition":"AUTHORIZED"},{"action":"CONTAIN"},{"mode":"LIVE"},{"authority_granted":True}])
def test_finding_contract_rejects_malformed_policy_and_authority(changes):
 values=dict(schema_version="1",finding_id="fw-finding/tenant-a/f",tenant_id="tenant-a",source_event_id="fw-event/tenant-a/e",agent_ref="fw-id/tenant-a/a",threat_class="AID-PRIVILEGE",severity="CRITICAL",confidence=80,matched_facts=("authority_expansion",),evidence_references=("fw-evid/tenant-a/e",),observed_at_epoch=1)
 values.update(changes)
 with pytest.raises(AIThreatClassificationError): AIThreatFinding(**values)


def lifecycle(*,attempted=("permission.expand",),denied=("permission.expand",),tenant="tenant-a",worker="codex-worker",model="gpt-approved"):
 return HarnessLifecycleEvidence(1,"task_denied",tenant,"FW-AID-004","FW-AID-004","controller",worker,"openai",model,"a"*64,("source.write",),attempted,denied,("swarm/ai_agent_defense.py",),(),(),(),"DENIED","DENIED","2026-09-12T02:00:00Z",None,())

def binding(**changes):
 value=dict(event_id="fw-event/tenant-a/harness-1",session_ref="fw-session/tenant-a/s-1",capability_lease_ref="fw-lease/tenant-a/l-1",action_ticket_ref="fw-action/tenant-a/t-1",mcp_server_ref="registered-mcp",target_resource_ref="fw-resource/tenant-a/repository",evidence_references=("fw-evid/tenant-a/harness-1",)); value.update(changes); return HarnessMonitorBinding(**value)

def test_harness_monitor_maps_closed_security_signals_into_canonical_store():
 calls=[]; store=NormalizedEventStore(lambda *args:calls.append(args)); monitor=HarnessAIDMonitorAdapter("tenant-a",store)
 cases=(("permission.expand","AID-PRIVILEGE","authority_expansion"),("secret.read","AID-SECRETS","secret_access"),("mcp.unapproved","AID-MISSION","unexpected_tool"),("path.out_of_scope","AID-MISSION","mission_deviation"),("agent.coordinate","AID-COORDINATION","unapproved_coordination"),("review.manipulate","AID-EVALUATION","reviewer_manipulation"),("test.manipulate","AID-EVALUATION","test_manipulation"),("evidence.modify","AID-TAMPER","evidence_tamper"))
 for index,(action,threat,indicator) in enumerate(cases):
  item=monitor.observe(lifecycle(attempted=(action,),denied=(action,)),binding(event_id=f"fw-event/tenant-a/harness-{index}"))
  assert item.event_class==threat and item.anomaly_indicators==(indicator,)
  assert item.purpose_sha256=="a"*64 and item.agent_ref.endswith("/codex-worker") and item.model_ref.endswith("/gpt-approved")
  assert item.action=="DETECT_ONLY" and not item.authority_granted
 assert len(calls)==len(cases)

def test_harness_monitor_uses_deterministic_priority_and_never_mutates_lifecycle():
 source=lifecycle(attempted=("permission.expand","evidence.modify"),denied=("permission.expand","evidence.modify")); before=source
 monitor=HarnessAIDMonitorAdapter("tenant-a",NormalizedEventStore(lambda *_:None)); item=monitor.observe(source,binding())
 assert item.event_class=="AID-TAMPER" and item.anomaly_indicators==("evidence_tamper",) and source==before

def test_harness_monitor_fails_closed_on_missing_cross_tenant_raw_unknown_replay_and_evidence_failure():
 store=NormalizedEventStore(lambda *_:None); monitor=HarnessAIDMonitorAdapter("tenant-a",store)
 with pytest.raises(AIThreatClassificationError,match="no closed"): monitor.observe(lifecycle(attempted=("benign.read",),denied=()),binding())
 with pytest.raises(AIThreatClassificationError,match="binding"): monitor.observe(lifecycle(tenant="tenant-b"),binding())
 with pytest.raises(AIThreatClassificationError,match="binding"): monitor.observe(lifecycle(worker=None),binding())
 with pytest.raises(AIThreatClassificationError,match="admission"): monitor.observe(lifecycle(),binding(session_ref="fw-session/tenant-b/s"))
 first=monitor.observe(lifecycle(),binding())
 with pytest.raises(AIThreatClassificationError,match="admission"): monitor.observe(lifecycle(),binding())
 assert store.pending_ai_security_events(tenant_id="tenant-a",agent_ref=first.agent_ref)==(first,)
 failed=HarnessAIDMonitorAdapter("tenant-a",NormalizedEventStore(lambda *_:(_ for _ in ()).throw(OSError("offline"))))
 with pytest.raises(AIThreatClassificationError,match="admission"): failed.observe(lifecycle(),binding())


def cross_fact(domain,index,**changes):
 value=dict(tenant_id="tenant-a",domain=domain,fact_ref=f"fw-fact/tenant-a/{domain}/fact-{index}",affected_ref=f"asset/{domain.lower()}",occurred_at_epoch=110+index,evidence_ref=f"fw-evid/tenant-a/{domain.lower()}-{index}"); value.update(changes); return CrossDomainSecurityFact(**value)

def classified_source():
 source=validate_ai_workload_event(event(event_class="AID-SECRETS",anomaly_indicators=["secret_access"],observed_at_epoch=100)); classifier=DeterministicAIThreatClassifier("tenant-a",lambda *_:None); finding=classifier.classify(source,finding_id="fw-finding/tenant-a/secrets-1"); return source,finding

def test_cross_domain_correlation_uses_canonical_soc_attack_story_and_ordered_refs():
 source,finding=classified_source(); calls=[]; correlator=AICrossDomainCorrelator("tenant-a",lambda *args:calls.append(args)); facts=(cross_fact("ENDPOINT",1),cross_fact("IDENTITY",2),cross_fact("NETWORK",3))
 story=correlator.correlate(finding,source,facts,story_id="story-aid-1",ai_incident_id="incident-ai",domain_incident_id="incident-domain")
 assert story.facts==facts and story.agent_ref==source.agent_ref and story.model_ref==source.model_ref and story.task_ref==source.task_ref
 assert story.projection.incident_ids==("incident-ai","incident-domain") and story.projection.action=="CORRELATE_ONLY" and story.confidence=="HIGH" and not story.authority_granted
 assert [call[0] for call in calls]==["soc_incident_projected","soc_incident_projected","soc_attack_story_projected"]

def test_cross_domain_correlation_denies_baseline_like_insufficient_replay_chronology_and_tenant():
 source,finding=classified_source(); calls=[]; correlator=AICrossDomainCorrelator("tenant-a",lambda *args:calls.append(args)); facts=(cross_fact("ENDPOINT",1),cross_fact("IDENTITY",2),cross_fact("NETWORK",3))
 for bad in ((facts[0],facts[1]),(facts[1],facts[0],facts[2]),(facts[0],facts[0],facts[2])):
  with pytest.raises(AIThreatClassificationError): correlator.correlate(finding,source,bad,story_id="bad",ai_incident_id="a",domain_incident_id="b")
 foreign=replace(facts[0],tenant_id="tenant-b",fact_ref="fw-fact/tenant-b/ENDPOINT/f",evidence_ref="fw-evid/tenant-b/f")
 with pytest.raises(AIThreatClassificationError): correlator.correlate(finding,source,(foreign,facts[1],facts[2]),story_id="cross",ai_incident_id="a",domain_incident_id="b")
 result=correlator.correlate(finding,source,facts,story_id="good",ai_incident_id="a",domain_incident_id="b")
 with pytest.raises(AIThreatClassificationError,match="replay"): correlator.correlate(finding,source,facts,story_id="good",ai_incident_id="c",domain_incident_id="d")
 assert result.projection.story_id=="good"

def test_cross_domain_correlation_revalidates_source_and_fails_closed_on_evidence():
 source,finding=classified_source(); facts=(cross_fact("ENDPOINT",1),cross_fact("IDENTITY",2),cross_fact("MCP",3))
 correlator=AICrossDomainCorrelator("tenant-a",lambda *_:(_ for _ in ()).throw(OSError("offline")))
 with pytest.raises(AIThreatClassificationError,match="Evidence"): correlator.correlate(finding,source,facts,story_id="story",ai_incident_id="a",domain_incident_id="b")
 with pytest.raises(AIThreatClassificationError,match="source binding"): AICrossDomainCorrelator("tenant-a",lambda *_:None).correlate(replace(finding,agent_ref="fw-id/tenant-a/other"),source,facts,story_id="story",ai_incident_id="a",domain_incident_id="b")
