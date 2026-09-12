"""Deterministic fixture-only FW-AID threat classification."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import re
from threading import RLock
from typing import Any
from .endpoint_fixtures import EndpointFixtureDenied
from .normalized_events import AIWorkloadSecurityEvent, NormalizedEventStore
from .harness_evidence import HarnessLifecycleEvidence, validate_harness_lifecycle_evidence
from .soc import SOCAttackStoryProjection, SOCIncidentDenied, project_attack_story, project_soc_incident

class AIThreatClassificationError(ValueError): pass

_RULES={
 "AID-ESCAPE":({"sandbox_escape","host_resource_access","namespace_violation"},"CRITICAL"),
 "AID-EGRESS":({"unauthorized_egress","dns_anomaly","network_probe","exfiltration_pattern"},"HIGH"),
 "AID-SECRETS":({"secret_access","credential_discovery","root_material_request"},"CRITICAL"),
 "AID-PRIVILEGE":({"authority_expansion","self_authorization","repeated_denial"},"CRITICAL"),
 "AID-LATERAL":({"lateral_movement","cross_tenant_target","unrelated_resource_access"},"CRITICAL"),
 "AID-INJECTION":({"prompt_injection","poisoned_retrieval","constraint_override"},"HIGH"),
 "AID-MISSION":({"mission_deviation","unexpected_tool","unexpected_model"},"HIGH"),
 "AID-COORDINATION":({"unapproved_coordination","covert_channel","unauthorized_delegation"},"HIGH"),
 "AID-EVALUATION":({"test_manipulation","reviewer_manipulation","failure_concealment"},"CRITICAL"),
 "AID-TAMPER":({"security_control_tamper","evidence_tamper","kill_switch_clear"},"CRITICAL"),
}
_FINDING=re.compile(r"^fw-finding/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")

@dataclass(frozen=True)
class AIThreatFinding:
 schema_version:str; finding_id:str; tenant_id:str; source_event_id:str; agent_ref:str; threat_class:str; severity:str; confidence:int; matched_facts:tuple[str,...]; evidence_references:tuple[str,...]; observed_at_epoch:int; disposition:str="ADVISORY"; action:str="DETECT_ONLY"; mode:str="DRY_RUN"; authority_granted:bool=False
 def __post_init__(self):
  match=_FINDING.fullmatch(self.finding_id) if isinstance(self.finding_id,str) else None
  if self.schema_version!="1" or match is None or match.group(1)!=self.tenant_id: raise AIThreatClassificationError("finding identity or tenant invalid")
  if self.threat_class not in _RULES or self.severity not in {"HIGH","CRITICAL"}: raise AIThreatClassificationError("finding classification invalid")
  if not isinstance(self.confidence,int) or isinstance(self.confidence,bool) or not 0<=self.confidence<=100: raise AIThreatClassificationError("finding confidence invalid")
  allowed=_RULES[self.threat_class][0]
  if not self.matched_facts or tuple(sorted(set(self.matched_facts)))!=self.matched_facts or not set(self.matched_facts)<=allowed: raise AIThreatClassificationError("finding facts invalid")
  if not isinstance(self.evidence_references,tuple) or tuple(sorted(set(self.evidence_references)))!=self.evidence_references: raise AIThreatClassificationError("finding Evidence invalid")
  if self.disposition!="ADVISORY" or self.action!="DETECT_ONLY" or self.mode!="DRY_RUN" or self.authority_granted is not False: raise AIThreatClassificationError("finding authority forbidden")

class DeterministicAIThreatClassifier:
 """Closed rules with Evidence-before-state admission; no model is consulted."""
 def __init__(self,tenant_id:str,evidence_sink:Any):
  if not isinstance(tenant_id,str) or not tenant_id or not callable(evidence_sink): raise AIThreatClassificationError("classifier configuration invalid")
  self.tenant_id=tenant_id; self._sink=evidence_sink; self._records:dict[str,AIThreatFinding]={}; self._pending:set[str]=set(); self._lock=RLock()
 def classify(self,event:AIWorkloadSecurityEvent,*,finding_id:str)->AIThreatFinding:
  if not isinstance(event,AIWorkloadSecurityEvent) or event.tenant_id!=self.tenant_id: raise AIThreatClassificationError("source event tenant mismatch")
  allowed,severity=_RULES[event.event_class]; matched=tuple(sorted(set(event.anomaly_indicators)&allowed))
  if not matched: raise AIThreatClassificationError("insufficient canonical facts")
  confidence=min(95,70+10*len(matched))
  finding=AIThreatFinding("1",finding_id,event.tenant_id,event.event_id,event.agent_ref,event.event_class,severity,confidence,matched,event.evidence_references,event.observed_at_epoch)
  with self._lock:
   if finding.finding_id in self._records or finding.finding_id in self._pending: raise AIThreatClassificationError("finding duplicate or pending")
   self._pending.add(finding.finding_id)
  try:
   self._sink("ai_threat_finding_admitted", {name:getattr(finding,name) for name in finding.__dataclass_fields__})
   with self._lock: self._records[finding.finding_id]=finding
  except Exception as exc: raise AIThreatClassificationError("finding Evidence failed") from exc
  finally:
   with self._lock: self._pending.discard(finding.finding_id)
  return finding
 def snapshot(self,tenant_id:str)->tuple[AIThreatFinding,...]:
  if tenant_id!=self.tenant_id: raise AIThreatClassificationError("finding tenant mismatch")
  with self._lock: return tuple(self._records[key] for key in sorted(self._records))


_HARNESS_SIGNALS={
 "sandbox.escape":("AID-ESCAPE","sandbox_escape","PROCESS"),
 "network.egress":("AID-EGRESS","unauthorized_egress","NETWORK"),
 "secret.read":("AID-SECRETS","secret_access","CREDENTIAL"),
 "permission.expand":("AID-PRIVILEGE","authority_expansion","NONE"),
 "self.authorize":("AID-PRIVILEGE","self_authorization","NONE"),
 "tenant.cross":("AID-LATERAL","cross_tenant_target","NONE"),
 "prompt.injected":("AID-INJECTION","prompt_injection","NONE"),
 "path.out_of_scope":("AID-MISSION","mission_deviation","FILESYSTEM"),
 "git.out_of_scope":("AID-MISSION","mission_deviation","FILESYSTEM"),
 "mcp.unapproved":("AID-MISSION","unexpected_tool","MCP"),
 "model.unexpected":("AID-MISSION","unexpected_model","NONE"),
 "agent.coordinate":("AID-COORDINATION","unapproved_coordination","NONE"),
 "review.manipulate":("AID-EVALUATION","reviewer_manipulation","NONE"),
 "test.manipulate":("AID-EVALUATION","test_manipulation","FILESYSTEM"),
 "evidence.modify":("AID-TAMPER","evidence_tamper","FILESYSTEM"),
 "kill_switch.clear":("AID-TAMPER","kill_switch_clear","NONE"),
}
_HARNESS_PRIORITY=("AID-TAMPER","AID-ESCAPE","AID-SECRETS","AID-LATERAL","AID-PRIVILEGE","AID-EVALUATION","AID-EGRESS","AID-INJECTION","AID-COORDINATION","AID-MISSION")

@dataclass(frozen=True)
class HarnessMonitorBinding:
 event_id:str; session_ref:str; capability_lease_ref:str; action_ticket_ref:str; mcp_server_ref:str; target_resource_ref:str; evidence_references:tuple[str,...]

class HarnessAIDMonitorAdapter:
 """Separate deterministic adapter from validated harness facts to FW-AID telemetry."""
 def __init__(self,tenant_id:str,event_store:NormalizedEventStore):
  if not isinstance(event_store,NormalizedEventStore) or not isinstance(tenant_id,str) or not tenant_id: raise AIThreatClassificationError("monitor configuration invalid")
  self.tenant_id=tenant_id; self._store=event_store
 def observe(self,lifecycle:HarnessLifecycleEvidence,binding:HarnessMonitorBinding)->AIWorkloadSecurityEvent:
  lifecycle=validate_harness_lifecycle_evidence(lifecycle)
  if lifecycle.tenant_id!=self.tenant_id or not isinstance(binding,HarnessMonitorBinding) or lifecycle.worker_id is None or lifecycle.model_id is None: raise AIThreatClassificationError("monitor binding invalid")
  signals=[]
  for action in lifecycle.denied_actions+lifecycle.attempted_actions:
   if action in _HARNESS_SIGNALS: signals.append(_HARNESS_SIGNALS[action])
  if not signals: raise AIThreatClassificationError("no closed harness anomaly")
  threat=next(item for item in _HARNESS_PRIORITY if any(signal[0]==item for signal in signals))
  matching=[signal for signal in signals if signal[0]==threat]; indicators=tuple(sorted({signal[1] for signal in matching})); tool=next((signal[2] for signal in matching if signal[2]!="NONE"),"NONE")
  value={"schema_version":"1","event_id":binding.event_id,"tenant_id":self.tenant_id,"event_class":threat,"source":"fw-harness.fixture","classification":"INTERNAL","observed_at_epoch":int(datetime.fromisoformat(lifecycle.timestamp.replace("Z","+00:00")).timestamp()),"agent_ref":f"fw-id/{self.tenant_id}/{lifecycle.worker_id.lower()}","model_ref":f"fw-model/{self.tenant_id}/{lifecycle.model_id.lower()}","session_ref":binding.session_ref,"task_ref":f"fw-task/{self.tenant_id}/{lifecycle.task_id.lower()}","initiating_user_ref":f"fw-id/{self.tenant_id}/{lifecycle.actor_id.lower()}","purpose_sha256":lifecycle.context_sha256,"capability_lease_ref":binding.capability_lease_ref,"action_ticket_ref":binding.action_ticket_ref,"tool_category":tool,"mcp_server_ref":binding.mcp_server_ref,"target_resource_ref":binding.target_resource_ref,"decision":"DENIED" if lifecycle.denied_actions else "OBSERVED","anomaly_indicators":indicators,"evidence_references":binding.evidence_references,"mode":"DRY_RUN","action":"DETECT_ONLY","authority_granted":False}
  try: return self._store.admit_ai_security_event(value)
  except EndpointFixtureDenied as exc: raise AIThreatClassificationError("harness monitor admission failed") from exc


_CROSS_DOMAINS=frozenset({"AV","ENDPOINT","IDENTITY","BROWSER_EMAIL","MCP","NETWORK"})
_FACT_REF=re.compile(r"^fw-fact/([a-z][a-z0-9_.-]{0,127})/(AV|ENDPOINT|IDENTITY|BROWSER_EMAIL|MCP|NETWORK)/[a-z][a-z0-9_.:/-]{0,191}$")

@dataclass(frozen=True)
class CrossDomainSecurityFact:
 tenant_id:str; domain:str; fact_ref:str; affected_ref:str; occurred_at_epoch:int; evidence_ref:str
 def __post_init__(self):
  match=_FACT_REF.fullmatch(self.fact_ref) if isinstance(self.fact_ref,str) else None
  if self.domain not in _CROSS_DOMAINS or match is None or match.group(1)!=self.tenant_id or match.group(2)!=self.domain: raise AIThreatClassificationError("cross-domain fact binding invalid")
  prefix=f"fw-evid/{self.tenant_id}/"
  if not isinstance(self.evidence_ref,str) or not self.evidence_ref.startswith(prefix) or not isinstance(self.affected_ref,str) or not self.affected_ref or not isinstance(self.occurred_at_epoch,int) or isinstance(self.occurred_at_epoch,bool) or self.occurred_at_epoch<0: raise AIThreatClassificationError("cross-domain fact invalid")

@dataclass(frozen=True)
class AIAttackStory:
 tenant_id:str; finding_id:str; source_event_id:str; agent_ref:str; model_ref:str; task_ref:str; facts:tuple[CrossDomainSecurityFact,...]; projection:SOCAttackStoryProjection; confidence:str="HIGH"; mode:str="DRY_ONLY"; action:str="CORRELATE_ONLY"; authority_granted:bool=False

class AICrossDomainCorrelator:
 """Compose validated references through canonical FW-SOC projections."""
 def __init__(self,tenant_id:str,audit:Any):
  if not isinstance(tenant_id,str) or not tenant_id or not callable(audit): raise AIThreatClassificationError("correlator configuration invalid")
  self.tenant_id=tenant_id; self._audit=audit; self._stories:set[str]=set(); self._pending:set[str]=set(); self._lock=RLock()
 def correlate(self,finding:AIThreatFinding,event:AIWorkloadSecurityEvent,facts:tuple[CrossDomainSecurityFact,...],*,story_id:str,ai_incident_id:str,domain_incident_id:str)->AIAttackStory:
  if not isinstance(finding,AIThreatFinding) or not isinstance(event,AIWorkloadSecurityEvent) or finding.tenant_id!=self.tenant_id or event.tenant_id!=self.tenant_id or finding.source_event_id!=event.event_id or finding.agent_ref!=event.agent_ref or finding.threat_class!=event.event_class: raise AIThreatClassificationError("correlation source binding invalid")
  if not isinstance(facts,tuple) or not 3<=len(facts)<=32 or any(not isinstance(item,CrossDomainSecurityFact) or item.tenant_id!=self.tenant_id for item in facts): raise AIThreatClassificationError("correlation facts invalid")
  ordered=tuple(sorted(facts,key=lambda item:(item.occurred_at_epoch,item.fact_ref)))
  if ordered!=facts or len({item.fact_ref for item in facts})!=len(facts): raise AIThreatClassificationError("correlation chronology or replay invalid")
  domains={item.domain for item in facts}
  if "ENDPOINT" not in domains or len(domains)<3: raise AIThreatClassificationError("insufficient cross-domain confidence")
  with self._lock:
   if story_id in self._stories or story_id in self._pending: raise AIThreatClassificationError("correlation replay or pending")
   self._pending.add(story_id)
  try:
   shared_affected=sorted({event.agent_ref}|{item.affected_ref for item in facts})
   evidence=sorted(set(finding.evidence_references)|{item.evidence_ref for item in facts})
   common=dict(tenant_id=self.tenant_id,title="AI-enabled intrusion correlation",severity="CRITICAL" if finding.severity=="CRITICAL" else "HIGH",status="OPEN",created_at_epoch=min(event.observed_at_epoch,facts[0].occurred_at_epoch),updated_at_epoch=max(item.occurred_at_epoch for item in facts),affected_refs=shared_affected,normalized_event_refs=[event.event_id],evidence_refs=evidence,disposition="NONE")
   ai=project_soc_incident(dict(common,incident_id=ai_incident_id),tenant_id=self.tenant_id,now_epoch=common["updated_at_epoch"],audit=self._audit)
   domain=project_soc_incident(dict(common,incident_id=domain_incident_id),tenant_id=self.tenant_id,now_epoch=common["updated_at_epoch"],audit=self._audit)
   projection=project_attack_story((ai,domain),story_id=story_id,tenant_id=self.tenant_id,audit=self._audit)
   result=AIAttackStory(self.tenant_id,finding.finding_id,event.event_id,event.agent_ref,event.model_ref,event.task_ref,facts,projection)
   with self._lock: self._stories.add(story_id)
   return result
  except SOCIncidentDenied as exc:
   raise AIThreatClassificationError("cross-domain Evidence or projection failed") from exc
  finally:
   with self._lock: self._pending.discard(story_id)


_PROPOSAL_ACTIONS={"AID-ESCAPE":"ISOLATE_WORKLOAD","AID-EGRESS":"DENY_EGRESS","AID-SECRETS":"REVOKE_LEASE","AID-PRIVILEGE":"FREEZE_SESSION","AID-LATERAL":"ISOLATE_WORKLOAD","AID-INJECTION":"BLOCK_TOOL","AID-MISSION":"FREEZE_SESSION","AID-COORDINATION":"FREEZE_SESSION","AID-EVALUATION":"FREEZE_SESSION","AID-TAMPER":"FREEZE_SESSION"}
_PROPOSAL_REF=re.compile(r"^fw-(?:proposal|policy|lease|action|approval|checkpoint|rollback|evid|resource)/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$")

@dataclass(frozen=True)
class AIContainmentProposal:
 schema_version:str; proposal_id:str; tenant_id:str; finding_id:str; story_id:str; action_class:str; target_ref:str; blast_radius:int; policy_decision_ref:str; capability_lease_ref:str; action_ticket_ref:str; approval_ref:str; checkpoint_ref:str; rollback_ref:str; evidence_references:tuple[str,...]; created_at_epoch:int; lease_expires_at_epoch:int; mode:str="DRY_RUN"; deployment:str="DISABLED"; kill_switch:str="ENGAGED"; disposition:str="PROPOSE_ONLY"; authority_granted:bool=False; response_executed:bool=False
 def __post_init__(self):
  for value,name in ((self.proposal_id,"proposal"),(self.target_ref,"target"),(self.policy_decision_ref,"policy"),(self.capability_lease_ref,"lease"),(self.action_ticket_ref,"ticket"),(self.approval_ref,"approval"),(self.checkpoint_ref,"checkpoint"),(self.rollback_ref,"rollback")):
   match=_PROPOSAL_REF.fullmatch(value) if isinstance(value,str) else None
   if match is None or match.group(1)!=self.tenant_id: raise AIThreatClassificationError(f"containment {name} binding invalid")
  if self.schema_version!="1" or self.action_class not in set(_PROPOSAL_ACTIONS.values()) or not isinstance(self.blast_radius,int) or isinstance(self.blast_radius,bool) or not 1<=self.blast_radius<=10: raise AIThreatClassificationError("containment policy bounds invalid")
  if not isinstance(self.created_at_epoch,int) or not isinstance(self.lease_expires_at_epoch,int) or not self.created_at_epoch<self.lease_expires_at_epoch<=self.created_at_epoch+3600: raise AIThreatClassificationError("containment lease invalid")
  if not self.evidence_references or tuple(sorted(set(self.evidence_references)))!=self.evidence_references: raise AIThreatClassificationError("containment Evidence invalid")
  for ref in self.evidence_references:
   match=_PROPOSAL_REF.fullmatch(ref) if isinstance(ref,str) else None
   if match is None or match.group(1)!=self.tenant_id or not ref.startswith("fw-evid/"): raise AIThreatClassificationError("containment Evidence binding invalid")
  if self.mode!="DRY_RUN" or self.deployment!="DISABLED" or self.kill_switch!="ENGAGED" or self.disposition!="PROPOSE_ONLY" or self.authority_granted is not False or self.response_executed is not False: raise AIThreatClassificationError("containment execution or authority forbidden")

class AIContainmentProposalRegistry:
 """Evidence-first inert proposals; contains deliberately no executor."""
 def __init__(self,tenant_id:str,evidence_sink:Any):
  if not isinstance(tenant_id,str) or not tenant_id or not callable(evidence_sink): raise AIThreatClassificationError("containment registry configuration invalid")
  self.tenant_id=tenant_id; self._sink=evidence_sink; self._records:dict[str,AIContainmentProposal]={}; self._pending:set[str]=set(); self._lock=RLock()
 def propose(self,finding:AIThreatFinding,story:AIAttackStory,*,proposal_id:str,target_ref:str,blast_radius:int,policy_decision_ref:str,capability_lease_ref:str,action_ticket_ref:str,approval_ref:str,checkpoint_ref:str,rollback_ref:str,evidence_references:tuple[str,...],created_at_epoch:int,lease_expires_at_epoch:int)->AIContainmentProposal:
  if not isinstance(finding,AIThreatFinding) or not isinstance(story,AIAttackStory) or finding.tenant_id!=self.tenant_id or story.tenant_id!=self.tenant_id or story.finding_id!=finding.finding_id or story.source_event_id!=finding.source_event_id or story.mode!="DRY_ONLY" or story.action!="CORRELATE_ONLY" or story.authority_granted is not False: raise AIThreatClassificationError("containment source binding invalid")
  proposal=AIContainmentProposal("1",proposal_id,self.tenant_id,finding.finding_id,story.projection.story_id,_PROPOSAL_ACTIONS[finding.threat_class],target_ref,blast_radius,policy_decision_ref,capability_lease_ref,action_ticket_ref,approval_ref,checkpoint_ref,rollback_ref,evidence_references,created_at_epoch,lease_expires_at_epoch)
  with self._lock:
   if proposal.proposal_id in self._records or proposal.proposal_id in self._pending: raise AIThreatClassificationError("containment proposal replay or pending")
   self._pending.add(proposal.proposal_id)
  try:
   self._sink("ai_containment_proposal_recorded",{name:getattr(proposal,name) for name in proposal.__dataclass_fields__})
   with self._lock:self._records[proposal.proposal_id]=proposal
  except Exception as exc: raise AIThreatClassificationError("containment proposal Evidence failed") from exc
  finally:
   with self._lock:self._pending.discard(proposal.proposal_id)
  return proposal
 def snapshot(self,tenant_id:str)->tuple[AIContainmentProposal,...]:
  if tenant_id!=self.tenant_id: raise AIThreatClassificationError("containment tenant mismatch")
  with self._lock:return tuple(self._records[key] for key in sorted(self._records))
