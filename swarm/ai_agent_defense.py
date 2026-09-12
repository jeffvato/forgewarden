"""Deterministic fixture-only FW-AID threat classification."""
from __future__ import annotations
from dataclasses import dataclass
import re
from threading import RLock
from typing import Any
from .endpoint_fixtures import EndpointFixtureDenied
from .normalized_events import AIWorkloadSecurityEvent

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
