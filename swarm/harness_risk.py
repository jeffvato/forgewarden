"""Deterministic FW-HARNESS risk and assurance classification."""
from __future__ import annotations
from dataclasses import dataclass
from enum import IntEnum
from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Mapping

class HarnessRiskError(ValueError): pass
class AssuranceTier(IntEnum):
 T0=0; T1=1; T2=2; T3=3; T4=4

DENY_SIGNALS=frozenset({"self_authority_expansion","z3_bypass","action_ticket_forgery","tenant_isolation_weakening","evidence_disable","security_disable","kill_switch_bypass","unauthorized_deployment","approval_bypass","unrestricted_host_access","monitoring_disable"})
T4_SIGNALS=frozenset({"customer_root_change","signing_authority_change","destructive_recovery","root_authority_change"})
SECURITY_COMPONENTS=frozenset({"root","z3","identity","keys","policy","recovery","evidence","model_broker","mcp_gateway","deployment","sandbox","tenant_isolation","ransomware","ai_security"})
DANGEROUS_CAPABILITIES=frozenset({"shell_execution","dynamic_evaluation","dynamic_import","filesystem_traversal","network_listener","credential_access","secret_handling","unsafe_deserialization","dynamic_sql","permission_enforcement","cryptography","process_manipulation","arbitrary_tool_execution","mcp_exposure","deployment_execution"})

@dataclass(frozen=True)
class RiskPolicy:
 points: Mapping[str,int]
 boundaries: tuple[int,int,int,int]=(20,40,60,80)
 security_minimum: AssuranceTier=AssuranceTier.T3
 dangerous_minimum: AssuranceTier=AssuranceTier.T2
 def __post_init__(self):
  expected={"routine","many_files","many_subsystems","authentication_authorization","external_trust_boundary","mcp_tool_execution","cryptography","destructive_operation","root_z3_authority","tenant_boundary","high_reviewer_finding","repeated_validation_failure"}
  if not isinstance(self.points,Mapping) or set(self.points)!=expected or any(type(v) is not int or not 0<=v<=100 for v in self.points.values()): raise HarnessRiskError("risk policy points are invalid")
  if (not isinstance(self.boundaries,tuple) or len(self.boundaries)!=4 or tuple(sorted(set(self.boundaries)))!=self.boundaries or any(type(v) is not int or not 1<=v<=100 for v in self.boundaries)) or not isinstance(self.security_minimum,AssuranceTier) or not isinstance(self.dangerous_minimum,AssuranceTier): raise HarnessRiskError("risk policy tiers are invalid")
  object.__setattr__(self,"points",MappingProxyType(dict(self.points)))

DEFAULT_POLICY=RiskPolicy({"routine":10,"many_files":10,"many_subsystems":10,"authentication_authorization":25,"external_trust_boundary":15,"mcp_tool_execution":20,"cryptography":30,"destructive_operation":35,"root_z3_authority":50,"tenant_boundary":40,"high_reviewer_finding":25,"repeated_validation_failure":15})

@dataclass(frozen=True)
class TaskRiskFacts:
 task_id:str; tenant_id:str; request_tenant_id:str
 changed_file_count:int; subsystem_count:int
 signals:tuple[str,...]=(); components:tuple[str,...]=(); paths:tuple[str,...]=()
 dangerous_capabilities:tuple[str,...]=(); requested_max_tier:AssuranceTier|None=None

@dataclass(frozen=True)
class RiskDecision:
 task_id:str; tenant_id:str; score:int; tier:AssuranceTier; disposition:str
 reasons:tuple[str,...]; human_authorization_required:bool
 model_invocation_allowed:bool=False; authority_granted:bool=False
 mode:str="DRY_RUN"; deployment:str="DISABLED"

def _tier(score:int,boundaries:tuple[int,int,int,int])->AssuranceTier:
 b1,b2,b3,b4=boundaries
 return AssuranceTier.T4 if score>=b4 else AssuranceTier.T3 if score>=b3 else AssuranceTier.T2 if score>=b2 else AssuranceTier.T1 if score>=b1 else AssuranceTier.T0

def classify_risk(facts:TaskRiskFacts,policy:RiskPolicy=DEFAULT_POLICY)->RiskDecision:
 if not isinstance(facts,TaskRiskFacts) or not isinstance(policy,RiskPolicy): raise HarnessRiskError("risk input is invalid")
 if not facts.task_id.startswith("FWQ-") or not facts.tenant_id or facts.request_tenant_id!=facts.tenant_id: raise HarnessRiskError("task or tenant binding is invalid")
 if type(facts.changed_file_count) is not int or type(facts.subsystem_count) is not int or facts.changed_file_count<0 or facts.subsystem_count<0: raise HarnessRiskError("risk counts are invalid")
 for values,allowed,name in ((facts.signals,set(policy.points)|DENY_SIGNALS|T4_SIGNALS,"signal"),(facts.components,SECURITY_COMPONENTS,"component"),(facts.dangerous_capabilities,DANGEROUS_CAPABILITIES,"capability")):
  if not isinstance(values,tuple) or len(values)>64 or len(set(values))!=len(values) or any(v not in allowed for v in values): raise HarnessRiskError(f"unknown or duplicate {name}")
 if not isinstance(facts.paths,tuple) or len(facts.paths)>64 or len(set(facts.paths))!=len(facts.paths): raise HarnessRiskError("paths are invalid")
 for value in facts.paths:
  path=PurePosixPath(value)
  if not value or path.is_absolute() or ".." in path.parts: raise HarnessRiskError("path escapes task scope")
 if facts.requested_max_tier is not None and not isinstance(facts.requested_max_tier,AssuranceTier): raise HarnessRiskError("requested tier is invalid")
 denied=tuple(sorted(set(facts.signals)&DENY_SIGNALS))
 if denied:
  return RiskDecision(facts.task_id,facts.tenant_id,100,AssuranceTier.T4,"DENIED_POLICY_INVARIANT",denied,True)
 active=[s for s in facts.signals if s in policy.points]
 score=policy.points["routine"]+sum(policy.points[s] for s in active if s!="routine")
 if facts.changed_file_count>5: score+=policy.points["many_files"]; active.append("many_files")
 if facts.subsystem_count>2: score+=policy.points["many_subsystems"]; active.append("many_subsystems")
 score=min(score,100); tier=_tier(score,policy.boundaries)
 path_security=any(any(part.rsplit('.',1)[0] in SECURITY_COMPONENTS for part in PurePosixPath(p).parts) for p in facts.paths)
 if facts.components or path_security: tier=max(tier,policy.security_minimum); active.append("security_minimum")
 if facts.dangerous_capabilities: tier=max(tier,policy.dangerous_minimum); active.append("dangerous_capability_minimum")
 if set(facts.signals)&T4_SIGNALS: tier=AssuranceTier.T4; active.append("protected_authority")
 if facts.requested_max_tier is not None and facts.requested_max_tier<tier: raise HarnessRiskError("requested tier would downgrade assurance")
 return RiskDecision(facts.task_id,facts.tenant_id,score,tier,"HUMAN_AUTHORIZATION_REQUIRED" if tier is AssuranceTier.T4 else "CLASSIFIED",tuple(sorted(set(active))),tier is AssuranceTier.T4)
