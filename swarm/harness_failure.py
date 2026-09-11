"""Bounded deterministic FW-HARNESS failure escalation evidence."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Any, Callable
from pathlib import PurePosixPath
import re
from .harness_risk import AssuranceTier

class HarnessFailureError(ValueError): pass

_ID=re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,254}$")
_SHA=re.compile(r"^[0-9a-f]{64}$")
_SECRET=re.compile(r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=])")
FAILURES=frozenset({"ordinary","validation","reviewer_architecture","reviewer_security","unexpected_cross_subsystem","unknown_security","scope_escape","budget_exhausted","kill_switch","evidence_failure"})
ACTIONS=frozenset({"SAME_TIER_REPAIR","ESCALATE_TIER","HUMAN_ESCALATION","BLOCK"})

@dataclass(frozen=True)
class FailureObservation:
 packet_id:str; task_id:str; tenant_id:str; tier:AssuranceTier
 attempt_count:int; same_error_count:int; failure_classes:tuple[str,...]
 model_ids:tuple[str,...]; validations:tuple[str,...]; failures:tuple[str,...]
 changed_files:tuple[str,...]; diff_summary:str; reviewer_findings:tuple[str,...]
 escalation_history:tuple[str,...]; evidence_references:tuple[str,...]
 model_confidence:float|None=None; requested_tier:AssuranceTier|None=None
 budget_exhausted:bool=False; kill_switch:str="ENGAGED"

@dataclass(frozen=True)
class FailurePacket:
 packet_id:str; task_id:str; tenant_id:str; original_tier:AssuranceTier
 resulting_tier:AssuranceTier; disposition:str; attempts:int
 model_ids:tuple[str,...]; validations:tuple[str,...]; failures:tuple[str,...]
 changed_files:tuple[str,...]; diff_summary:str; reviewer_findings:tuple[str,...]
 escalation_history:tuple[str,...]; evidence_references:tuple[str,...]
 recommended_action:str; evidence_reference:str
 authority_granted:bool=False; executed:bool=False
 mode:str="DRY_RUN"; deployment:str="DISABLED"

def _items(values:tuple[str,...],name:str,maximum:int=64)->tuple[str,...]:
 if not isinstance(values,tuple) or len(values)>maximum or len(set(values))!=len(values): raise HarnessFailureError(f"{name} is malformed")
 for value in values:
  if not isinstance(value,str) or not value or len(value.encode())>512 or _SECRET.search(value): raise HarnessFailureError(f"{name} is secret-bearing or unbounded")
 return values

def create_failure_packet(observation:FailureObservation,*,evidence_sink:Callable[[str,dict[str,Any]],None],consumed_packet_ids:tuple[str,...]=())->FailurePacket:
 if not isinstance(observation,FailureObservation): raise HarnessFailureError("failure observation is malformed")
 for value,name in ((observation.packet_id,"packet"),(observation.task_id,"task"),(observation.tenant_id,"tenant")):
  if not isinstance(value,str) or not _ID.fullmatch(value): raise HarnessFailureError(f"{name} identity is malformed")
 if not isinstance(observation.tier,AssuranceTier) or type(observation.attempt_count) is not int or type(observation.same_error_count) is not int or observation.attempt_count<1 or observation.same_error_count<1 or observation.same_error_count>observation.attempt_count: raise HarnessFailureError("failure counters are invalid")
 classes=_items(observation.failure_classes,"failure classes")
 if not classes or any(value not in FAILURES for value in classes): raise HarnessFailureError("failure class is unknown")
 if type(observation.budget_exhausted) is not bool or observation.kill_switch not in {"ENGAGED","DISENGAGED"}: raise HarnessFailureError("safety state is malformed")
 if observation.model_confidence is not None and (not isinstance(observation.model_confidence,(int,float)) or isinstance(observation.model_confidence,bool) or not 0<=observation.model_confidence<=1): raise HarnessFailureError("model confidence is malformed")
 if observation.requested_tier is not None and not isinstance(observation.requested_tier,AssuranceTier): raise HarnessFailureError("requested tier is malformed")
 if not isinstance(consumed_packet_ids,tuple) or len(consumed_packet_ids)>1024 or len(set(consumed_packet_ids))!=len(consumed_packet_ids) or observation.packet_id in consumed_packet_ids: raise HarnessFailureError("failure packet replay denied")
 models=_items(observation.model_ids,"models"); validations=_items(observation.validations,"validations"); failures=_items(observation.failures,"failures"); files=_items(observation.changed_files,"changed files"); findings=_items(observation.reviewer_findings,"reviewer findings"); history=_items(observation.escalation_history,"escalation history"); refs=_items(observation.evidence_references,"evidence references")
 if any(PurePosixPath(value).is_absolute() or '..' in PurePosixPath(value).parts for value in files): raise HarnessFailureError('changed file escapes scope')
 if any(f'/{observation.tenant_id}/' not in value for value in refs): raise HarnessFailureError('Evidence reference tenant mismatch')
 if not observation.diff_summary or len(observation.diff_summary.encode())>1024 or _SECRET.search(observation.diff_summary): raise HarnessFailureError("diff summary is invalid")
 blocking=observation.budget_exhausted or observation.kill_switch!="ENGAGED" or bool(set(classes)&{"scope_escape","budget_exhausted","kill_switch","evidence_failure"})
 security=bool(set(classes)&{"reviewer_architecture","reviewer_security","unexpected_cross_subsystem","unknown_security"})
 if blocking:
  resulting=observation.tier; disposition="BLOCK"
 elif observation.tier is AssuranceTier.T4:
  resulting=AssuranceTier.T4; disposition="HUMAN_ESCALATION"
 elif security or observation.same_error_count>=2:
  resulting=AssuranceTier(observation.tier+1); disposition="HUMAN_ESCALATION" if resulting is AssuranceTier.T4 else "ESCALATE_TIER"
 elif observation.attempt_count==1:
  resulting=observation.tier; disposition="SAME_TIER_REPAIR"
 else:
  resulting=AssuranceTier(observation.tier+1); disposition="HUMAN_ESCALATION" if resulting is AssuranceTier.T4 else "ESCALATE_TIER"
 if observation.requested_tier is not None and observation.requested_tier<resulting: pass
 action={"SAME_TIER_REPAIR":"issue one bounded repair task","ESCALATE_TIER":"replan at required higher assurance","HUMAN_ESCALATION":"request human authorization","BLOCK":"stop and preserve state"}[disposition]
 reference=f"fw-evid/{observation.tenant_id}/harness-failure/{observation.packet_id}"
 packet=FailurePacket(observation.packet_id,observation.task_id,observation.tenant_id,observation.tier,resulting,disposition,observation.attempt_count,models,validations,failures,files,observation.diff_summary,findings,history,refs,action,reference)
 if not callable(evidence_sink): raise HarnessFailureError("canonical Evidence sink is unavailable")
 try: evidence_sink("fw_harness_failure_packet",asdict(packet))
 except Exception as exc: raise HarnessFailureError("Failure Packet Evidence write failed") from exc
 return packet
