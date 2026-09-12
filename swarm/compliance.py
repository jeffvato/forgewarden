"""Authority-free FW-COMP control mapping metadata."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import re
from threading import RLock
from typing import Any

class ComplianceContractError(ValueError): pass

_ID=re.compile(r"^[a-z][a-z0-9_.:/-]{0,191}$"); _CONTROL=re.compile(r"^FW-CTRL-[0-9]{4}$"); _REQ=re.compile(r"^FW-[A-Z0-9]+-[0-9]{3}$"); _EVID=re.compile(r"^fw-evid/([a-z][a-z0-9_.-]{0,127})/[a-z][a-z0-9_.:/-]{0,191}$"); _FRAMEWORK=re.compile(r"^(NIST-CSF-2\.0|NIST-800-53|CIS-CONTROLS-8):[A-Z0-9. -]{1,64}$"); _SECRET=re.compile(r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=])")
STATUSES=frozenset({"PLANNED","DESIGNED","STUBBED","PARTIAL","IMPLEMENTED","TESTED","SECURITY_VALIDATED","DEMO_AVAILABLE","PRODUCTION_READY"}); VALIDATIONS=frozenset({"NOT_VALIDATED","TESTED","SECURITY_REVIEWED"})

def _bounded(value:Any,name:str,pattern:re.Pattern[str]=_ID)->str:
 if not isinstance(value,str) or value!=value.strip() or not pattern.fullmatch(value) or _SECRET.search(value): raise ComplianceContractError(f"{name} is invalid")
 return value

@dataclass(frozen=True)
class ControlMapping:
 schema_version:str; mapping_id:str; tenant_id:str; control_id:str; requirement_ids:tuple[str,...]; owner:str; implementation_status:str; evidence_references:tuple[str,...]; validation_state:str; framework_references:tuple[str,...]; occurred_at:str; claim_status:str="MAPPING_ONLY"; mode:str="DRY_RUN"; deployment:str="DISABLED"; authority_granted:bool=False
 def __post_init__(self):
  if self.schema_version!="1": raise ComplianceContractError("mapping version invalid")
  tenant=_bounded(self.tenant_id,"tenant")
  if not _bounded(self.mapping_id,"mapping").startswith(f"fw-comp/{tenant}/"): raise ComplianceContractError("mapping tenant mismatch")
  _bounded(self.control_id,"control",_CONTROL); _bounded(self.owner,"owner")
  if not isinstance(self.requirement_ids,tuple) or not self.requirement_ids or tuple(sorted(set(self.requirement_ids)))!=self.requirement_ids: raise ComplianceContractError("requirements invalid")
  for value in self.requirement_ids: _bounded(value,"requirement",_REQ)
  if self.implementation_status not in STATUSES or self.validation_state not in VALIDATIONS: raise ComplianceContractError("status invalid")
  if not isinstance(self.evidence_references,tuple) or not self.evidence_references or tuple(sorted(set(self.evidence_references)))!=self.evidence_references: raise ComplianceContractError("Evidence references invalid")
  for value in self.evidence_references:
   match=_EVID.fullmatch(_bounded(value,"Evidence reference",_EVID))
   if match is None or match.group(1)!=tenant: raise ComplianceContractError("Evidence tenant mismatch")
  if not isinstance(self.framework_references,tuple) or not self.framework_references or tuple(sorted(set(self.framework_references)))!=self.framework_references: raise ComplianceContractError("framework references invalid")
  for value in self.framework_references: _bounded(value,"framework reference",_FRAMEWORK)
  try: datetime.strptime(self.occurred_at,"%Y-%m-%dT%H:%M:%SZ")
  except (TypeError,ValueError) as exc: raise ComplianceContractError("timestamp invalid") from exc
  if self.claim_status!="MAPPING_ONLY" or self.mode!="DRY_RUN" or self.deployment!="DISABLED" or self.authority_granted is not False: raise ComplianceContractError("compliance authority or certification claim forbidden")

class ControlMappingRegistry:
 """Evidence-first create-once registry; mappings never prove certification."""
 def __init__(self,tenant_id:str,evidence_sink:Any):
  self.tenant_id=_bounded(tenant_id,"tenant")
  if not callable(evidence_sink): raise ComplianceContractError("Evidence sink required")
  self._sink=evidence_sink; self._records:dict[str,ControlMapping]={}; self._pending:set[str]=set(); self._lock=RLock()
 def register(self,mapping:ControlMapping)->ControlMapping:
  if not isinstance(mapping,ControlMapping) or mapping.tenant_id!=self.tenant_id: raise ComplianceContractError("mapping tenant mismatch")
  with self._lock:
   if mapping.mapping_id in self._records or mapping.mapping_id in self._pending: raise ComplianceContractError("mapping duplicate or pending")
   self._pending.add(mapping.mapping_id)
  try:
   self._sink({"event":"FW_COMP_MAPPING_REGISTERED","mapping_id":mapping.mapping_id,"tenant_id":mapping.tenant_id,"control_id":mapping.control_id,"requirements":mapping.requirement_ids,"implementation_status":mapping.implementation_status,"validation_state":mapping.validation_state,"framework_references":mapping.framework_references,"evidence_references":mapping.evidence_references,"claim_status":"MAPPING_ONLY","authority_granted":False})
   with self._lock: self._records[mapping.mapping_id]=mapping
  except Exception as exc: raise ComplianceContractError("mapping Evidence failed") from exc
  finally:
   with self._lock: self._pending.discard(mapping.mapping_id)
  return mapping
 def snapshot(self,tenant_id:str)->tuple[ControlMapping,...]:
  if tenant_id!=self.tenant_id: raise ComplianceContractError("mapping tenant mismatch")
  with self._lock: return tuple(self._records[key] for key in sorted(self._records))
