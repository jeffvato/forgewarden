"""Authority-free FW-COMP control mapping metadata."""
from __future__ import annotations
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import re
from threading import RLock
from typing import Any

from .evidence import EvidenceContractError, EvidenceLedger, EvidenceRecord, validate_evidence_envelope

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
 def resolve_exact(self,mapping:ControlMapping)->ControlMapping:
  if not isinstance(mapping,ControlMapping) or mapping.tenant_id!=self.tenant_id: raise ComplianceContractError("mapping tenant mismatch")
  with self._lock:
   registered=self._records.get(mapping.mapping_id)
   if registered is None or registered != mapping: raise ComplianceContractError("mapping missing, stale, or substituted")
   return registered

def control_mapping_sha256(mapping:ControlMapping)->str:
 """Digest every canonical mapping field without retaining its payload."""
 if not isinstance(mapping,ControlMapping): raise ComplianceContractError("validated mapping required")
 body={name:getattr(mapping,name) for name in mapping.__dataclass_fields__}
 encoded=json.dumps(body,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")
 return hashlib.sha256(encoded).hexdigest()

class ComplianceEvidenceAdapter:
 """Admit an exact registered mapping to the canonical FW-EVID ledger."""
 def __init__(self,registry:ControlMappingRegistry,ledger:EvidenceLedger):
  if not isinstance(registry,ControlMappingRegistry) or not isinstance(ledger,EvidenceLedger) or registry.tenant_id!=ledger.tenant_id: raise ComplianceContractError("matching canonical registry and Evidence ledger required")
  self.registry=registry; self.ledger=ledger
 def admit(self,mapping:ControlMapping,*,evidence_id:str,actor_ref:str,subject_ref:str,correlation_id:str|None=None,classification:str="INTERNAL")->EvidenceRecord:
  exact=self.registry.resolve_exact(mapping)
  records=self.ledger.tenant_snapshot(exact.tenant_id)
  value={"schema_version":"1","evidence_id":evidence_id,"tenant_id":exact.tenant_id,"event_type":"compliance.mapping_admitted","actor_ref":actor_ref,"actor_tenant_id":exact.tenant_id,"subject_ref":subject_ref,"subject_tenant_id":exact.tenant_id,"occurred_at":exact.occurred_at,"classification":classification,"payload_schema_id":"fw-schema/compliance/control-mapping-v1","payload_sha256":control_mapping_sha256(exact),"previous_record_sha256":records[-1].record_sha256 if records else None,"correlation_id":correlation_id,"evidence_references":exact.evidence_references,"mode":"DRY_RUN","deployment":"DISABLED","authority_granted":False}
  try: envelope=validate_evidence_envelope(value)
  except EvidenceContractError as exc: raise ComplianceContractError("compliance Evidence envelope invalid") from exc
  try: return self.ledger.append(envelope)
  except EvidenceContractError as exc: raise ComplianceContractError("compliance Evidence admission failed") from exc
