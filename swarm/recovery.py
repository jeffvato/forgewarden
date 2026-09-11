'''Immutable, authority-free FW-REC checkpoint metadata.'''
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from typing import Any, Mapping

FIELDS=frozenset('schema_version checkpoint_id tenant_id task_id requirement_id task_status stage starting_commit current_commit changed_files_sha256 validation_status review_status authority_references authority_current budget_used budget_limit retry_count retry_limit evidence_tail_sha256 occurred_at interruption_class safe_resume_decision mode deployment authority_granted'.split())
ID=re.compile(r'^[a-z][a-z0-9_.:/-]{0,191}$'); TASK=re.compile(r'^FWQ-[0-9]{4}$'); REQ=re.compile(r'^FW-[A-Z0-9]+-[0-9]{3}$'); GIT=re.compile(r'^[0-9a-f]{40,64}$'); SHA=re.compile(r'^[0-9a-f]{64}$'); AUTH=re.compile(r'^fw-(?:action|lease|capability)/[a-z][a-z0-9_.:/-]{0,191}$')
SECRET=re.compile(r'(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=])')
STATUSES={'queued','ready','running','awaiting_validation','awaiting_review','repair_required','blocked','completed','rejected','cancelled'}; STAGES={'selection','context','worker','validation','review','acceptance','checkpoint'}

class RecoveryContractError(ValueError): pass
class ResumeDecision(str,Enum):
 RESUME='RESUME'; BLOCK='BLOCK'; ROLLBACK_PROPOSAL_REQUIRED='ROLLBACK_PROPOSAL_REQUIRED'

def text(v,n,p):
 if not isinstance(v,str) or v!=v.strip() or not p.fullmatch(v) or SECRET.search(v): raise RecoveryContractError(f'{n} is invalid')
 return v

@dataclass(frozen=True)
class RecoveryCheckpoint:
 schema_version:str; checkpoint_id:str; tenant_id:str; task_id:str; requirement_id:str; task_status:str; stage:str; starting_commit:str; current_commit:str; changed_files_sha256:str; validation_status:str; review_status:str; authority_references:tuple[str,...]; authority_current:bool; budget_used:int; budget_limit:int; retry_count:int; retry_limit:int; evidence_tail_sha256:str; occurred_at:str; interruption_class:str; safe_resume_decision:ResumeDecision; mode:str; deployment:str; authority_granted:bool
 def __post_init__(self):
  if self.schema_version!='1': raise RecoveryContractError('version invalid')
  tenant=text(self.tenant_id,'tenant',ID)
  if not text(self.checkpoint_id,'checkpoint',ID).startswith(f'fw-rec/{tenant}/'): raise RecoveryContractError('tenant mismatch')
  text(self.task_id,'task',TASK); text(self.requirement_id,'requirement',REQ)
  if self.task_status not in STATUSES or self.stage not in STAGES: raise RecoveryContractError('state invalid')
  if any(not isinstance(x,str) or not GIT.fullmatch(x) for x in (self.starting_commit,self.current_commit)): raise RecoveryContractError('commit invalid')
  if any(not isinstance(x,str) or not SHA.fullmatch(x) for x in (self.changed_files_sha256,self.evidence_tail_sha256)): raise RecoveryContractError('digest invalid')
  if self.validation_status not in {'NOT_RUN','PASSED','FAILED'} or self.review_status not in {'NOT_RUN','APPROVE_LOW','FINDINGS','UNAVAILABLE'}: raise RecoveryContractError('gate invalid')
  refs=self.authority_references
  if not isinstance(refs,tuple) or len(refs)>32 or tuple(sorted(set(refs)))!=refs: raise RecoveryContractError('authority references invalid')
  for ref in refs:
   text(ref,'authority reference',AUTH)
   if ref.split('/',2)[1] != tenant: raise RecoveryContractError('authority tenant mismatch')
  if type(self.authority_current) is not bool or type(self.authority_granted) is not bool: raise RecoveryContractError('authority flag invalid')
  for used,limit in ((self.budget_used,self.budget_limit),(self.retry_count,self.retry_limit)):
   if type(used) is not int or type(limit) is not int or used<0 or limit<0 or used>limit: raise RecoveryContractError('counter invalid')
  try: datetime.strptime(self.occurred_at,'%Y-%m-%dT%H:%M:%SZ')
  except (TypeError,ValueError) as e: raise RecoveryContractError('timestamp invalid') from e
  if self.interruption_class not in {'NONE','PROCESS_EXIT','HOST_RESTART','NETWORK_FAILURE','MODEL_TIMEOUT','API_FAILURE','APPLICATION_RESTART','UNKNOWN'} or not isinstance(self.safe_resume_decision,ResumeDecision): raise RecoveryContractError('resume metadata invalid')
  if self.mode!='DRY_RUN' or self.deployment!='DISABLED' or self.authority_granted: raise RecoveryContractError('authority forbidden')
  unsafe=(not self.authority_current or self.budget_used==self.budget_limit or self.retry_count==self.retry_limit or self.validation_status=='FAILED' or self.review_status=='FINDINGS')
  if unsafe and self.safe_resume_decision is ResumeDecision.RESUME: raise RecoveryContractError('unsafe resume')
  if self.task_status=='completed' and not (self.stage=='checkpoint' and self.validation_status=='PASSED' and self.review_status=='APPROVE_LOW' and self.safe_resume_decision is ResumeDecision.BLOCK): raise RecoveryContractError('completed state inconsistent')

def validate_recovery_checkpoint(value:Mapping[str,Any])->RecoveryCheckpoint:
 if not isinstance(value,Mapping) or set(value)!=FIELDS: raise RecoveryContractError('field set invalid')
 p=dict(value)
 try:
  if not isinstance(p['authority_references'],(list,tuple)): raise TypeError
  p['authority_references']=tuple(p['authority_references']); p['safe_resume_decision']=ResumeDecision(p['safe_resume_decision']); return RecoveryCheckpoint(**p)
 except (TypeError,ValueError) as e:
  if isinstance(e,RecoveryContractError): raise
  raise RecoveryContractError('checkpoint malformed') from e
