'''Immutable, authority-free FW-REC checkpoint metadata.'''
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import uuid
from typing import Any, Mapping

FIELDS=frozenset('schema_version checkpoint_id tenant_id task_id requirement_id task_status stage starting_commit current_commit changed_files_sha256 validation_status review_status authority_references authority_current budget_used budget_limit retry_count retry_limit evidence_tail_sha256 occurred_at interruption_class safe_resume_decision mode deployment authority_granted'.split())
ID=re.compile(r'^[a-z][a-z0-9_.:/-]{0,191}$'); TASK=re.compile(r'^FWQ-[0-9]{4}$'); REQ=re.compile(r'^FW-[A-Z0-9]+-[0-9]{3}$'); GIT=re.compile(r'^[0-9a-f]{40,64}$'); SHA=re.compile(r'^[0-9a-f]{64}$'); AUTH=re.compile(r'^fw-(?:action|lease|capability)/[a-z][a-z0-9_.:/-]{0,191}$')
SECRET=re.compile(r'(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|AIza[a-z0-9_-]{8,}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\s*[:=])')
MAX_CHECKPOINT_BYTES=65536
STORE_VERSION=1

STATUSES={'queued','ready','running','awaiting_validation','awaiting_review','repair_required','blocked','completed','rejected','cancelled'}; STAGES={'selection','context','worker','validation','review','acceptance','checkpoint'}

class RecoveryContractError(ValueError): pass
class ResumeDecision(str,Enum):
 RESUME='RESUME'; BLOCK='BLOCK'; ROLLBACK_PROPOSAL_REQUIRED='ROLLBACK_PROPOSAL_REQUIRED'

class ResumeAdmissionDecision(str,Enum):
 RESUME='RESUME'; BLOCK='BLOCK'; ROLLBACK_PROPOSAL='ROLLBACK_PROPOSAL'

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

@dataclass(frozen=True)
class ResumeAdmission:
 schema_version:str; admission_id:str; checkpoint_id:str; checkpoint_sha256:str; tenant_id:str; task_id:str; current_commit:str; evidence_tail_sha256:str; interruption_class:str; decision:ResumeAdmissionDecision; reason:str; budget_remaining:int; retries_remaining:int; occurred_at:str; mode:str='DRY_RUN'; deployment:str='DISABLED'; authority_granted:bool=False
 def __post_init__(self):
  if self.schema_version!='1': raise RecoveryContractError('admission version invalid')
  text(self.admission_id,'admission',ID); text(self.checkpoint_id,'checkpoint',ID); text(self.tenant_id,'tenant',ID); text(self.task_id,'task',TASK)
  if not SHA.fullmatch(self.checkpoint_sha256) or not GIT.fullmatch(self.current_commit) or not SHA.fullmatch(self.evidence_tail_sha256): raise RecoveryContractError('admission binding invalid')
  if self.interruption_class not in {'PROCESS_EXIT','HOST_RESTART','NETWORK_FAILURE','MODEL_TIMEOUT','API_FAILURE','APPLICATION_RESTART','UNKNOWN'}: raise RecoveryContractError('admission interruption invalid')
  if not isinstance(self.decision,ResumeAdmissionDecision): raise RecoveryContractError('admission decision invalid')
  if not isinstance(self.reason,str) or not self.reason or len(self.reason)>256 or SECRET.search(self.reason): raise RecoveryContractError('admission reason invalid')
  if type(self.budget_remaining) is not int or type(self.retries_remaining) is not int or self.budget_remaining<0 or self.retries_remaining<0: raise RecoveryContractError('admission counter invalid')
  try: datetime.strptime(self.occurred_at,'%Y-%m-%dT%H:%M:%SZ')
  except (TypeError,ValueError) as e: raise RecoveryContractError('admission timestamp invalid') from e
  if self.mode!='DRY_RUN' or self.deployment!='DISABLED' or self.authority_granted: raise RecoveryContractError('admission authority forbidden')

def admit_interruption(checkpoint:RecoveryCheckpoint, *, admission_id:str, checkpoint_sha256:str, tenant_id:str, current_commit:str, evidence_tail_sha256:str, kill_switch:str, authority_current:bool, occurred_at:str, consumed_admission_ids:tuple[str,...]=(), evidence_sink:Any=None)->ResumeAdmission:
 """Classify resume safety and emit evidence; never execute recovery."""
 if not isinstance(checkpoint,RecoveryCheckpoint): raise RecoveryContractError('validated checkpoint required')
 text(admission_id,'admission',ID); text(tenant_id,'tenant',ID)
 if not admission_id.startswith(f'fw-rec-admission/{tenant_id}/'): raise RecoveryContractError('admission tenant mismatch')
 if not SHA.fullmatch(checkpoint_sha256) or not GIT.fullmatch(current_commit) or not SHA.fullmatch(evidence_tail_sha256) or type(authority_current) is not bool or not isinstance(kill_switch,str): raise RecoveryContractError('trusted admission binding invalid')
 if not isinstance(consumed_admission_ids,tuple) or len(consumed_admission_ids)>1024 or len(set(consumed_admission_ids))!=len(consumed_admission_ids): raise RecoveryContractError('consumed admission set invalid')
 if admission_id in consumed_admission_ids: raise RecoveryContractError('admission replay denied')
 if checkpoint.tenant_id!=tenant_id or checkpoint.current_commit!=current_commit or checkpoint.evidence_tail_sha256!=evidence_tail_sha256: raise RecoveryContractError('admission binding is stale or cross-tenant')
 if checkpoint_sha256!=recovery_checkpoint_digest(checkpoint): raise RecoveryContractError('checkpoint digest mismatch')
 try:
  if datetime.strptime(occurred_at,'%Y-%m-%dT%H:%M:%SZ') < datetime.strptime(checkpoint.occurred_at,'%Y-%m-%dT%H:%M:%SZ'): raise RecoveryContractError('admission predates checkpoint')
 except (TypeError,ValueError) as exc: raise RecoveryContractError('admission timestamp invalid') from exc
 remaining_budget=checkpoint.budget_limit-checkpoint.budget_used; remaining_retries=checkpoint.retry_limit-checkpoint.retry_count
 terminal=checkpoint.task_status in {'completed','rejected','cancelled'}
 unsafe_authority=kill_switch!='ENGAGED' or not authority_current or not checkpoint.authority_current
 failed_gate=checkpoint.validation_status=='FAILED' or checkpoint.review_status=='FINDINGS'
 if terminal: decision,reason=ResumeAdmissionDecision.BLOCK,'TERMINAL_TASK'
 elif unsafe_authority: decision,reason=ResumeAdmissionDecision.BLOCK,'AUTHORITY_OR_KILL_SWITCH_UNSAFE'
 elif remaining_budget<=0 or remaining_retries<=0: decision,reason=ResumeAdmissionDecision.BLOCK,'BUDGET_OR_RETRY_EXHAUSTED'
 elif checkpoint.interruption_class=='UNKNOWN' or failed_gate or checkpoint.safe_resume_decision is ResumeDecision.ROLLBACK_PROPOSAL_REQUIRED: decision,reason=ResumeAdmissionDecision.ROLLBACK_PROPOSAL,'ROLLBACK_REVIEW_REQUIRED'
 elif checkpoint.safe_resume_decision is ResumeDecision.RESUME and checkpoint.task_status in {'running','awaiting_validation','awaiting_review','repair_required'}: decision,reason=ResumeAdmissionDecision.RESUME,'EXACT_CHECKPOINT_RESUMABLE'
 else: decision,reason=ResumeAdmissionDecision.BLOCK,'CHECKPOINT_NOT_RESUMABLE'
 admission=ResumeAdmission('1',admission_id,checkpoint.checkpoint_id,checkpoint_sha256,tenant_id,checkpoint.task_id,current_commit,evidence_tail_sha256,checkpoint.interruption_class,decision,reason,remaining_budget,remaining_retries,occurred_at)
 if evidence_sink is None or not callable(evidence_sink): raise RecoveryContractError('Evidence sink required')
 try: evidence_sink({'event':'FW_REC_RESUME_ADMISSION','admission_id':admission.admission_id,'checkpoint_id':admission.checkpoint_id,'checkpoint_sha256':admission.checkpoint_sha256,'tenant_id':admission.tenant_id,'task_id':admission.task_id,'decision':admission.decision.value,'reason':admission.reason,'authority_granted':False})
 except Exception as exc: raise RecoveryContractError('resume admission Evidence failed') from exc
 return admission

def validate_recovery_checkpoint(value:Mapping[str,Any])->RecoveryCheckpoint:
 if not isinstance(value,Mapping) or set(value)!=FIELDS: raise RecoveryContractError('field set invalid')
 p=dict(value)
 try:
  if not isinstance(p['authority_references'],(list,tuple)): raise TypeError
  p['authority_references']=tuple(p['authority_references']); p['safe_resume_decision']=ResumeDecision(p['safe_resume_decision']); return RecoveryCheckpoint(**p)
 except (TypeError,ValueError) as e:
  if isinstance(e,RecoveryContractError): raise
  raise RecoveryContractError('checkpoint malformed') from e


def _canonical(value: Any) -> bytes:
 return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode('ascii')

def recovery_checkpoint_digest(checkpoint:RecoveryCheckpoint)->str:
 if not isinstance(checkpoint,RecoveryCheckpoint): raise RecoveryContractError('validated checkpoint required')
 record=asdict(checkpoint); record['safe_resume_decision']=checkpoint.safe_resume_decision.value
 return hashlib.sha256(_canonical({'version':STORE_VERSION,'checkpoint':record})).hexdigest()

def _safe_parent(path: Path) -> None:
 if not path.is_absolute() or not path.parent.is_dir(): raise RecoveryContractError('checkpoint parent is unsafe')
 current=Path(path.anchor)
 for part in path.parent.parts[1:]:
  current/=part
  if current.is_symlink(): raise RecoveryContractError('checkpoint parent is symlinked')

def write_recovery_checkpoint(path: Path, checkpoint: RecoveryCheckpoint) -> str:
 """Atomically persist validated metadata; this grants no recovery execution."""
 if not isinstance(checkpoint,RecoveryCheckpoint): raise RecoveryContractError('validated checkpoint required')
 if not hasattr(os,'O_NOFOLLOW'): raise RecoveryContractError('safe file primitive unavailable')
 path=Path(path); _safe_parent(path)
 if path.exists() and (path.is_symlink() or not path.is_file()): raise RecoveryContractError('checkpoint target is unsafe')
 record=asdict(checkpoint); record['safe_resume_decision']=checkpoint.safe_resume_decision.value
 payload={'version':STORE_VERSION,'checkpoint':record}
 digest=recovery_checkpoint_digest(checkpoint)
 raw=_canonical({**payload,'sha256':digest})
 if len(raw)>MAX_CHECKPOINT_BYTES: raise RecoveryContractError('checkpoint is oversized')
 temporary=path.parent/f'.{path.name}.{uuid.uuid4().hex}.tmp'
 try:
  fd=os.open(temporary,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
  with os.fdopen(fd,'wb') as handle:
   handle.write(raw); handle.flush(); os.fsync(handle.fileno())
  os.replace(temporary,path)
  directory=os.open(path.parent,os.O_RDONLY|getattr(os,'O_DIRECTORY',0))
  try: os.fsync(directory)
  finally: os.close(directory)
 except OSError as exc:
  raise RecoveryContractError('checkpoint persistence failed') from exc
 finally:
  temporary.unlink(missing_ok=True)
 return digest

def load_recovery_checkpoint(path: Path, *, tenant_id: str, current_commit: str,
 evidence_tail_sha256: str, consumed_checkpoint_ids: tuple[str,...]=()) -> RecoveryCheckpoint:
 """Reconstruct and reconcile metadata against caller-provided trusted facts."""
 text(tenant_id,'tenant',ID)
 if not GIT.fullmatch(current_commit) or not SHA.fullmatch(evidence_tail_sha256): raise RecoveryContractError('trusted recovery binding is invalid')
 if not isinstance(consumed_checkpoint_ids,tuple) or len(consumed_checkpoint_ids)>1024 or len(set(consumed_checkpoint_ids))!=len(consumed_checkpoint_ids): raise RecoveryContractError('consumed checkpoint set is invalid')
 path=Path(path); _safe_parent(path)
 if not hasattr(os,'O_NOFOLLOW') or path.is_symlink() or not path.is_file(): raise RecoveryContractError('checkpoint is missing or unsafe')
 try:
  fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK)
  try:
   meta=os.fstat(fd)
   if not stat.S_ISREG(meta.st_mode) or meta.st_size>MAX_CHECKPOINT_BYTES or meta.st_mode&0o077: raise RecoveryContractError('checkpoint permissions or size are unsafe')
   raw=os.read(fd,MAX_CHECKPOINT_BYTES+1)
  finally: os.close(fd)
  if len(raw)>MAX_CHECKPOINT_BYTES: raise RecoveryContractError('checkpoint is oversized')
  envelope=json.loads(raw.decode('ascii'))
 except RecoveryContractError: raise
 except (OSError,UnicodeDecodeError,json.JSONDecodeError) as exc: raise RecoveryContractError('checkpoint is corrupt or incomplete') from exc
 if not isinstance(envelope,dict) or set(envelope)!={'version','checkpoint','sha256'} or envelope['version']!=STORE_VERSION: raise RecoveryContractError('checkpoint envelope is invalid')
 payload={'version':envelope['version'],'checkpoint':envelope['checkpoint']}
 digest=hashlib.sha256(_canonical(payload)).hexdigest()
 if envelope['sha256']!=digest: raise RecoveryContractError('checkpoint integrity mismatch')
 checkpoint=validate_recovery_checkpoint(envelope['checkpoint'])
 if checkpoint.checkpoint_id in consumed_checkpoint_ids: raise RecoveryContractError('checkpoint replay denied')
 if checkpoint.tenant_id!=tenant_id or checkpoint.current_commit!=current_commit or checkpoint.evidence_tail_sha256!=evidence_tail_sha256: raise RecoveryContractError('checkpoint binding is stale or cross-tenant')
 return checkpoint
