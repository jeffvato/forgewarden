from dataclasses import asdict,replace
import pytest
from swarm.recovery import *
import json
import os

def cp(**kw):
 v=RecoveryCheckpoint('1','fw-rec/tenant-one/cp-1','tenant-one','FWQ-0080','FW-REC-001','awaiting_review','review','a'*40,'b'*40,'c'*64,'PASSED','APPROVE_LOW',('fw-action/tenant-one/task-80','fw-lease/tenant-one/task-80'),True,10,100,1,3,'d'*64,'2026-09-10T16:00:00Z','NONE',ResumeDecision.RESUME,'DRY_RUN','DISABLED',False)
 return replace(v,**kw)

def test_immutable_exact_authority_free_contract():
 v=cp(); assert validate_recovery_checkpoint(asdict(v))==v and not v.authority_granted
 assert cp(tenant_id='tenant',checkpoint_id='fw-rec/tenant/cp-1',authority_references=('fw-lease/tenant/task-80',)).tenant_id=='tenant'
 with pytest.raises(Exception): v.task_status='completed'
 p=asdict(v); p['rollback_executed']=True
 with pytest.raises(RecoveryContractError): validate_recovery_checkpoint(p)

@pytest.mark.parametrize('kw',[{'checkpoint_id':'fw-rec/other/cp'},{'current_commit':'abc'},{'evidence_tail_sha256':'x'*64},{'authority_references':('fw-lease/tenant-one/password=secret-value',)},{'authority_references':('fw-lease/tenant-two/task-80',)},{'tenant_id':'tenant','checkpoint_id':'fw-rec/tenant/cp-1','authority_references':('fw-lease/tenant-two/task-80',)},{'authority_references':('bad-format',)},{'authority_current':False},{'budget_used':100},{'retry_count':3},{'validation_status':'FAILED'},{'review_status':'FINDINGS'}])
def test_unsafe_resume_fails_closed(kw):
 with pytest.raises(RecoveryContractError): cp(**kw)

def test_blocked_failure_and_completed_proof_are_recordable():
 blocked=cp(task_status='blocked',validation_status='FAILED',review_status='FINDINGS',authority_current=False,budget_used=100,retry_count=3,safe_resume_decision=ResumeDecision.ROLLBACK_PROPOSAL_REQUIRED,interruption_class='PROCESS_EXIT')
 assert blocked.safe_resume_decision is ResumeDecision.ROLLBACK_PROPOSAL_REQUIRED
 done=cp(task_status='completed',stage='checkpoint',safe_resume_decision=ResumeDecision.BLOCK)
 assert done.task_status=='completed'


def load(path, **kw):
 return load_recovery_checkpoint(path,tenant_id=kw.pop('tenant_id','tenant-one'),current_commit=kw.pop('current_commit','b'*40),evidence_tail_sha256=kw.pop('evidence_tail_sha256','d'*64),**kw)

def test_atomic_private_round_trip_and_restart_reconstruction(tmp_path):
 path=tmp_path/'recovery.json'
 digest=write_recovery_checkpoint(path,cp())
 assert len(digest)==64 and load(path)==cp()
 assert path.stat().st_mode&0o077==0

def test_corruption_truncation_and_oversize_fail_closed(tmp_path):
 path=tmp_path/'recovery.json'; write_recovery_checkpoint(path,cp())
 data=json.loads(path.read_text()); data['checkpoint']['task_id']='FWQ-9999'; path.write_text(json.dumps(data)); os.chmod(path,0o600)
 with pytest.raises(RecoveryContractError,match='integrity'): load(path)
 path.write_text('{'); os.chmod(path,0o600)
 with pytest.raises(RecoveryContractError,match='corrupt'): load(path)
 path.write_bytes(b'x'*(MAX_CHECKPOINT_BYTES+1)); os.chmod(path,0o600)
 with pytest.raises(RecoveryContractError,match='size'): load(path)

def test_stale_cross_tenant_evidence_git_and_replay_fail_closed(tmp_path):
 path=tmp_path/'recovery.json'; write_recovery_checkpoint(path,cp())
 cases=({'tenant_id':'tenant-two'},{'current_commit':'e'*40},{'evidence_tail_sha256':'f'*64},{'consumed_checkpoint_ids':('fw-rec/tenant-one/cp-1',)})
 for values in cases:
  with pytest.raises(RecoveryContractError): load(path,**values)

def test_symlink_and_public_permissions_fail_closed(tmp_path):
 path=tmp_path/'recovery.json'; write_recovery_checkpoint(path,cp()); os.chmod(path,0o644)
 with pytest.raises(RecoveryContractError,match='permissions'): load(path)
 target=tmp_path/'target'; target.write_text('x'); link=tmp_path/'link'; link.symlink_to(target)
 with pytest.raises(RecoveryContractError,match='unsafe'): load(link)
 with pytest.raises(RecoveryContractError,match='unsafe'): write_recovery_checkpoint(link,cp())

def test_persistence_failure_never_reports_success(tmp_path,monkeypatch):
 path=tmp_path/'recovery.json'
 def fail(*args,**kwargs): raise OSError('disk')
 monkeypatch.setattr(os,'replace',fail)
 with pytest.raises(RecoveryContractError,match='persistence failed'): write_recovery_checkpoint(path,cp())
 assert not path.exists()

def test_unknown_schema_and_malformed_consumed_set_fail_closed(tmp_path):
 path=tmp_path/'recovery.json'; write_recovery_checkpoint(path,cp())
 with pytest.raises(RecoveryContractError,match='consumed'): load(path,consumed_checkpoint_ids=['x'])
 data=json.loads(path.read_text()); data['extra']=True; path.write_text(json.dumps(data)); os.chmod(path,0o600)
 with pytest.raises(RecoveryContractError,match='envelope'): load(path)

def admission(checkpoint=None, sink=None, **kw):
 checkpoint=checkpoint or cp(task_status='running',stage='worker',validation_status='NOT_RUN',review_status='NOT_RUN',interruption_class='PROCESS_EXIT')
 values={'admission_id':'fw-rec-admission/tenant-one/a-1','checkpoint_sha256':recovery_checkpoint_digest(checkpoint),'tenant_id':'tenant-one','current_commit':'b'*40,'evidence_tail_sha256':'d'*64,'kill_switch':'ENGAGED','authority_current':True,'occurred_at':'2026-09-10T16:01:00Z','evidence_sink':sink or (lambda event: None)}
 values.update(kw); return admit_interruption(checkpoint,**values)

def test_exact_resumable_interruption_emits_evidence_first_admission():
 events=[]; result=admission(sink=events.append)
 assert result.decision is ResumeAdmissionDecision.RESUME and not result.authority_granted
 assert result.budget_remaining==90 and result.retries_remaining==2
 assert events==[{'event':'FW_REC_RESUME_ADMISSION','admission_id':result.admission_id,'checkpoint_id':result.checkpoint_id,'checkpoint_sha256':result.checkpoint_sha256,'tenant_id':'tenant-one','task_id':'FWQ-0080','decision':'RESUME','reason':'EXACT_CHECKPOINT_RESUMABLE','authority_granted':False}]

@pytest.mark.parametrize('changes,decision',[
 ({'kill_switch':'CLEARED'},ResumeAdmissionDecision.BLOCK),
 ({'authority_current':False},ResumeAdmissionDecision.BLOCK),
 ({'checkpoint':cp(task_status='running',stage='worker',validation_status='NOT_RUN',review_status='NOT_RUN',interruption_class='UNKNOWN')},ResumeAdmissionDecision.ROLLBACK_PROPOSAL),
 ({'checkpoint':cp(task_status='blocked',stage='validation',validation_status='FAILED',review_status='NOT_RUN',interruption_class='PROCESS_EXIT',safe_resume_decision=ResumeDecision.ROLLBACK_PROPOSAL_REQUIRED)},ResumeAdmissionDecision.ROLLBACK_PROPOSAL),
 ({'checkpoint':cp(task_status='completed',stage='checkpoint',interruption_class='PROCESS_EXIT',safe_resume_decision=ResumeDecision.BLOCK)},ResumeAdmissionDecision.BLOCK),
 ({'checkpoint':cp(task_status='running',stage='worker',validation_status='NOT_RUN',review_status='NOT_RUN',interruption_class='PROCESS_EXIT',budget_used=100,safe_resume_decision=ResumeDecision.BLOCK)},ResumeAdmissionDecision.BLOCK),
])
def test_admission_classifies_stop_boundaries(changes,decision):
 checkpoint=changes.pop('checkpoint',None)
 assert admission(checkpoint,**changes).decision is decision

@pytest.mark.parametrize('changes',[{'tenant_id':'tenant-two'},{'admission_id':'fw-rec-admission/tenant-two/a-1'},{'current_commit':'f'*40},{'checkpoint_sha256':'f'*64},{'evidence_tail_sha256':'f'*64},{'consumed_admission_ids':('fw-rec-admission/tenant-one/a-1',)},{'kill_switch':None},{'authority_current':'yes'},{'occurred_at':'2026-09-10T15:59:59Z'}])
def test_admission_rejects_stale_cross_tenant_replay_and_malformed_facts(changes):
 with pytest.raises(RecoveryContractError): admission(**changes)

def test_evidence_failure_returns_no_admission_and_allows_safe_retry():
 def fail(_event): raise RuntimeError('disk')
 with pytest.raises(RecoveryContractError,match='Evidence failed'): admission(sink=fail)
 assert admission().decision is ResumeAdmissionDecision.RESUME

def test_resume_admission_is_immutable_and_authority_free():
 result=admission()
 with pytest.raises(Exception): result.decision=ResumeAdmissionDecision.BLOCK
 with pytest.raises(RecoveryContractError,match='authority forbidden'):
  replace(result,authority_granted=True)
