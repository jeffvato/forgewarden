from dataclasses import asdict,replace
import pytest
from swarm.recovery import *

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
