"""Integrated metadata-only FW-REC lifecycle proof."""
import hashlib
import json

import pytest

from swarm.core import AuditLog
from swarm.evidence import CanonicalAuditEvidenceStore, EvidenceEnvelope, EvidenceLedger
from swarm.recovery import (
    RecoveryCheckpoint, RecoveryContractError, ResumeAdmissionDecision, ResumeDecision,
    admit_interruption, load_recovery_checkpoint, recovery_checkpoint_digest,
    write_recovery_checkpoint,
)

TENANT="tenant-recovery-proof"; TASK="FWQ-0300"; COMMIT="a"*40; TAIL="b"*64

def checkpoint(**overrides):
    values=dict(schema_version="1",checkpoint_id=f"fw-rec/{TENANT}/checkpoint-1",tenant_id=TENANT,task_id=TASK,requirement_id="FW-REC-004",task_status="running",stage="worker",starting_commit="c"*40,current_commit=COMMIT,changed_files_sha256="d"*64,validation_status="NOT_RUN",review_status="NOT_RUN",authority_references=(f"fw-lease/{TENANT}/task-300",),authority_current=True,budget_used=12,budget_limit=100,retry_count=1,retry_limit=3,evidence_tail_sha256=TAIL,occurred_at="2026-09-11T01:00:00Z",interruption_class="HOST_RESTART",safe_resume_decision=ResumeDecision.RESUME,mode="DRY_RUN",deployment="DISABLED",authority_granted=False)
    values.update(overrides); return RecoveryCheckpoint(**values)

def evidence_adapter(ledger):
    def append(payload):
        digest=hashlib.sha256(json.dumps(payload,sort_keys=True,separators=(",",":"),ensure_ascii=True).encode("ascii")).hexdigest()
        previous=ledger.tenant_snapshot(TENANT)[-1].record_sha256 if ledger.tenant_snapshot(TENANT) else None
        ledger.append(EvidenceEnvelope("1",f"fw-evid/{TENANT}/resume-admission-1",TENANT,"recovery.resume-admission",f"fw-id/{TENANT}/harness-controller",TENANT,f"fw-task/{TENANT}/fwq-0300",TENANT,"2026-09-11T01:00:01Z","INTERNAL","fw-schema/recovery/resume-admission-v1",digest,previous,f"fw-corr/{TENANT}/fwq-0300",(),"DRY_RUN","DISABLED",False))
    return append

def test_integrated_checkpoint_restart_admission_and_evidence_recovery(tmp_path):
    cp=checkpoint(); path=tmp_path/"checkpoint.json"; digest=write_recovery_checkpoint(path,cp)
    recovered=load_recovery_checkpoint(path,tenant_id=TENANT,current_commit=COMMIT,evidence_tail_sha256=TAIL)
    audit=AuditLog(tmp_path/"evidence.jsonl"); store=CanonicalAuditEvidenceStore(audit); ledger=EvidenceLedger(TENANT,store)
    admission=admit_interruption(recovered,admission_id=f"fw-rec-admission/{TENANT}/admission-1",checkpoint_sha256=digest,tenant_id=TENANT,current_commit=COMMIT,evidence_tail_sha256=TAIL,kill_switch="ENGAGED",authority_current=True,occurred_at="2026-09-11T01:00:01Z",evidence_sink=evidence_adapter(ledger))
    assert admission.decision is ResumeAdmissionDecision.RESUME and not admission.authority_granted
    restarted=store.recover(TENANT); records=restarted.tenant_snapshot(TENANT)
    assert len(records)==1 and records[0].envelope.payload_sha256
    with pytest.raises(RecoveryContractError,match="replay"):
        admit_interruption(recovered,admission_id=admission.admission_id,checkpoint_sha256=digest,tenant_id=TENANT,current_commit=COMMIT,evidence_tail_sha256=TAIL,kill_switch="ENGAGED",authority_current=True,occurred_at="2026-09-11T01:00:02Z",consumed_admission_ids=(admission.admission_id,),evidence_sink=evidence_adapter(restarted))

def test_integrated_evidence_failure_leaves_exact_checkpoint_retryable(tmp_path):
    cp=checkpoint(); path=tmp_path/"checkpoint.json"; digest=write_recovery_checkpoint(path,cp)
    recovered=load_recovery_checkpoint(path,tenant_id=TENANT,current_commit=COMMIT,evidence_tail_sha256=TAIL)
    def fail(_payload): raise RuntimeError("durability unavailable")
    args=dict(admission_id=f"fw-rec-admission/{TENANT}/admission-1",checkpoint_sha256=digest,tenant_id=TENANT,current_commit=COMMIT,evidence_tail_sha256=TAIL,kill_switch="ENGAGED",authority_current=True,occurred_at="2026-09-11T01:00:01Z")
    with pytest.raises(RecoveryContractError,match="Evidence failed"): admit_interruption(recovered,evidence_sink=fail,**args)
    events=[]; assert admit_interruption(recovered,evidence_sink=events.append,**args).decision is ResumeAdmissionDecision.RESUME
    assert len(events)==1

def test_integrated_tamper_stale_tenant_and_unsafe_state_fail_closed(tmp_path):
    cp=checkpoint(); path=tmp_path/"checkpoint.json"; digest=write_recovery_checkpoint(path,cp)
    path.write_text(path.read_text().replace(TASK,"FWQ-9999")); path.chmod(0o600)
    with pytest.raises(RecoveryContractError,match="integrity"): load_recovery_checkpoint(path,tenant_id=TENANT,current_commit=COMMIT,evidence_tail_sha256=TAIL)
    safe=checkpoint()
    common=dict(admission_id=f"fw-rec-admission/{TENANT}/admission-2",checkpoint_sha256=recovery_checkpoint_digest(safe),tenant_id=TENANT,current_commit=COMMIT,evidence_tail_sha256=TAIL,authority_current=True,occurred_at="2026-09-11T01:00:01Z",evidence_sink=lambda event: None)
    with pytest.raises(RecoveryContractError): admit_interruption(safe,kill_switch="ENGAGED",**{**common,"tenant_id":"tenant-other"})
    assert admit_interruption(safe,kill_switch="CLEARED",**common).decision is ResumeAdmissionDecision.BLOCK
