from dataclasses import replace
import pytest
from swarm.harness_failure import *
from swarm.harness_risk import AssuranceTier

def obs(**kw):
 base=FailureObservation("packet-1","FWQ-0084","tenant-one",AssuranceTier.T1,1,1,("ordinary",),("model-one",),("pytest failed",),("assertion failed",),("swarm/module.py",),"1 file changed",(),(),("fw-evid/tenant-one/task/1",))
 return replace(base,**kw)

def make(value=None,sink=lambda *args:None,**kw):
 return create_failure_packet(value or obs(),evidence_sink=sink,**kw)

def test_first_ordinary_failure_allows_one_same_tier_repair():
 p=make(); assert p.disposition=="SAME_TIER_REPAIR" and p.resulting_tier is AssuranceTier.T1 and not p.executed and not p.authority_granted

def test_different_error_on_second_attempt_escalates_one_tier():
 p=make(obs(attempt_count=2,same_error_count=1,failure_classes=("validation",)))
 assert p.disposition=="ESCALATE_TIER" and p.resulting_tier is AssuranceTier.T2

def test_same_error_twice_escalates_exactly_one_tier():
 p=make(obs(attempt_count=2,same_error_count=2))
 assert p.disposition=="ESCALATE_TIER" and p.resulting_tier is AssuranceTier.T2

@pytest.mark.parametrize("failure",["reviewer_architecture","reviewer_security","unexpected_cross_subsystem","unknown_security"])
def test_security_and_architecture_conditions_escalate(failure):
 p=make(obs(failure_classes=(failure,)))
 assert p.resulting_tier is AssuranceTier.T2

@pytest.mark.parametrize("failure",["scope_escape","budget_exhausted","kill_switch","evidence_failure"])
def test_hard_stop_conditions_block(failure):
 changes={"failure_classes":(failure,)}
 if failure=="budget_exhausted": changes["budget_exhausted"]=True
 if failure=="kill_switch": changes["kill_switch"]="DISENGAGED"
 assert make(obs(**changes)).disposition=="BLOCK"

def test_t3_escalation_and_t4_failure_require_human():
 assert make(obs(tier=AssuranceTier.T3,attempt_count=2,same_error_count=2)).disposition=="HUMAN_ESCALATION"
 assert make(obs(tier=AssuranceTier.T4)).disposition=="HUMAN_ESCALATION"

def test_model_confidence_and_requested_tier_cannot_lower_outcome():
 p=make(obs(attempt_count=2,same_error_count=2,model_confidence=1.0,requested_tier=AssuranceTier.T0))
 assert p.resulting_tier is AssuranceTier.T2

def test_evidence_is_first_and_failure_returns_no_packet():
 calls=[]; p=make(sink=lambda event,payload:calls.append((event,payload)))
 assert calls[0][0]=="fw_harness_failure_packet" and calls[0][1]["packet_id"]==p.packet_id
 def fail(*args): raise RuntimeError("offline")
 with pytest.raises(HarnessFailureError,match="Evidence write failed"): make(sink=fail)

def test_replay_secret_unknown_and_unbounded_input_fail_closed():
 with pytest.raises(HarnessFailureError,match="replay"): make(consumed_packet_ids=("packet-1",))
 with pytest.raises(HarnessFailureError): make(obs(failures=("password=hidden-secret",)))
 with pytest.raises(HarnessFailureError): make(obs(failure_classes=("invented",)))
 with pytest.raises(HarnessFailureError): make(obs(changed_files=("../escape",)))
 with pytest.raises(HarnessFailureError): make(obs(evidence_references=("fw-evid/tenant-two/task/1",)))
 with pytest.raises(HarnessFailureError): make(obs(model_ids=tuple(f"m{i}" for i in range(65))))

def test_packet_is_tenant_bound_bounded_metadata_only():
 p=make(); assert p.tenant_id=="tenant-one" and p.mode=="DRY_RUN" and p.deployment=="DISABLED"
 with pytest.raises(Exception): p.disposition="EXECUTE"


@pytest.mark.parametrize("changes",[
 {"attempt_count":0},{"same_error_count":2},{"packet_id":""},
 {"packet_id":"x"*256},{"packet_id":"bad value"},{"diff_summary":""},
 {"model_confidence":-0.1},{"model_confidence":1.1},{"tier":1},
])
def test_counter_identity_summary_confidence_and_tier_boundaries(changes):
 with pytest.raises(HarnessFailureError): make(obs(**changes))
