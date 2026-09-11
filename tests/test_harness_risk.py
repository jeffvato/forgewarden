from dataclasses import replace
import pytest
from swarm.harness_risk import *

def facts(**kw):
 return replace(TaskRiskFacts("FWQ-0082","tenant-one","tenant-one",1,1),**kw)

@pytest.mark.parametrize("score,tier",[(10,AssuranceTier.T0),(20,AssuranceTier.T1),(40,AssuranceTier.T2),(60,AssuranceTier.T3),(80,AssuranceTier.T4)])
def test_exact_score_boundaries(score,tier):
 points=dict(DEFAULT_POLICY.points); points["routine"]=score
 assert classify_risk(facts(),RiskPolicy(points)).tier is tier

def test_file_subsystem_and_signal_scores_are_policy_driven():
 result=classify_risk(facts(changed_file_count=6,subsystem_count=3,signals=("external_trust_boundary",)))
 assert result.score==45 and result.tier is AssuranceTier.T2

@pytest.mark.parametrize("kw",[
 {"components":("identity",)},{"paths":("swarm/recovery.py",)},
])
def test_security_metadata_promotes_to_t3(kw):
 assert classify_risk(facts(**kw)).tier is AssuranceTier.T3

def test_dangerous_capability_promotes_without_prohibiting():
 result=classify_risk(facts(dangerous_capabilities=("shell_execution",)))
 assert result.tier is AssuranceTier.T2 and result.disposition=="CLASSIFIED"

@pytest.mark.parametrize("signal",sorted(DENY_SIGNALS))
def test_hard_invariant_violation_denies_before_model(signal):
 result=classify_risk(facts(signals=(signal,)))
 assert result.disposition=="DENIED_POLICY_INVARIANT" and not result.model_invocation_allowed and not result.authority_granted

@pytest.mark.parametrize("signal",sorted(T4_SIGNALS))
def test_root_operations_require_human_and_select_no_model(signal):
 result=classify_risk(facts(signals=(signal,)))
 assert result.tier is AssuranceTier.T4 and result.human_authorization_required and not result.model_invocation_allowed

def test_model_or_request_cannot_downgrade_tier():
 with pytest.raises(HarnessRiskError,match="downgrade"):
  classify_risk(facts(components=("policy",),requested_max_tier=AssuranceTier.T1))

@pytest.mark.parametrize("kw",[{"request_tenant_id":"tenant-two"},{"signals":("unknown",)},{"dangerous_capabilities":("magic",)},{"paths":("../secret",)},{"changed_file_count":-1}])
def test_malformed_unknown_and_cross_tenant_facts_fail_closed(kw):
 with pytest.raises(HarnessRiskError): classify_risk(facts(**kw))

def test_policy_is_immutable_and_exact():
 with pytest.raises(HarnessRiskError): RiskPolicy({"routine":10})
 with pytest.raises(TypeError): DEFAULT_POLICY.points["routine"]=0


def test_tier_thresholds_are_configurable():
 policy=RiskPolicy(dict(DEFAULT_POLICY.points),boundaries=(5,30,70,95))
 assert classify_risk(facts(),policy).tier is AssuranceTier.T1
