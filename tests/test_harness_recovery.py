from dataclasses import replace

import pytest

from swarm.harness_recovery import Anomaly, HarnessRecoveryError, MonitorSnapshot, monitor, request_repair, review_recovery


def snapshot(**changes):
    value = MonitorSnapshot("tenant-one", "FWQ-0077", "codex-cli", "gpt-approved", "validation", 10, 60, 0, 2, False, True, True, "ENGAGED", ("swarm/harness_recovery.py",), ("swarm/harness_recovery.py",), True)
    return replace(value, **changes)


def observe(value=None, sink=None):
    return monitor(value or snapshot(), evidence_sink=sink or (lambda event, payload: None))


def test_healthy_observation_is_evidence_first_and_continues():
    calls = []
    result = observe(sink=lambda event, payload: calls.append((event, payload)))
    assert result.anomaly == Anomaly.NONE and result.disposition == "CONTINUE"
    assert calls[0][0] == "fw_harness_monitor" and not result.authority_expanded


@pytest.mark.parametrize("changes,anomaly,disposition", [
    ({"kill_switch": "DISENGAGED"}, Anomaly.KILL_SWITCH, "STOP"),
    ({"evidence_healthy": False}, Anomaly.EVIDENCE_FAILURE, "STOP"),
    ({"identity_matches": False}, Anomaly.IDENTITY_SUBSTITUTION, "ESCALATE"),
    ({"changed_files": ("swarm/other.py",)}, Anomaly.FILE_SCOPE_ESCAPE, "ESCALATE"),
    ({"budget_exhausted": True}, Anomaly.RESOURCE_EXHAUSTION, "STOP"),
    ({"retry_count": 3}, Anomaly.RETRY_EXHAUSTION, "ESCALATE"),
    ({"elapsed_seconds": 61}, Anomaly.STUCK_WORKFLOW, "REPAIR_REQUEST"),
    ({"tests_passed": False}, Anomaly.TEST_DEGRADATION, "REPAIR_REQUEST"),
])
def test_anomalies_have_deterministic_bounded_dispositions(changes, anomaly, disposition):
    result = observe(snapshot(**changes))
    assert result.anomaly == anomaly and result.disposition == disposition
    assert result.repair_allowed is (disposition == "REPAIR_REQUEST")


def test_precedence_stops_security_anomaly_before_repairable_failure():
    result = observe(snapshot(evidence_healthy=False, tests_passed=False, elapsed_seconds=100))
    assert result.anomaly == Anomaly.EVIDENCE_FAILURE and result.disposition == "STOP"


def test_monitor_evidence_failure_returns_no_decision():
    def fail(event, payload): raise RuntimeError("offline")
    with pytest.raises(HarnessRecoveryError, match="Evidence write failed"):
        observe(sink=fail)


def test_only_repairable_decision_creates_inert_scoped_request():
    value = snapshot(tests_passed=False)
    repair = request_repair(value, observe(value), repair_id="repair-one")
    assert repair.action == "REQUEST_ONLY" and not repair.executed and not repair.authority_expanded
    assert repair.allowed_files == value.allowed_files
    with pytest.raises(HarnessRecoveryError, match="does not authorize"):
        request_repair(snapshot(), observe(snapshot()), repair_id="repair-two")


def test_recovery_review_accepts_only_exact_low_risk_passed_evidence():
    value = snapshot(tests_passed=False)
    repair = request_repair(value, observe(value), repair_id="repair-one")
    calls = []
    result = review_recovery(repair, candidate_commit="a" * 40, checkpoint_reference="checkpoint-one", validation="PASSED", reviewer_verdict="APPROVE", reviewer_risk="LOW", evidence_sink=lambda event, payload: calls.append((event, payload)))
    assert result.final_status == "RECOVERED" and not result.rollback_executed
    assert calls[0][0] == "fw_harness_recovery_review"


@pytest.mark.parametrize("validation,verdict,risk", [("FAILED", "APPROVE", "LOW"), ("PASSED", "REJECT", "LOW"), ("PASSED", "APPROVE", "HIGH")])
def test_nonpassing_recovery_review_escalates(validation, verdict, risk):
    value = snapshot(tests_passed=False)
    repair = request_repair(value, observe(value), repair_id="repair-one")
    result = review_recovery(repair, candidate_commit="a" * 40, checkpoint_reference="checkpoint-one", validation=validation, reviewer_verdict=verdict, reviewer_risk=risk, evidence_sink=lambda *args: None)
    assert result.final_status == "ESCALATED"


def test_review_evidence_failure_returns_no_recovery_status():
    value = snapshot(tests_passed=False); repair = request_repair(value, observe(value), repair_id="repair-one")
    def fail(event, payload): raise RuntimeError("offline")
    with pytest.raises(HarnessRecoveryError, match="Evidence write failed"):
        review_recovery(repair, candidate_commit="a" * 40, checkpoint_reference="checkpoint-one", validation="PASSED", reviewer_verdict="APPROVE", reviewer_risk="LOW", evidence_sink=fail)


def test_monitor_rejects_escaping_allowed_paths_and_invalid_retry_bounds():
    with pytest.raises(HarnessRecoveryError, match="escaping"):
        observe(snapshot(allowed_files=("../outside",)))
    with pytest.raises(HarnessRecoveryError, match="retry"):
        observe(snapshot(retry_count=-1))
