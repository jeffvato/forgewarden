import pytest

from swarm.action_ticket import ActionTicket, ActionTicketRegistry
from swarm.asoc import HMACLeaseSigner
from swarm.endpoint_fixtures import EndpointObservation
from swarm.ransomware import RansomwareCanaryRegistry, RansomwareEvaluationDenied, evaluate_ransomware_activity, evaluate_smb_propagation, propose_ransomware_isolation


def observation(event_id, observed, operation="WRITE", indicators=(), tenant="tenant-a", device="device-a"):
    return EndpointObservation(
        event_id, tenant, device, observed, "FILE_LIFECYCLE", "WINDOWS_SENSOR",
        (("operation", operation), ("path", f"C:/fixture/{event_id}")), (),
        tuple(indicators), f"evidence-{event_id}",
    )


def test_high_confidence_finding_is_evidence_first_and_non_executing():
    events = []
    items = [
        observation("e1", 100, "WRITE", ("HIGH_ENTROPY",)),
        observation("e2", 101, "RENAME", ("EXTENSION_CHANGE",)),
        observation("e3", 102, "WRITE"), observation("e4", 103, "DELETE"),
    ]
    finding = evaluate_ransomware_activity(
        list(reversed(items)), tenant_id="tenant-a", device_id="device-a",
        audit=lambda *args: events.append(args),
    )
    assert finding.confidence == "HIGH"
    assert finding.event_ids == ("e1", "e2", "e3", "e4")
    assert finding.signals == ("EXTENSION_CHANGE", "HIGH_ENTROPY", "MASS_FILE_CHANGE")
    assert finding.recommendations == ("WARN", "PROPOSE_ISOLATION")
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert events[0][0] == "ransomware_activity_evaluated"
    assert events[0][1]["deployment"] == "DISABLED"


def test_every_finding_warns_and_benign_window_returns_none_with_evidence():
    evidence = []
    low = evaluate_ransomware_activity(
        [observation("e1", 100, indicators=("RANSOM_NOTE",))],
        tenant_id="tenant-a", device_id="device-a", audit=lambda *args: evidence.append(args),
    )
    assert low.confidence == "LOW" and low.recommendations == ("WARN",)
    assert evaluate_ransomware_activity(
        [observation("e2", 101)], tenant_id="tenant-a", device_id="device-a",
        audit=lambda *args: evidence.append(args),
    ) is None
    assert evidence[-1][1]["confidence"] == "NONE"


def test_noncanonical_signal_case_does_not_match():
    finding = evaluate_ransomware_activity(
        [observation("e1", 100, operation="write", indicators=("ransom_note",))],
        tenant_id="tenant-a", device_id="device-a", audit=lambda *_args: None,
    )
    assert finding is None


@pytest.mark.parametrize("items, reason", [
    ([], "EVENT_COUNT_INVALID"),
    ([observation("e1", 100), observation("e1", 101)], "EVENT_ID_DUPLICATE"),
    ([observation("e1", 100), observation("e2", 401)], "EVENT_WINDOW_EXCEEDED"),
    ([observation("e1", 100), observation("e2", 101, tenant="tenant-b")], "TENANT_OR_DEVICE_MISMATCH"),
])
def test_invalid_windows_fail_closed_before_evidence(items, reason):
    evidence = []
    with pytest.raises(RansomwareEvaluationDenied, match=reason):
        evaluate_ransomware_activity(items, tenant_id="tenant-a", device_id="device-a", audit=lambda *args: evidence.append(args))
    assert evidence == []


def test_evidence_failure_denies_the_result():
    def fail(*_args):
        raise RuntimeError("offline")
    with pytest.raises(RansomwareEvaluationDenied, match="EVIDENCE_WRITE_FAILED"):
        evaluate_ransomware_activity(
            [observation("e1", 100, indicators=("RANSOM_NOTE",))],
            tenant_id="tenant-a", device_id="device-a", audit=fail,
        )


def high_finding():
    return evaluate_ransomware_activity([
        observation("e1", 100, "WRITE", ("HIGH_ENTROPY",)),
        observation("e2", 101, "RENAME", ("EXTENSION_CHANGE",)),
        observation("e3", 102, "WRITE"), observation("e4", 103, "DELETE"),
    ], tenant_id="tenant-a", device_id="device-a", audit=lambda *_args: None)


def ticket_registry(*, resource="device-a", expires=200):
    registry = ActionTicketRegistry(HMACLeaseSigner({"key-1": b"test-only-key-material"}))
    registry.issue(ActionTicket(
        "ticket-1", "tenant-a", "agent-1", "lease-1", "endpoint.isolate.propose",
        resource, "ISOLATION_PROPOSAL", "human-1", "approval-1", "policy-1",
        100, expires, "key-1",
    ))
    return registry


def test_high_finding_creates_evidence_first_single_use_dry_run_proposal():
    tickets = ticket_registry()
    evidence = []
    proposal = propose_ransomware_isolation(
        high_finding(), tickets=tickets, ticket_id="ticket-1", subject_agent_id="agent-1",
        lease_id="lease-1", policy_version="policy-1", now=150,
        kill_switch_state="ENGAGED", audit=lambda *args: evidence.append(args),
    )
    assert proposal.mode == "DRY_RUN" and proposal.action == "DETECT_ONLY"
    assert evidence[0][0] == "ransomware_isolation_proposed"
    assert evidence[0][1]["containment_executed"] is False
    with pytest.raises(RansomwareEvaluationDenied, match="ACTION_TICKET_DENIED"):
        propose_ransomware_isolation(
            high_finding(), tickets=tickets, ticket_id="ticket-1", subject_agent_id="agent-1",
            lease_id="lease-1", policy_version="policy-1", now=150,
            kill_switch_state="ENGAGED", audit=lambda *_args: None,
        )


def test_isolation_proposal_denies_low_confidence_ticket_mismatch_and_kill_switch_before_evidence():
    evidence = []
    low = evaluate_ransomware_activity(
        [observation("low", 100, indicators=("RANSOM_NOTE",))],
        tenant_id="tenant-a", device_id="device-a", audit=lambda *_args: None,
    )
    base = dict(tickets=ticket_registry(), ticket_id="ticket-1", subject_agent_id="agent-1",
                lease_id="lease-1", policy_version="policy-1", now=150,
                kill_switch_state="ENGAGED", audit=lambda *args: evidence.append(args))
    with pytest.raises(RansomwareEvaluationDenied, match="CONFIDENCE_INSUFFICIENT"):
        propose_ransomware_isolation(low, **base)
    with pytest.raises(RansomwareEvaluationDenied, match="ACTION_TICKET_DENIED"):
        propose_ransomware_isolation(high_finding(), **(base | {"tickets": ticket_registry(resource="other")}))
    with pytest.raises(RansomwareEvaluationDenied, match="KILL_SWITCH_NOT_ENGAGED"):
        propose_ransomware_isolation(high_finding(), **(base | {"kill_switch_state": "CLEARED"}))
    assert evidence == []


def test_isolation_proposal_evidence_failure_does_not_consume_ticket():
    tickets = ticket_registry()
    def fail(*_args):
        raise RuntimeError("offline")
    kwargs = dict(tickets=tickets, ticket_id="ticket-1", subject_agent_id="agent-1",
                  lease_id="lease-1", policy_version="policy-1", now=150,
                  kill_switch_state="ENGAGED")
    with pytest.raises(RansomwareEvaluationDenied, match="EVIDENCE_WRITE_FAILED"):
        propose_ransomware_isolation(high_finding(), audit=fail, **kwargs)
    proposal = propose_ransomware_isolation(high_finding(), audit=lambda *_args: None, **kwargs)
    assert proposal.ticket_id == "ticket-1"


def test_canary_registration_and_exact_touch_are_evidence_first_and_warn_only():
    evidence = []
    registry = RansomwareCanaryRegistry(lambda *args: evidence.append(args))
    assert registry.register(("C:/canary/b", "C:/canary/a"), tenant_id="tenant-a", device_id="device-a") == ("C:/canary/a", "C:/canary/b")
    finding = registry.evaluate_touch(
        observation("canary-touch", 100, operation="WRITE"),
        tenant_id="tenant-a", device_id="device-a",
    )
    assert finding is None
    touched = EndpointObservation(
        "canary-touch", "tenant-a", "device-a", 100, "FILE_LIFECYCLE", "WINDOWS_SENSOR",
        (("operation", "WRITE"), ("path", "C:/canary/a")), (), (), "evidence-canary",
    )
    finding = registry.evaluate_touch(touched, tenant_id="tenant-a", device_id="device-a")
    assert finding.signals == ("CANARY_TOUCHED",)
    assert finding.confidence == "HIGH" and finding.recommendations == ("WARN",)
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert [item[0] for item in evidence] == ["ransomware_canaries_registered", "ransomware_canary_touched"]
    assert "identifiers" not in evidence[0][1] and "canary_identifier" not in evidence[1][1]
    assert len(evidence[0][1]["identifier_refs"][0]) == 64


def test_canary_registry_is_tenant_device_isolated_and_rejects_duplicates():
    registry = RansomwareCanaryRegistry(lambda *_args: None)
    registry.register(("C:/canary/a",), tenant_id="tenant-a", device_id="device-a")
    with pytest.raises(RansomwareEvaluationDenied, match="CANARY_SCOPE_ALREADY_REGISTERED"):
        registry.register(("C:/canary/b",), tenant_id="tenant-a", device_id="device-a")
    with pytest.raises(RansomwareEvaluationDenied, match="CANARY_DUPLICATE"):
        RansomwareCanaryRegistry(lambda *_args: None).register(("a", "a"), tenant_id="tenant-a", device_id="device-a")
    with pytest.raises(RansomwareEvaluationDenied, match="CANARY_SCOPE_INVALID"):
        RansomwareCanaryRegistry(lambda *_args: None).register(("a",), tenant_id=" tenant-a", device_id="device-a")
    cross_tenant = EndpointObservation(
        "cross", "tenant-b", "device-a", 100, "FILE_LIFECYCLE", "WINDOWS_SENSOR",
        (("operation", "WRITE"), ("path", "C:/canary/a")), (), (), "evidence-cross",
    )
    with pytest.raises(RansomwareEvaluationDenied, match="TENANT_OR_DEVICE_MISMATCH"):
        registry.evaluate_touch(cross_tenant, tenant_id="tenant-a", device_id="device-a")


def test_canary_evidence_failures_do_not_register_or_return_findings():
    calls = 0
    def fail(*_args):
        nonlocal calls
        calls += 1
        raise RuntimeError("offline")
    registry = RansomwareCanaryRegistry(fail)
    with pytest.raises(RansomwareEvaluationDenied, match="EVIDENCE_WRITE_FAILED"):
        registry.register(("C:/canary/a",), tenant_id="tenant-a", device_id="device-a")
    assert calls == 1
    evidence = []
    registry = RansomwareCanaryRegistry(lambda *args: evidence.append(args))
    registry.register(("C:/canary/a",), tenant_id="tenant-a", device_id="device-a")
    registry._audit = fail
    touched = EndpointObservation(
        "touch", "tenant-a", "device-a", 100, "FILE_LIFECYCLE", "WINDOWS_SENSOR",
        (("operation", "WRITE"), ("path", "C:/canary/a")), (), (), "evidence-touch",
    )
    with pytest.raises(RansomwareEvaluationDenied, match="EVIDENCE_WRITE_FAILED"):
        registry.evaluate_touch(touched, tenant_id="tenant-a", device_id="device-a")


def network_observation(event_id, device, observed, indicators):
    return EndpointObservation(
        event_id, "tenant-a", device, observed, "NETWORK_CONNECT", "WINDOWS_SENSOR",
        (("destination", "fixture-smb"),), (), tuple(indicators), f"evidence-{event_id}",
    )


def test_smb_propagation_is_deterministic_evidence_first_and_warn_only():
    evidence = []
    items = [
        network_observation("e2", "device-b", 102, ("SMB_WRITE",)),
        network_observation("e1", "device-a", 100, ("SMB_WRITE", "LATERAL_MOVEMENT")),
    ]
    finding = evaluate_smb_propagation(
        items, tenant_id="tenant-a", audit=lambda *args: evidence.append(args),
    )
    assert finding.device_ids == ("device-a", "device-b")
    assert finding.event_ids == ("e1", "e2")
    assert finding.signals == ("LATERAL_MOVEMENT", "SMB_PROPAGATION")
    assert finding.confidence == "HIGH" and finding.recommendations == ("WARN",)
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert evidence[0][0] == "ransomware_smb_propagation_detected"
    assert evidence[0][1]["deployment"] == "DISABLED"


def test_smb_propagation_requires_exact_tokens_and_multiple_devices():
    assert evaluate_smb_propagation([
        network_observation("e1", "device-a", 100, ("smb_write", "lateral_movement")),
        network_observation("e2", "device-b", 101, ("smb_write",)),
    ], tenant_id="tenant-a", audit=lambda *_args: None) is None
    assert evaluate_smb_propagation([
        network_observation("e1", "device-a", 100, ("SMB_WRITE", "LATERAL_MOVEMENT")),
        network_observation("e2", "device-a", 101, ("SMB_WRITE",)),
    ], tenant_id="tenant-a", audit=lambda *_args: None) is None


def test_smb_propagation_rejects_cross_tenant_duplicates_and_evidence_failure():
    cross = network_observation("e1", "device-a", 100, ("SMB_WRITE", "LATERAL_MOVEMENT"))
    cross = EndpointObservation(
        cross.event_id, "tenant-b", cross.device_id, cross.observed_at_epoch,
        cross.event_type, cross.source, cross.metadata, (), cross.related_indicators, cross.evidence_ref,
    )
    with pytest.raises(RansomwareEvaluationDenied, match="TENANT_MISMATCH"):
        evaluate_smb_propagation([cross], tenant_id="tenant-a", audit=lambda *_args: None)
    duplicate = network_observation("e1", "device-a", 100, ("SMB_WRITE",))
    with pytest.raises(RansomwareEvaluationDenied, match="EVENT_ID_DUPLICATE"):
        evaluate_smb_propagation([duplicate, duplicate], tenant_id="tenant-a", audit=lambda *_args: None)
    items = [
        network_observation("e1", "device-a", 100, ("SMB_WRITE", "LATERAL_MOVEMENT")),
        network_observation("e2", "device-b", 101, ("SMB_WRITE",)),
    ]
    with pytest.raises(RansomwareEvaluationDenied, match="EVIDENCE_WRITE_FAILED"):
        evaluate_smb_propagation(items, tenant_id="tenant-a", audit=lambda *_args: (_ for _ in ()).throw(RuntimeError("offline")))


def test_smb_propagation_enforces_window_and_device_bounds_before_evidence():
    evidence = []
    with pytest.raises(RansomwareEvaluationDenied, match="EVENT_WINDOW_EXCEEDED"):
        evaluate_smb_propagation([
            network_observation("e1", "device-a", 100, ("SMB_WRITE", "LATERAL_MOVEMENT")),
            network_observation("e2", "device-b", 401, ("SMB_WRITE",)),
        ], tenant_id="tenant-a", audit=lambda *args: evidence.append(args))
    with pytest.raises(RansomwareEvaluationDenied, match="DEVICE_COUNT_EXCEEDED"):
        evaluate_smb_propagation([
            network_observation(f"e{i}", f"device-{i}", 100 + i, ("SMB_WRITE", "LATERAL_MOVEMENT"))
            for i in range(17)
        ], tenant_id="tenant-a", audit=lambda *args: evidence.append(args))
    assert evidence == []
