import pytest

from swarm.endpoint_fixtures import EndpointObservation
from swarm.ransomware import RansomwareEvaluationDenied, evaluate_ransomware_activity


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
