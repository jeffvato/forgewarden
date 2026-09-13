from swarm.macos_fixtures import MACOS_SOURCE, ingest_macos_batch
from swarm.normalized_events import NormalizedEventStore
from swarm.ransomware import evaluate_ransomware_activity


def _record(event_id, observed_at, operation, indicators=()):
    return {
        "event_id": event_id,
        "tenant_id": "tenant-a",
        "device_id": "mac-1",
        "observed_at_epoch": observed_at,
        "event_type": "FILE_LIFECYCLE",
        "source": MACOS_SOURCE,
        "metadata": {"path": f"/Users/fixture/{event_id}", "operation": operation},
        "process_ancestry": [],
        "related_indicators": list(indicators),
        "evidence_ref": f"evidence-{event_id}",
    }


def test_macos_fixtures_reuse_canonical_ransomware_evaluator():
    evidence = []
    store = NormalizedEventStore(lambda *args: evidence.append(args))
    observations = ingest_macos_batch(
        store,
        [
            _record("m4", 103, "DELETE"),
            _record("m2", 101, "RENAME", ("EXTENSION_CHANGE",)),
            _record("m1", 100, "WRITE", ("HIGH_ENTROPY",)),
            _record("m3", 102, "WRITE"),
        ],
        tenant_id="tenant-a", device_id="mac-1", now_epoch=150,
    )
    finding = evaluate_ransomware_activity(
        observations, tenant_id="tenant-a", device_id="mac-1",
        audit=lambda *args: evidence.append(args),
    )
    assert finding is not None
    assert finding.event_ids == ("m1", "m2", "m3", "m4")
    assert finding.signals == ("EXTENSION_CHANGE", "HIGH_ENTROPY", "MASS_FILE_CHANGE")
    assert finding.confidence == "HIGH"
    assert finding.recommendations == ("WARN", "PROPOSE_ISOLATION")
    assert finding.mode == "DRY_RUN" and finding.action == "DETECT_ONLY"
    assert [item[0] for item in evidence] == [
        "endpoint_events_batch_admitted", "ransomware_activity_evaluated",
    ]
    assert evidence[-1][1]["deployment"] == "DISABLED"
