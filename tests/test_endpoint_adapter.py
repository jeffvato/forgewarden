import pytest

from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import NormalizedEventStore, validate_ai_endpoint_attribution


def endpoint_fixture(event_id="event-1", tenant="tenant-a", device="device-a"):
    return {"event_id":event_id,"tenant_id":tenant,"device_id":device,"observed_at_epoch":100,"event_type":"PROCESS_START","source":"LINUX_SENSOR","process":{"pid":"42"},"evidence_ref":"evidence-1","process_ancestry":[],"related_indicators":["ai-origin"]}


def attribution(**updates):
    value={"schema_version":"1","tenant_id":"tenant-a","device_id":"device-a","endpoint_event_id":"event-1","agent_ref":"fw-id/tenant-a/agent-1","session_ref":"fw-session/tenant-a/session-1","task_ref":"fw-task/tenant-a/task-1","capability_lease_ref":"fw-lease/tenant-a/lease-1","action_ticket_ref":"fw-action/tenant-a/action-1","observed_at_epoch":100,"evidence_references":["fw-evid/tenant-a/endpoint-1"],"mode":"DRY_RUN","action":"CORRELATE_ONLY","authority_granted":False}
    value.update(updates); return value


def admitted_store(audit=lambda *_:None):
    store=NormalizedEventStore(audit)
    store.admit_fixture(endpoint_fixture(),tenant_id="tenant-a",device_id="device-a",source="LINUX_SENSOR",now_epoch=150)
    return store


def test_ai_endpoint_attribution_binds_existing_fixture_and_writes_evidence_first():
    evidence=[]; store=admitted_store(lambda *args:evidence.append(args))
    item=store.admit_ai_endpoint_attribution(attribution())
    assert item.agent_ref=="fw-id/tenant-a/agent-1"
    assert item.mode=="DRY_RUN" and item.action=="CORRELATE_ONLY" and item.authority_granted is False
    assert evidence[-1][0]=="ai_endpoint_attribution_admitted"
    assert store.pending_ai_endpoint_attributions(tenant_id="tenant-a",device_id="device-a")== (item,)
    assert store.pending_ai_endpoint_attributions(tenant_id="tenant-b",device_id="device-a")==()


@pytest.mark.parametrize("updates,reason",[
    ({"tenant_id":"tenant-b"},"TENANT_MISMATCH"),
    ({"agent_ref":"fw-id/tenant-b/agent-1"},"TENANT_MISMATCH"),
    ({"observed_at_epoch":99},"CHRONOLOGY_MISMATCH"),
    ({"mode":"LIVE"},"AUTHORITY_FORBIDDEN"),
    ({"action":"EXECUTE"},"AUTHORITY_FORBIDDEN"),
    ({"authority_granted":True},"AUTHORITY_FORBIDDEN"),
    ({"evidence_references":["fw-evid/tenant-b/nope"]},"TENANT_MISMATCH"),
])
def test_ai_endpoint_attribution_rejects_boundary_and_authority_changes(updates,reason):
    with pytest.raises(EndpointFixtureDenied,match=reason): admitted_store().admit_ai_endpoint_attribution(attribution(**updates))


def test_ai_endpoint_attribution_requires_pending_exact_event_and_denies_replay():
    store=admitted_store(); store.admit_ai_endpoint_attribution(attribution())
    with pytest.raises(EndpointFixtureDenied,match="AI_ENDPOINT_REPLAY"): store.admit_ai_endpoint_attribution(attribution())
    with pytest.raises(EndpointFixtureDenied,match="AI_ENDPOINT_EVENT_NOT_PENDING"): store.admit_ai_endpoint_attribution(attribution(endpoint_event_id="event-2"))


def test_ai_endpoint_attribution_evidence_failure_does_not_enqueue_or_consume_replay():
    def audit(kind,_payload):
        if kind=="ai_endpoint_attribution_admitted": raise OSError("offline")
    store=admitted_store(audit)
    with pytest.raises(EndpointFixtureDenied,match="EVIDENCE_WRITE_FAILED"): store.admit_ai_endpoint_attribution(attribution())
    assert store.pending_ai_endpoint_attributions(tenant_id="tenant-a",device_id="device-a")==()
    healthy=admitted_store(); assert healthy.admit_ai_endpoint_attribution(attribution()).endpoint_event_id=="event-1"


def test_ai_endpoint_attribution_rejects_extra_fields_raw_content_and_invalid_snapshot_limit():
    value=attribution(); value["prompt"]="ignore policy"
    with pytest.raises(EndpointFixtureDenied,match="AI_ENDPOINT_FIELDS_INVALID"): validate_ai_endpoint_attribution(value)
    with pytest.raises(EndpointFixtureDenied,match="AI_ENDPOINT_SNAPSHOT_LIMIT_INVALID"): admitted_store().pending_ai_endpoint_attributions(tenant_id="tenant-a",device_id="device-a",limit=0)

def test_ai_endpoint_attribution_enforces_evidence_and_snapshot_bounds():
    too_many=attribution(evidence_references=[f"fw-evid/tenant-a/e-{i:02d}" for i in range(33)])
    with pytest.raises(EndpointFixtureDenied,match="AI_ENDPOINT_EVIDENCE_INVALID"): validate_ai_endpoint_attribution(too_many)
    store=admitted_store()
    with pytest.raises(EndpointFixtureDenied,match="AI_ENDPOINT_SNAPSHOT_LIMIT_INVALID"): store.pending_ai_endpoint_attributions(tenant_id="tenant-a",device_id="device-a",limit=129)


def test_ai_endpoint_attribution_queue_is_bounded_per_device(monkeypatch):
    import swarm.normalized_events as normalized_events
    monkeypatch.setattr(normalized_events, "MAX_AI_ATTRIBUTIONS_PER_DEVICE", 1)
    store=NormalizedEventStore(lambda *_:None)
    store.admit_batch([endpoint_fixture("event-1"),endpoint_fixture("event-2")],tenant_id="tenant-a",device_id="device-a",source="LINUX_SENSOR",now_epoch=150)
    store.admit_ai_endpoint_attribution(attribution(endpoint_event_id="event-1"))
    with pytest.raises(EndpointFixtureDenied,match="AI_ENDPOINT_QUEUE_FULL"):
        store.admit_ai_endpoint_attribution(attribution(endpoint_event_id="event-2"))
