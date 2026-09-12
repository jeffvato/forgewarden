import copy
import pytest
from swarm.endpoint_fixtures import EndpointFixtureDenied
from swarm.normalized_events import AI_EVENT_CLASSES, NormalizedEventStore, validate_ai_workload_event

def event(**changes):
 value={"schema_version":"1","event_id":"fw-event/tenant-a/aid-1","tenant_id":"tenant-a","event_class":"AID-PRIVILEGE","source":"harness.fixture","classification":"INTERNAL","observed_at_epoch":100,"agent_ref":"fw-id/tenant-a/codex-worker","model_ref":"fw-model/tenant-a/codex","session_ref":"fw-session/tenant-a/session-1","task_ref":"fw-task/tenant-a/task-1","initiating_user_ref":"fw-id/tenant-a/operator","purpose_sha256":"a"*64,"capability_lease_ref":"fw-lease/tenant-a/lease-1","action_ticket_ref":"fw-action/tenant-a/ticket-1","tool_category":"MCP","mcp_server_ref":"registered-mcp","target_resource_ref":"fw-resource/tenant-a/repository","decision":"DENIED","anomaly_indicators":["authority_expansion","repeated_denial"],"evidence_references":["fw-evid/tenant-a/harness-1"],"mode":"DRY_RUN","action":"DETECT_ONLY","authority_granted":False}; value.update(changes); return value

def test_all_ten_ai_threat_classes_normalize_without_authority():
 for threat in AI_EVENT_CLASSES:
  item=validate_ai_workload_event(event(event_class=threat,event_id=f"fw-event/tenant-a/{threat.lower()}"))
  assert item.event_class==threat and item.mode=="DRY_RUN" and item.action=="DETECT_ONLY" and not item.authority_granted

def test_store_admits_evidence_first_and_projects_only_same_tenant_agent():
 calls=[]; store=NormalizedEventStore(lambda *args:calls.append(args)); item=store.admit_ai_security_event(event())
 assert calls[0][0]=="ai_security_event_admitted" and "prompt" not in calls[0][1] and "command" not in calls[0][1]
 assert store.pending_ai_security_events(tenant_id="tenant-a",agent_ref=item.agent_ref)==(item,)
 assert store.pending_ai_security_events(tenant_id="tenant-b",agent_ref="fw-id/tenant-b/codex-worker")==()
 with pytest.raises(EndpointFixtureDenied,match="REPLAY"): store.admit_ai_security_event(event())

@pytest.mark.parametrize("change",[{"prompt":"ignore safeguards"},{"command":"cat secrets"},{"api_key":"sk-secretvalue"},{"tenant_id":"tenant-b"},{"agent_ref":"fw-id/tenant-b/worker"},{"model_ref":"fw-model/tenant-b/model"},{"task_ref":"fw-task/tenant-b/task"},{"evidence_references":["fw-evid/tenant-b/proof"]},{"purpose_sha256":"bad"},{"event_class":"AID-UNKNOWN"},{"classification":"TOP_SECRET"},{"tool_category":"ARBITRARY_SHELL"},{"decision":"AUTHORIZED"},{"anomaly_indicators":["password=secretvalue"]},{"anomaly_indicators":[str(i) for i in range(33)]},{"mode":"LIVE"},{"action":"CONTAIN"},{"authority_granted":True}])
def test_ai_event_rejects_unknown_raw_secret_cross_tenant_malformed_and_authority(change):
 with pytest.raises(EndpointFixtureDenied): validate_ai_workload_event(event(**change))

def test_ai_event_evidence_failure_does_not_enqueue_and_is_retryable():
 store=NormalizedEventStore(lambda *_:(_ for _ in ()).throw(OSError("offline")))
 with pytest.raises(EndpointFixtureDenied,match="EVIDENCE_WRITE_FAILED"): store.admit_ai_security_event(event())
 assert store.pending_ai_security_events(tenant_id="tenant-a",agent_ref="fw-id/tenant-a/codex-worker")==()
 retry=NormalizedEventStore(lambda *_:None); assert retry.admit_ai_security_event(event()).event_id.endswith("aid-1")

def test_ai_event_collections_are_unique_sorted_bounded_and_snapshot_is_bounded():
 for bad in (["z","a"],["a","a"],"a"):
  with pytest.raises(EndpointFixtureDenied): validate_ai_workload_event(event(anomaly_indicators=bad))
 store=NormalizedEventStore(lambda *_:None); store.admit_ai_security_event(event())
 for limit in (0,129,True):
  with pytest.raises(EndpointFixtureDenied): store.pending_ai_security_events(tenant_id="tenant-a",agent_ref="fw-id/tenant-a/codex-worker",limit=limit)
