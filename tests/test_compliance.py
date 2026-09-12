from dataclasses import replace
import pytest
from swarm.compliance import *
from swarm.evidence import EvidenceLedger

def mapping(**kw):
 values=dict(schema_version="1",mapping_id="fw-comp/tenant-one/map-1",tenant_id="tenant-one",control_id="FW-CTRL-0001",requirement_ids=("FW-EVID-006","FW-REC-004"),owner="fw-evid",implementation_status="TESTED",evidence_references=("fw-evid/tenant-one/proof-1",),validation_state="SECURITY_REVIEWED",framework_references=("CIS-CONTROLS-8:8.2","NIST-CSF-2.0:GV.OV-01"),occurred_at="2026-09-11T02:00:00Z")
 values.update(kw); return ControlMapping(**values)

def test_mapping_is_immutable_descriptive_and_tenant_bound():
 item=mapping(); assert item.claim_status=="MAPPING_ONLY" and not item.authority_granted
 with pytest.raises(Exception): item.claim_status="CERTIFIED"
 with pytest.raises(ComplianceContractError): replace(item,claim_status="CERTIFIED")
 with pytest.raises(ComplianceContractError): mapping(mapping_id="fw-comp/tenant-two/map-1")

@pytest.mark.parametrize("changes",[
 {"requirement_ids":()}, {"requirement_ids":("FW-REC-004","FW-REC-004")}, {"requirement_ids":("bad",)}, {"evidence_references":()}, {"evidence_references":("fw-evid/tenant-two/proof",)}, {"framework_references":()}, {"framework_references":("SOC-2:CC1",)}, {"implementation_status":"CERTIFIED"}, {"validation_state":"PASS"}, {"owner":"password=secret-value"}, {"occurred_at":"tomorrow"}, {"authority_granted":True},
 {"control_id":"CONTROL-1"}, {"mapping_id":"map-1"}, {"tenant_id":"Tenant With Spaces","mapping_id":"fw-comp/Tenant With Spaces/map-1"},
])
def test_mapping_rejects_invalid_claims_bindings_and_secret_data(changes):
 with pytest.raises(ComplianceContractError): mapping(**changes)

def test_registry_writes_evidence_before_create_once_state():
 events=[]; registry=ControlMappingRegistry("tenant-one",events.append); item=mapping()
 assert registry.register(item)==item and registry.snapshot("tenant-one")== (item,)
 assert events[0]["claim_status"]=="MAPPING_ONLY" and events[0]["authority_granted"] is False
 with pytest.raises(ComplianceContractError,match="duplicate"): registry.register(item)
 with pytest.raises(ComplianceContractError,match="tenant"): registry.snapshot("tenant-two")

def test_evidence_failure_leaves_mapping_retryable_and_reentrancy_denied():
 item=mapping(); holder={}
 def reenter(_event): holder["registry"].register(item)
 registry=ControlMappingRegistry("tenant-one",reenter); holder["registry"]=registry
 with pytest.raises(ComplianceContractError,match="Evidence failed"): registry.register(item)
 assert registry.snapshot("tenant-one")==()
 events=[]; retry=ControlMappingRegistry("tenant-one",events.append); assert retry.register(item)==item

def test_cross_tenant_registration_fails_before_evidence():
 events=[]; registry=ControlMappingRegistry("tenant-one",events.append)
 with pytest.raises(ComplianceContractError,match="tenant"): registry.register(mapping(tenant_id="tenant-two",mapping_id="fw-comp/tenant-two/map-1",evidence_references=("fw-evid/tenant-two/proof",)))
 assert events==[]


def registered_adapter(*,sink=None):
 events=[]; registry=ControlMappingRegistry("tenant-one",events.append); item=registry.register(mapping()); writes=[]
 ledger=EvidenceLedger("tenant-one",sink or (lambda envelope,digest:writes.append((envelope,digest))))
 return item,registry,ledger,ComplianceEvidenceAdapter(registry,ledger),writes

def test_adapter_admits_exact_mapping_to_canonical_evidence():
 item,_,ledger,adapter,writes=registered_adapter()
 record=adapter.admit(item,evidence_id="fw-evid/tenant-one/compliance-map-1",actor_ref="fw-id/compliance-controller",subject_ref="fw-resource/compliance-map-1",correlation_id="fw-corr/tenant-one/compliance-map-1")
 assert record.envelope.payload_sha256==control_mapping_sha256(item)
 assert record.envelope.evidence_references==item.evidence_references
 assert record.envelope.payload_schema_id=="fw-schema/compliance/control-mapping-v1"
 assert record.envelope.event_type=="compliance.mapping_admitted"
 assert record.envelope.authority_granted is False and writes==[(record.envelope,record.record_sha256)]
 assert ledger.tenant_snapshot("tenant-one")== (record,)

def test_adapter_rejects_missing_stale_substituted_and_cross_tenant_mapping_before_evidence():
 item,registry,_,adapter,writes=registered_adapter()
 invalid=(replace(item,owner="other-owner"),mapping(mapping_id="fw-comp/tenant-one/missing"),mapping(tenant_id="tenant-two",mapping_id="fw-comp/tenant-two/map-1",evidence_references=("fw-evid/tenant-two/proof",)))
 for candidate in invalid:
  with pytest.raises(ComplianceContractError): adapter.admit(candidate,evidence_id="fw-evid/tenant-one/rejected",actor_ref="fw-id/controller",subject_ref="fw-resource/map")
 assert writes==[] and registry.snapshot("tenant-one")== (item,)

def test_adapter_replay_duplicate_and_stale_chain_fail_without_advancing():
 item,_,ledger,adapter,_=registered_adapter()
 first=adapter.admit(item,evidence_id="fw-evid/tenant-one/compliance-1",actor_ref="fw-id/controller",subject_ref="fw-resource/map")
 with pytest.raises(ComplianceContractError,match="admission failed"): adapter.admit(item,evidence_id="fw-evid/tenant-one/compliance-1",actor_ref="fw-id/controller",subject_ref="fw-resource/map")
 assert ledger.tenant_snapshot("tenant-one")== (first,)

def test_adapter_durability_failure_leaves_ledger_unadvanced_and_retryable():
 item,registry,ledger,adapter,_=registered_adapter(sink=lambda *_:(_ for _ in ()).throw(OSError("offline")))
 with pytest.raises(ComplianceContractError,match="admission failed"): adapter.admit(item,evidence_id="fw-evid/tenant-one/compliance-1",actor_ref="fw-id/controller",subject_ref="fw-resource/map")
 assert ledger.tenant_snapshot("tenant-one")==() and registry.snapshot("tenant-one")== (item,)
 retry_writes=[]; retry=ComplianceEvidenceAdapter(registry,EvidenceLedger("tenant-one",lambda e,d:retry_writes.append((e,d))))
 assert retry.admit(item,evidence_id="fw-evid/tenant-one/compliance-1",actor_ref="fw-id/controller",subject_ref="fw-resource/map").record_sha256

def test_adapter_rejects_invalid_envelope_and_mismatched_owners():
 item,registry,_,adapter,writes=registered_adapter()
 with pytest.raises(ComplianceContractError,match="envelope invalid"): adapter.admit(item,evidence_id="fw-evid/tenant-two/wrong",actor_ref="fw-id/controller",subject_ref="fw-resource/map")
 with pytest.raises(ComplianceContractError,match="matching canonical"): ComplianceEvidenceAdapter(registry,EvidenceLedger("tenant-two",lambda *_:None))
 assert writes==[]


def observation(item=None,**kw):
 item=item or mapping(); values=dict(schema_version="1",assessment_id="fw-comp-assessment/tenant-one/assessment-1",tenant_id="tenant-one",mapping_id=item.mapping_id,mapping_sha256=control_mapping_sha256(item),control_id=item.control_id,assessor_ref="fw-id/compliance-reviewer",observation_type="TEST_RESULT",outcome="OBSERVED",evidence_references=("fw-evid/tenant-one/test-proof",),fact_references=("fw-policy/control-evaluation","fw-test/compliance-proof"),observed_at="2026-09-11T02:00:00Z",expires_at="2026-10-11T02:00:00Z")
 values.update(kw); return ControlAssessmentObservation(**values)

def assessment_registry(sink=None):
 mapping_events=[]; mappings=ControlMappingRegistry("tenant-one",mapping_events.append); item=mappings.register(mapping()); events=[]
 return item,mappings,ControlAssessmentRegistry("tenant-one",mappings,sink or events.append),events

def test_assessment_records_exact_mapping_and_bounded_facts_evidence_first():
 item,_,registry,events=assessment_registry(); value=observation(item)
 assert registry.register(value,item,as_of="2026-09-12T00:00:00Z")==value
 assert registry.snapshot("tenant-one")== (value,) and events[0]["mapping_sha256"]==control_mapping_sha256(item)
 assert events[0]["claim_status"]=="OBSERVATION_ONLY" and events[0]["authority_granted"] is False
 with pytest.raises(ComplianceContractError,match="duplicate"): registry.register(value,item,as_of="2026-09-12T00:00:00Z")

@pytest.mark.parametrize("changes",[{"assessment_id":"fw-comp-assessment/tenant-two/a"},{"mapping_sha256":"0"},{"control_id":"CONTROL-9999"},{"assessor_ref":"admin"},{"observation_type":"CERTIFICATION"},{"outcome":"COMPLIANT"},{"evidence_references":()},{"evidence_references":("fw-evid/tenant-two/proof",)},{"fact_references":()},{"fact_references":("external/report",)},{"observed_at":"tomorrow"},{"expires_at":"2026-09-11T02:00:00Z"},{"claim_status":"CERTIFIED"},{"authority_granted":True}])
def test_assessment_rejects_invalid_bindings_claims_and_secret_free_facts(changes):
 with pytest.raises(ComplianceContractError): observation(**changes)

def test_assessment_rejects_stale_mapping_cross_tenant_and_expiry_before_evidence():
 item,_,registry,events=assessment_registry(); value=observation(item)
 for changed_mapping in (replace(item,owner="other"),mapping(mapping_id="fw-comp/tenant-one/missing")):
  with pytest.raises(ComplianceContractError): registry.register(value,changed_mapping,as_of="2026-09-12T00:00:00Z")
 with pytest.raises(ComplianceContractError,match="mapping binding"): registry.register(replace(value,mapping_sha256="0"*64),item,as_of="2026-09-12T00:00:00Z")
 with pytest.raises(ComplianceContractError,match="mapping binding"): registry.register(replace(value,control_id="FW-CTRL-9999"),item,as_of="2026-09-12T00:00:00Z")
 with pytest.raises(ComplianceContractError,match="expired"): registry.register(value,item,as_of=value.expires_at)
 cross=mapping(tenant_id="tenant-two",mapping_id="fw-comp/tenant-two/map-1",evidence_references=("fw-evid/tenant-two/proof",))
 with pytest.raises(ComplianceContractError): registry.register(observation(cross,tenant_id="tenant-two",assessment_id="fw-comp-assessment/tenant-two/a",evidence_references=("fw-evid/tenant-two/proof",)),cross,as_of="2026-09-12T00:00:00Z")
 assert events==[] and registry.snapshot("tenant-one")==()

def test_assessment_evidence_failure_is_retryable_and_reentrancy_denied():
 item,mappings,_,_=assessment_registry(); value=observation(item); holder={}
 def reenter(_): holder["registry"].register(value,item,as_of="2026-09-12T00:00:00Z")
 registry=ControlAssessmentRegistry("tenant-one",mappings,reenter); holder["registry"]=registry
 with pytest.raises(ComplianceContractError,match="Evidence failed"): registry.register(value,item,as_of="2026-09-12T00:00:00Z")
 assert registry.snapshot("tenant-one")==()
 events=[]; retry=ControlAssessmentRegistry("tenant-one",mappings,events.append); assert retry.register(value,item,as_of="2026-09-12T00:00:00Z")==value

def test_assessment_registry_requires_same_tenant_and_valid_current_time():
 item,mappings,registry,events=assessment_registry()
 with pytest.raises(ComplianceContractError,match="matching mapping"): ControlAssessmentRegistry("tenant-two",mappings,events.append)
 with pytest.raises(ComplianceContractError,match="current time"): registry.register(observation(item),item,as_of="now")
 with pytest.raises(ComplianceContractError,match="tenant"): registry.snapshot("tenant-two")
 assert events==[]


def test_integrated_compliance_mapping_evidence_assessment_lifecycle():
 mapping_events=[]; mappings=ControlMappingRegistry("tenant-one",mapping_events.append); item=mappings.register(mapping())
 durable=[]; ledger=EvidenceLedger("tenant-one",lambda envelope,digest:durable.append((envelope,digest)))
 adapter=ComplianceEvidenceAdapter(mappings,ledger)
 evidence=adapter.admit(item,evidence_id="fw-evid/tenant-one/comp-lifecycle",actor_ref="fw-id/compliance-controller",subject_ref="fw-resource/control-map",correlation_id="fw-corr/tenant-one/comp-lifecycle")
 assessment_events=[]; assessments=ControlAssessmentRegistry("tenant-one",mappings,assessment_events.append)
 value=observation(item,evidence_references=(evidence.envelope.evidence_id,),fact_references=("fw-policy/control-evaluation","fw-test/compliance-lifecycle"))
 recorded=assessments.register(value,item,as_of="2026-09-12T00:00:00Z")
 assert evidence.envelope.payload_sha256==recorded.mapping_sha256==control_mapping_sha256(item)
 assert evidence.envelope.tenant_id==recorded.tenant_id==item.tenant_id
 assert recorded.control_id==item.control_id and recorded.evidence_references==(evidence.envelope.evidence_id,)
 assert mappings.snapshot("tenant-one")== (item,) and ledger.tenant_snapshot("tenant-one")== (evidence,) and assessments.snapshot("tenant-one")== (recorded,)
 assert durable==[(evidence.envelope,evidence.record_sha256)] and len(mapping_events)==len(assessment_events)==1
 for operation in (lambda: adapter.admit(item,evidence_id=evidence.envelope.evidence_id,actor_ref="fw-id/compliance-controller",subject_ref="fw-resource/control-map"),lambda: assessments.register(recorded,item,as_of="2026-09-12T00:00:00Z"),lambda: assessments.register(replace(recorded,assessment_id="fw-comp-assessment/tenant-one/stale",mapping_sha256="0"*64),item,as_of="2026-09-12T00:00:00Z"),lambda: assessments.register(replace(recorded,assessment_id="fw-comp-assessment/tenant-one/expired"),item,as_of=recorded.expires_at)):
  with pytest.raises(ComplianceContractError): operation()
 assert mappings.snapshot("tenant-one")== (item,) and ledger.tenant_snapshot("tenant-one")== (evidence,) and assessments.snapshot("tenant-one")== (recorded,)
