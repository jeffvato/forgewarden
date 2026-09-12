from dataclasses import replace
import pytest
from swarm.compliance import *

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
