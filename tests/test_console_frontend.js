'use strict';
const assert = require('node:assert/strict');

const ids = ['policy-live-state','evidence-verification-state','evidence-record-state','evidence-live-state','incident-live-state','harness-live-state','view-title','executive-headline','executive-summary','executive-risk','executive-attention','executive-recovery','executive-outcomes','tour-map','tour-step','tour-label','tour-detail','demo-tour','vault-tenant','evidence-chronology','policy-id','policy-engine','policy-subject','policy-resource','policy-action','policy-decision','policy-reason','policy-radius','policy-lease','policy-approval','ticket-id','ticket-operation','ticket-requester','ticket-authority','ticket-target','ticket-scope','ticket-expires','ticket-signature','ticket-status','model-table','mcp-grid','aid-agent','aid-score','aid-authority','aid-model','aid-task','aid-session','aid-lease','aid-ticket','aid-mcp','aid-proposal','aid-incident','aid-tools','aid-evidence','harness-detail-model','harness-detail-lease','harness-detail-review','harness-score','harness-identity','harness-tenant','harness-registry','harness-lease-scope','harness-validation','harness-reviewer','harness-commit','harness-capabilities','harness-tools','budget-calls','budget-tokens','budget-elapsed','budget-diff','harness-escalation','scenario-id','connection','mode','deployment','kill-switch','posture-score','posture-label','posture-trend','posture-bars','agent-count','denied-count','suspended-count','asset-grid','executive-metrics','incident-status','incident-id','incident-title','incident-summary','affected','attack-story','incident-timeline','detail-incident-id','detail-incident-title','detail-incident-summary','detail-confidence','detail-status','detail-affected','incident-detections','incident-actions','recovery-checkpoint','recovery-state','recovery-execution','incident-evidence','incident-ticket','incident-chain','harness-flow','harness-flow-large','harness-tier','harness-detail-tier','harness-model','harness-lease','harness-review','harness-task','harness-requester','routing-reason','harness-budget','actions','ai-risk','ai-events','evidence-records','evidence-bundle','chain-status','vault-bundle','vault-chain','vault-ticket'];
const {escapeHtml,validateSnapshot,validateCoreStatus,validateHarnessActivity,validateIncidentActivity,validateEvidenceActivity,validatePolicyTicketActivity,validateModelMCPActivity,MissionControlClient,renderStory,renderCanonicalIncident,renderIncidentActivity,renderEvidenceActivity,renderPolicyTicketActivity,renderModelMCPActivity,render,showTour} = require('../console/app.js');
const elements = Object.fromEntries(ids.map(id => [id, {textContent:'',innerHTML:''}]));
global.document = {getElementById:id=>elements[id],querySelectorAll:()=>[],body:{classList:{add(){}}}};
const snapshot = require('node:child_process').execFileSync('python3',['-c','import json; from swarm.mission_control_demo import mission_control_demo_snapshot; print(json.dumps(mission_control_demo_snapshot()))'],{encoding:'utf8',env:{...process.env,PYTHONPATH:'.'}});
const valid = JSON.parse(snapshot);

assert.equal(validateSnapshot(valid), valid);
for (const changed of [
  {schema_version:2}, {data_mode:'LIVE'}, {safety:{...valid.safety,mutation_allowed:true}},
  {safety:{...valid.safety,deployment:'ENABLED'}}, {safety:{...valid.safety,kill_switch:'CLEARED'}},
  {posture:{...valid.posture,dimensions:[{label:'bad',value:101}]}}, {incident:{...valid.incident,detections:null}}, {ai_security:{...valid.ai_security,timeline:null}}, {harness:{...valid.harness,tools:null}}, {models:null}, {mcp:null}, {evidence:{...valid.evidence,chronology:null}}, {governance:{...valid.governance,policy:null}}, {executive:{...valid.executive,outcomes:null}}, {demo_tour:null}
]) assert.throws(()=>validateSnapshot({...valid,...changed}));

const core={safety:{mode:'DRY_RUN',deployment:'DISABLED',kill_switch:'ENGAGED',autonomous_dry_run:'DISABLED'},workflow:{mode:'DRY_RUN',deployment:'DISABLED',kill_switch:'ENGAGED',read_only:true,state:'SUCCEEDED',next_action:'NONE',running_marker:false,stale_markers:false}};
assert.equal(validateCoreStatus(core),core);
for(const changed of [
  {safety:{...core.safety,mode:'LIVE'}},{safety:{...core.safety,deployment:'ENABLED'}},{safety:{...core.safety,kill_switch:'CLEARED'}},
  {workflow:{...core.workflow,read_only:false}},{workflow:{...core.workflow,deployment:'ENABLED'}},{workflow:{...core.workflow,kill_switch:'CLEARED'}},
  {workflow:{...core.workflow,state:null}},{workflow:{...core.workflow,running_marker:'false'}}
]) assert.throws(()=>validateCoreStatus({...core,...changed}));
const emptyHarness={schema_version:1,data_mode:'EMPTY',data_label:'NO CANONICAL HARNESS ACTIVITY',view:null,safety:{mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED'}};
assert.equal(validateHarnessActivity(emptyHarness),emptyHarness);
assert.throws(()=>validateHarnessActivity({...emptyHarness,safety:{...emptyHarness.safety,mutation_allowed:true}}));
assert.throws(()=>validateHarnessActivity({...emptyHarness,data_mode:'CANONICAL'}));
assert.throws(()=>validateHarnessActivity({...emptyHarness,data_mode:'UNAVAILABLE',view:{}}));

const emptyIncident={schema_version:1,data_mode:'EMPTY',data_label:'NO CANONICAL INCIDENT ACTIVITY',view:null,safety:{mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',response_executed:false}};
const canonicalIncident={...emptyIncident,data_mode:'CANONICAL',data_label:'CANONICAL READ-ONLY INCIDENT ACTIVITY',view:{tenant_id:'tenant-a',primary_incident_id:'incident-1',mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',response_executed:false,incidents:[{incident_id:'incident-1',tenant_id:'tenant-a',title:'Canonical incident',status:'OPEN',severity:'HIGH',affected_refs:['asset/a'],normalized_event_refs:['event/a'],evidence_refs:['evidence/a'],mode:'DRY_RUN',action:'RECORD_ONLY'},{incident_id:'incident-2',tenant_id:'tenant-a',title:'Related incident',status:'OPEN',severity:'HIGH',affected_refs:['asset/a'],normalized_event_refs:['event/a'],evidence_refs:['evidence/b'],mode:'DRY_RUN',action:'RECORD_ONLY'}],attack_story:{tenant_id:'tenant-a',severity:'HIGH'},timeline:{tenant_id:'tenant-a',incident_id:'incident-1',entries:[{occurred_at_epoch:100,entry_type:'DETECTION',source_ref:'event/a'}]},response_proposal:{tenant_id:'tenant-a',incident_id:'incident-1',action:'PROPOSE_ONLY',steps:[{action_class:'ISOLATE_ENDPOINT',resource_ref:'asset/a',checkpoint_ref:'checkpoint/a',action_ticket_ref:'ticket/a'}]}}};
assert.equal(validateIncidentActivity(emptyIncident),emptyIncident);
assert.equal(validateIncidentActivity(canonicalIncident),canonicalIncident);
assert.equal(validateIncidentActivity({...emptyIncident,data_mode:'UNAVAILABLE',data_label:'CANONICAL INCIDENT ACTIVITY UNAVAILABLE'}).data_mode,'UNAVAILABLE');
assert.equal(validateIncidentActivity({...canonicalIncident,view:{...canonicalIncident.view,timeline:{...canonicalIncident.view.timeline,entries:Array.from({length:128},(_,index)=>({occurred_at_epoch:100+index,entry_type:'DETECTION',source_ref:`event/${index}`}))}}}).view.timeline.entries.length,128);
assert.equal(validateIncidentActivity({...canonicalIncident,view:{...canonicalIncident.view,response_proposal:{...canonicalIncident.view.response_proposal,steps:Array.from({length:32},(_,index)=>({action_class:'ISOLATE_ENDPOINT',resource_ref:`asset/${index}`}))}}}).view.response_proposal.steps.length,32);
assert.throws(()=>validateIncidentActivity({...emptyIncident,safety:{...emptyIncident.safety,response_executed:true}}));
assert.throws(()=>validateIncidentActivity({...emptyIncident,data_mode:'UNAVAILABLE',view:{}}));
assert.throws(()=>validateIncidentActivity({...canonicalIncident,view:{...canonicalIncident.view,tenant_id:'tenant-b'}}));
assert.throws(()=>validateIncidentActivity({...canonicalIncident,view:{...canonicalIncident.view,timeline:{...canonicalIncident.view.timeline,entries:[]}}}));
assert.throws(()=>validateIncidentActivity({...canonicalIncident,view:{...canonicalIncident.view,response_proposal:{...canonicalIncident.view.response_proposal,steps:[{action_class:null,resource_ref:'asset/a'}]}}}));

const emptyEvidence={schema_version:1,data_mode:'EMPTY',data_label:'NO CANONICAL EVIDENCE ACTIVITY',view:null,safety:{mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',signing_performed:false}};
const canonicalEvidence={...emptyEvidence,data_mode:'CANONICAL',data_label:'CANONICAL FW-EVID · DIGEST AND CHAIN VALIDATED',view:{tenant_id:'tenant-a',record_count:1,head_record_sha256:'b'.repeat(64),chain_status:'DIGEST_AND_CHAIN_VALIDATED',signature_status:'NOT_PRESENT',verification_scope:'LOCAL_CANONICAL_ENVELOPE_AND_CHAIN',mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',signing_performed:false,records:[{position:1,evidence_id:'fw-evid/tenant-a/task/0001',occurred_at:'2026-09-12T18:00:00Z',event_type:'task.completed',actor_ref:'fw-id/tenant-a/worker',subject_ref:'fw-task/tenant-a/fw-ux-009',classification:'INTERNAL',payload_schema_id:'fw-schema/harness/task-v1',payload_sha256:'a'.repeat(64),record_sha256:'b'.repeat(64),previous_record_sha256:null,correlation_id:'fw-corr/tenant-a/fw-ux-009',evidence_references:[]}]}};
assert.equal(validateEvidenceActivity(emptyEvidence),emptyEvidence);
assert.equal(validateEvidenceActivity({...emptyEvidence,data_mode:'UNAVAILABLE',data_label:'CANONICAL EVIDENCE ACTIVITY UNAVAILABLE'}).data_mode,'UNAVAILABLE');
assert.equal(validateEvidenceActivity(canonicalEvidence),canonicalEvidence);
assert.throws(()=>validateEvidenceActivity({...emptyEvidence,safety:{...emptyEvidence.safety,signing_performed:true}}));
assert.throws(()=>validateEvidenceActivity({...canonicalEvidence,view:{...canonicalEvidence.view,signature_status:'VALID'}}));
assert.throws(()=>validateEvidenceActivity({...canonicalEvidence,view:{...canonicalEvidence.view,tenant_id:'tenant-b'}}));
assert.throws(()=>validateEvidenceActivity({...canonicalEvidence,view:{...canonicalEvidence.view,records:[{...canonicalEvidence.view.records[0],previous_record_sha256:'c'.repeat(64)}]}}));

const emptyPolicy={schema_version:1,data_mode:'EMPTY',data_label:'NO CANONICAL POLICY OR TICKET ACTIVITY',view:null,safety:{mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',ticket_consumed:false}};
const canonicalPolicy={...emptyPolicy,data_mode:'CANONICAL',data_label:'CANONICAL READ-ONLY POLICY AND ACTION TICKET',view:{tenant_id:'tenant-a',subject_agent_id:'agent-a',capability:'endpoint.isolate.request',resource:'endpoint-1',action_class:'ISOLATE_ENDPOINT',policy_version:'policy-v1',decision:'ALLOW',reason:'RULE_MATCH',observed_at_epoch:150,mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',ticket_consumed:false,ticket:{ticket_id:'ticket-1',tenant_id:'tenant-a',subject_agent_id:'agent-a',lease_id:'lease-1',capability:'endpoint.isolate.request',resource:'endpoint-1',action_class:'ISOLATE_ENDPOINT',issued_by:'root-operator',approval_reference:'approval-1',policy_version:'policy-v1',issued_at:100,expires_at:200,key_reference:'fw-keys/ticket',signature_status:'PRESENT_NOT_VERIFIED',usage_status:'UNCONSUMED'}}};
assert.equal(validatePolicyTicketActivity(emptyPolicy),emptyPolicy);
assert.equal(validatePolicyTicketActivity(canonicalPolicy),canonicalPolicy);
assert.equal(validatePolicyTicketActivity({...canonicalPolicy,view:{...canonicalPolicy.view,decision:'DENY',ticket:null}}).view.decision,'DENY');
assert.throws(()=>validatePolicyTicketActivity({...emptyPolicy,safety:{...emptyPolicy.safety,ticket_consumed:true}}));
assert.throws(()=>validatePolicyTicketActivity({...canonicalPolicy,view:{...canonicalPolicy.view,tenant_id:'tenant-b'}}));
assert.throws(()=>validatePolicyTicketActivity({...canonicalPolicy,view:{...canonicalPolicy.view,decision:'DENY'}}));

const emptyModelMCP={schema_version:1,data_mode:'EMPTY',data_label:'NO CANONICAL MODEL OR MCP ACTIVITY',view:null,safety:{mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',model_invoked:false,tool_executed:false}};
const canonicalModelMCP={...emptyModelMCP,data_mode:'CANONICAL',data_label:'CANONICAL READ-ONLY MODEL BROKER AND MCP ACTIVITY',view:{tenant_id:'tenant-a',gateway_health:'HEALTHY',gateway_kill_switch:'ENGAGED',mutation_allowed:false,deployment:'DISABLED',kill_switch:'ENGAGED',model_invoked:false,tool_executed:false,models:[{candidate_id:'model-one',provider:'provider-a',model_id:'model-a',environment:'local',assurance_tier:'T1',registry_evidence_reference:'fw-evid/model-one',approval_status:'APPROVED',availability:'AVAILABLE',invocation_authorized:false}],tools:[{tool:'repo.read',capability:'repo.read',trust_level:'TRUSTED_READ_ONLY',enabled:true,lease_status:'NOT_PRESENT',tool_executed:false}]}};
assert.equal(validateModelMCPActivity(emptyModelMCP),emptyModelMCP);
assert.equal(validateModelMCPActivity(canonicalModelMCP),canonicalModelMCP);
assert.throws(()=>validateModelMCPActivity({...emptyModelMCP,safety:{...emptyModelMCP.safety,model_invoked:true}}));
assert.throws(()=>validateModelMCPActivity({...canonicalModelMCP,view:{...canonicalModelMCP.view,gateway_kill_switch:'CLEARED'}}));
assert.throws(()=>validateModelMCPActivity({...canonicalModelMCP,view:{...canonicalModelMCP.view,models:[canonicalModelMCP.view.models[0],canonicalModelMCP.view.models[0]]}}));
renderModelMCPActivity(canonicalModelMCP);
assert.equal(elements['model-table'].innerHTML.includes('NOT INVOKED'),true);
assert.equal(elements['mcp-grid'].innerHTML.includes('NOT EXECUTED'),true);
renderModelMCPActivity({...canonicalModelMCP,view:{...canonicalModelMCP.view,tools:[{...canonicalModelMCP.view.tools[0],tool:'<script>bad</script>'}]}});
assert.equal(elements['mcp-grid'].innerHTML.includes('&lt;script&gt;'),true);
assert.equal(elements['mcp-grid'].innerHTML.includes('<script>'),false);

assert.equal(escapeHtml('<script>"x" & y</script>'),'&lt;script&gt;&quot;x&quot; &amp; y&lt;/script&gt;');
renderStory('attack-story',[],false); assert.equal(elements['attack-story'].innerHTML,'');
renderStory('attack-story',[{time:'<1>',domain:'A&B',title:'"unsafe"',state:"x'y"}],false);
assert.ok(!elements['attack-story'].innerHTML.includes('<1>'));
assert.ok(elements['attack-story'].innerHTML.includes('&lt;1&gt;'));

valid.incident.title='<img src=x onerror=alert(1)>';
valid.assets[0].detail='<script>alert(1)</script>';
valid.executive.outcomes[0].detail='<script>executive</script>'; valid.demo_tour[0].label='<svg onload=tour>'; valid.evidence.chronology[0].event='<img src=x onerror=y>'; valid.governance.policy.reason='<script>policy</script>'; valid.models[0].name='<svg onload=x>'; valid.mcp[0].tools[0]='<script>mcp</script>'; valid.ai_security.timeline[0].title='<svg onload=alert(1)>'; valid.ai_security.agent.tools[0]='<script>tool</script>'; valid.incident.detections[0].name='<script>bad</script>'; valid.incident.recovery.checkpoint='<svg onload=x>';
render(valid);
for (const id of ['incident-title','asset-grid','ai-events','aid-tools','incident-detections','evidence-chronology','model-table','mcp-grid','executive-outcomes','tour-map']) assert.ok(!elements[id].innerHTML.includes('<script>') && !elements[id].innerHTML.includes('<svg'));
showTour(0); assert.equal(elements['tour-label'].textContent,'<svg onload=tour>'); assert.equal(elements['demo-tour'].hidden,false);
assert.equal(elements['incident-title'].textContent,'<img src=x onerror=alert(1)>');
render(valid,core); assert.equal(elements.connection.textContent,'LOCAL CORE CONNECTED · DEMO SCENARIO'); assert.equal(elements.mode.textContent,'DRY_RUN');

async function testDualProviderClient(){
  const demo=JSON.parse(snapshot); const requested=[];
  const payload=url=>url==='/api/status'?core:url==='/api/harness-activity'?emptyHarness:url==='/api/incident-activity'?emptyIncident:url==='/api/canonical-evidence-activity'?emptyEvidence:url==='/api/policy-ticket-activity'?emptyPolicy:url==='/api/model-mcp-activity'?emptyModelMCP:demo;
  global.fetch=async url=>{requested.push(url);return {ok:true,json:async()=>payload(url)};};
  const result=await new MissionControlClient().snapshot();
  assert.deepEqual(requested,['/api/mission-control','/api/status','/api/harness-activity','/api/incident-activity','/api/canonical-evidence-activity','/api/policy-ticket-activity','/api/model-mcp-activity']);
  assert.equal(result.scenario.data_mode,'DEMO'); assert.equal(result.core.safety.mode,'DRY_RUN');
  assert.equal(result.harness.data_mode,'EMPTY'); assert.equal(result.incident.data_mode,'EMPTY'); assert.equal(result.evidence.data_mode,'EMPTY'); assert.equal(result.policy.data_mode,'EMPTY'); render(result.scenario,result.core,result.harness); renderIncidentActivity(result.incident); renderEvidenceActivity(result.evidence); renderPolicyTicketActivity(result.policy); assert.equal(elements['harness-live-state'].textContent,'NO CANONICAL HARNESS ACTIVITY'); assert.equal(elements['incident-live-state'].textContent,'NO CANONICAL INCIDENT ACTIVITY'); assert.equal(elements['evidence-live-state'].textContent,'NO CANONICAL EVIDENCE ACTIVITY'); assert.equal(elements['policy-live-state'].textContent,'NO CANONICAL POLICY OR TICKET ACTIVITY');
  render(result.scenario,result.core,result.harness); renderCanonicalIncident(canonicalIncident); assert.equal(elements['incident-title'].textContent,'Canonical incident'); assert.equal(elements['incident-actions'].innerHTML.includes('PROPOSE ONLY'),true); assert.equal(elements['recovery-execution'].textContent,'NOT EXECUTED');
  renderIncidentActivity({...emptyIncident,data_mode:'UNAVAILABLE',data_label:'CANONICAL INCIDENT ACTIVITY UNAVAILABLE'}); assert.equal(elements['incident-live-state'].textContent,'CANONICAL INCIDENT ACTIVITY UNAVAILABLE');
  renderCanonicalIncident({...canonicalIncident,view:{...canonicalIncident.view,response_proposal:{...canonicalIncident.view.response_proposal,steps:[]}}}); assert.equal(elements['recovery-checkpoint'].textContent,'NONE'); assert.equal(elements['incident-ticket'].textContent,'NONE');
  renderCanonicalIncident({...canonicalIncident,view:{...canonicalIncident.view,timeline:{...canonicalIncident.view.timeline,entries:[{occurred_at_epoch:100,entry_type:'DETECTION',source_ref:'<img src=x onerror=alert(1)>'}]}}}); assert.equal(elements['attack-story'].innerHTML.includes('&lt;img'),true); assert.equal(elements['attack-story'].innerHTML.includes('<img'),false);
  renderEvidenceActivity(canonicalEvidence); assert.equal(elements['vault-tenant'].textContent,'tenant-a'); assert.equal(elements['vault-chain'].textContent.includes('SIGNATURE NOT_PRESENT'),true); assert.equal(elements['evidence-verification-state'].textContent,'DIGEST / CHAIN VERIFIED · NO SIGNATURE'); assert.equal(elements['evidence-record-state'].textContent,'CANONICAL RECORDS'); assert.equal(elements['evidence-chronology'].innerHTML.includes('task.completed'),true);
  renderEvidenceActivity({...canonicalEvidence,view:{...canonicalEvidence.view,records:[{...canonicalEvidence.view.records[0],occurred_at:'<img src=x onerror=alert(1)>'}]}}); assert.equal(elements['evidence-chronology'].innerHTML.includes('&lt;img'),true); assert.equal(elements['evidence-chronology'].innerHTML.includes('<img'),false);
  renderPolicyTicketActivity(canonicalPolicy); assert.equal(elements['policy-decision'].textContent,'ALLOW'); assert.equal(elements['ticket-signature'].textContent,'PRESENT_NOT_VERIFIED'); assert.equal(elements['ticket-status'].textContent,'UNCONSUMED');
  global.fetch=async url=>({ok:true,json:async()=>url==='/api/status'?{...core,safety:{...core.safety,kill_switch:'CLEARED'}}:payload(url)});
  const degraded=await new MissionControlClient().snapshot(); assert.equal(degraded.core,null); render(degraded.scenario,degraded.core);
  assert.equal(elements.connection.textContent,'LOCAL CORE UNAVAILABLE · DEMO SCENARIO');
  global.fetch=async url=>({ok:url!=='/api/status',json:async()=>payload(url)});
  assert.equal((await new MissionControlClient().snapshot()).core,null);
  global.fetch=async url=>url==='/api/canonical-evidence-activity'?Promise.reject(new Error('offline')):{ok:true,json:async()=>payload(url)};
  const evidenceUnavailable=await new MissionControlClient().snapshot(); assert.equal(evidenceUnavailable.evidence,null); renderEvidenceActivity(evidenceUnavailable.evidence); assert.equal(elements['evidence-live-state'].textContent,'CANONICAL EVIDENCE ACTIVITY UNAVAILABLE');
  global.fetch=async url=>({ok:url!=='/api/mission-control',json:async()=>payload(url)});
  await assert.rejects(()=>new MissionControlClient().snapshot(),/Mission Control demo provider unavailable/);
}
testDualProviderClient().then(()=>console.log('frontend contract and rendering boundaries passed')).catch(error=>{console.error(error);process.exitCode=1;});
