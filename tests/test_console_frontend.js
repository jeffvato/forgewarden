'use strict';
const assert = require('node:assert/strict');

const ids = ['view-title','executive-headline','executive-summary','executive-risk','executive-attention','executive-recovery','executive-outcomes','tour-map','tour-step','tour-label','tour-detail','demo-tour','vault-tenant','evidence-chronology','policy-id','policy-engine','policy-subject','policy-resource','policy-action','policy-decision','policy-reason','policy-radius','policy-lease','policy-approval','ticket-id','ticket-operation','ticket-requester','ticket-authority','ticket-target','ticket-scope','ticket-expires','ticket-signature','ticket-status','model-table','mcp-grid','aid-agent','aid-score','aid-authority','aid-model','aid-task','aid-session','aid-lease','aid-ticket','aid-mcp','aid-proposal','aid-incident','aid-tools','aid-evidence','harness-detail-model','harness-detail-lease','harness-detail-review','harness-score','harness-identity','harness-tenant','harness-registry','harness-lease-scope','harness-validation','harness-reviewer','harness-commit','harness-capabilities','harness-tools','budget-calls','budget-tokens','budget-elapsed','budget-diff','harness-escalation','scenario-id','connection','mode','deployment','kill-switch','posture-score','posture-label','posture-trend','posture-bars','agent-count','denied-count','suspended-count','asset-grid','executive-metrics','incident-status','incident-id','incident-title','incident-summary','affected','attack-story','incident-timeline','detail-incident-id','detail-incident-title','detail-incident-summary','detail-confidence','detail-status','detail-affected','incident-detections','incident-actions','recovery-checkpoint','recovery-state','recovery-execution','incident-evidence','incident-ticket','incident-chain','harness-flow','harness-flow-large','harness-tier','harness-detail-tier','harness-model','harness-lease','harness-review','harness-task','harness-requester','routing-reason','harness-budget','actions','ai-risk','ai-events','evidence-records','evidence-bundle','chain-status','vault-bundle','vault-chain','vault-ticket'];
const {escapeHtml,validateSnapshot,validateCoreStatus,MissionControlClient,renderStory,render,showTour} = require('../console/app.js');
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
  global.fetch=async url=>{requested.push(url);return {ok:true,json:async()=>url==='/api/status'?core:demo};};
  const result=await new MissionControlClient().snapshot();
  assert.deepEqual(requested,['/api/mission-control','/api/status']);
  assert.equal(result.scenario.data_mode,'DEMO'); assert.equal(result.core.safety.mode,'DRY_RUN');
  global.fetch=async url=>({ok:true,json:async()=>url==='/api/status'?{...core,safety:{...core.safety,kill_switch:'CLEARED'}}:demo});
  const degraded=await new MissionControlClient().snapshot(); assert.equal(degraded.core,null); render(degraded.scenario,degraded.core);
  assert.equal(elements.connection.textContent,'LOCAL CORE UNAVAILABLE · DEMO SCENARIO');
  global.fetch=async url=>({ok:url!=='/api/status',json:async()=>demo});
  assert.equal((await new MissionControlClient().snapshot()).core,null);
  global.fetch=async url=>({ok:url!=='/api/mission-control',json:async()=>core});
  await assert.rejects(()=>new MissionControlClient().snapshot(),/Mission Control demo provider unavailable/);
}
testDualProviderClient().then(()=>console.log('frontend contract and rendering boundaries passed')).catch(error=>{console.error(error);process.exitCode=1;});
