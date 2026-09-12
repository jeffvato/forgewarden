'use strict';
const assert = require('node:assert/strict');

const ids = ['aid-agent','aid-score','aid-authority','aid-model','aid-task','aid-session','aid-lease','aid-ticket','aid-mcp','aid-proposal','aid-incident','aid-tools','aid-evidence','harness-detail-model','harness-detail-lease','harness-detail-review','harness-score','harness-identity','harness-tenant','harness-registry','harness-lease-scope','harness-validation','harness-reviewer','harness-commit','harness-capabilities','harness-tools','budget-calls','budget-tokens','budget-elapsed','budget-diff','harness-escalation','scenario-id','connection','mode','deployment','kill-switch','posture-score','posture-label','posture-trend','posture-bars','agent-count','denied-count','suspended-count','asset-grid','executive-metrics','incident-status','incident-id','incident-title','incident-summary','affected','attack-story','incident-timeline','detail-incident-id','detail-incident-title','detail-incident-summary','detail-confidence','detail-status','detail-affected','incident-detections','incident-actions','recovery-checkpoint','recovery-state','recovery-execution','incident-evidence','incident-ticket','incident-chain','harness-flow','harness-flow-large','harness-tier','harness-detail-tier','harness-model','harness-lease','harness-review','harness-task','harness-requester','routing-reason','harness-budget','actions','ai-risk','ai-events','evidence-records','evidence-bundle','chain-status','vault-bundle','vault-chain','vault-ticket'];
const {escapeHtml,validateSnapshot,renderStory,render} = require('../console/app.js');
const elements = Object.fromEntries(ids.map(id => [id, {textContent:'',innerHTML:''}]));
global.document = {getElementById:id=>elements[id],querySelectorAll:()=>[],body:{classList:{add(){}}}};
const snapshot = require('node:child_process').execFileSync('python3',['-c','import json; from swarm.mission_control_demo import mission_control_demo_snapshot; print(json.dumps(mission_control_demo_snapshot()))'],{encoding:'utf8',env:{...process.env,PYTHONPATH:'.'}});
const valid = JSON.parse(snapshot);

assert.equal(validateSnapshot(valid), valid);
for (const changed of [
  {schema_version:2}, {data_mode:'LIVE'}, {safety:{...valid.safety,mutation_allowed:true}},
  {safety:{...valid.safety,deployment:'ENABLED'}}, {safety:{...valid.safety,kill_switch:'CLEARED'}},
  {posture:{...valid.posture,dimensions:[{label:'bad',value:101}]}}, {incident:{...valid.incident,detections:null}}, {ai_security:{...valid.ai_security,timeline:null}}, {harness:{...valid.harness,tools:null}}
]) assert.throws(()=>validateSnapshot({...valid,...changed}));

assert.equal(escapeHtml('<script>"x" & y</script>'),'&lt;script&gt;&quot;x&quot; &amp; y&lt;/script&gt;');
renderStory('attack-story',[],false); assert.equal(elements['attack-story'].innerHTML,'');
renderStory('attack-story',[{time:'<1>',domain:'A&B',title:'"unsafe"',state:"x'y"}],false);
assert.ok(!elements['attack-story'].innerHTML.includes('<1>'));
assert.ok(elements['attack-story'].innerHTML.includes('&lt;1&gt;'));

valid.incident.title='<img src=x onerror=alert(1)>';
valid.assets[0].detail='<script>alert(1)</script>';
valid.ai_security.timeline[0].title='<svg onload=alert(1)>'; valid.ai_security.agent.tools[0]='<script>tool</script>'; valid.incident.detections[0].name='<script>bad</script>'; valid.incident.recovery.checkpoint='<svg onload=x>';
render(valid);
for (const id of ['incident-title','asset-grid','ai-events','aid-tools','incident-detections']) assert.ok(!elements[id].innerHTML.includes('<script>') && !elements[id].innerHTML.includes('<svg'));
assert.equal(elements['incident-title'].textContent,'<img src=x onerror=alert(1)>');
console.log('frontend contract and rendering boundaries passed');
