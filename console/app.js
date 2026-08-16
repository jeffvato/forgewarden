const $ = id => document.getElementById(id);
const views = { overview: 'Operations overview', jobs: 'Jobs & plans', evidence: 'Evidence posture', addons: 'Add-on platform', install: 'Install / update' };
let profiles = [];
const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));

function renderJobFeed(records) {
  const feed = $('job-feed');
  if (!records.length) { feed.innerHTML = '<span class="muted">No durable job records available.</span>'; return; }
  feed.innerHTML = records.slice(-6).reverse().map(record => `<div class="timeline-item"><span class="timeline-dot violet"></span><div><strong>${escapeHtml(record.event || record.state || 'RECORDED EVENT')}</strong><small>${escapeHtml(record.job_id || 'unbound job')} ${record.repair_commit ? `· commit ${escapeHtml(record.repair_commit.slice(0, 12))}` : ''}</small></div><time>${escapeHtml(record.timestamp || 'RECORDED')}</time></div>`).join('');
}

function renderAddons(snapshot) {
  const existing = $('addon-registry');
  if (existing) existing.remove();
  const card = document.querySelector('#view-addons .roadmap-card');
  if (!card) return;
  const entries = Object.values(snapshot.addons || {});
  const section = document.createElement('section');
  section.id = 'addon-registry';
  section.className = 'panel addon-registry';
  section.innerHTML = entries.length ? `<div class="panel-head"><span class="kicker">LOCAL REGISTRY</span><span class="badge">READ-ONLY</span></div>${entries.map(entry => {
    const manifest = entry.manifest || {};
    return `<article class="roadmap-line"><div><strong>${escapeHtml(manifest.name || manifest.id || 'Unknown add-on')}</strong><small>${escapeHtml(manifest.publisher || 'Unknown publisher')} · v${escapeHtml(manifest.version || '0.0.0')}</small></div><span class="roadmap-status">${escapeHtml(entry.status || 'UNKNOWN')}</span></article>`;
  }).join('')}` : '<div class="panel-head"><span class="kicker">LOCAL REGISTRY</span><span class="badge">READY</span></div><p class="muted">No add-ons installed. Local admission and lifecycle controls remain human-gated.</p>';
  card.insertAdjacentElement('afterend', section);
}

function showView(name) {
  document.querySelectorAll('.view').forEach(view => view.classList.toggle('active-view', view.id === `view-${name}`));
  document.querySelectorAll('.nav-item').forEach(item => {
    const active = item.dataset.view === name;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  $('view-title').textContent = views[name];
}

function populateModels(tasks) {
  $('task').innerHTML = tasks.map(task => `<option value="${task}">${task.replaceAll('_', ' ')}</option>`).join('');
  $('model').innerHTML = profiles.map(profile => `<option value="${profile.id}">${profile.name} — ${profile.role}</option>`).join('');
  $('models').innerHTML = profiles.map(profile => `<article class="model"><span class="dot ${profile.accent}"></span><div><h3>${profile.name}</h3><p>${profile.description}</p></div><span class="role">${profile.role}</span></article>`).join('');
  $('metric-models').textContent = String(profiles.length).padStart(2, '0');
}

async function load() {
  $('connection').setAttribute('aria-live', 'polite');
  $('result').setAttribute('aria-live', 'polite');
  try {
    const [models, status, addons, installation, audit, jobs, evidence, approvals] = await Promise.all([fetch('/api/models'), fetch('/api/status'), fetch('/api/addons'), fetch('/api/installation'), fetch('/api/audit'), fetch('/api/jobs'), fetch('/api/evidence'), fetch('/api/approvals')]);
    const modelData = await models.json(); const statusData = await status.json(); const addonData = await addons.json(); const installData = await installation.json(); const auditData = await audit.json(); const jobData = await jobs.json(); const evidenceData = await evidence.json(); const approvalData = await approvals.json(); profiles = modelData.profiles;
    $('connection').textContent = 'CONNECTED'; $('mode').textContent = statusData.safety.mode;
    $('dry-run').textContent = statusData.workflow.autonomous_dry_run; $('deployment').textContent = statusData.workflow.deployment;
    $('kill-switch').textContent = statusData.workflow.kill_switch; $('workflow-state').textContent = statusData.workflow.state;
    const addonCount = Object.keys(addonData.addons || {}).length;
    $('addon-state').textContent = addonCount ? `${addonCount} INSTALLED` : 'CATALOG READY';
    renderAddons(addonData);
    $('install-mode').textContent = installData.mode.replaceAll('_', ' ');
    $('install-promotion').textContent = installData.promotion.replaceAll('_', ' ');
    $('install-uninstall').textContent = installData.uninstall.replaceAll('_', ' ');
    $('metric-audit').textContent = `${auditData.events.length} EVENTS`;
    $('evidence-live-state').textContent = `${evidenceData.records.length} REVIEW RECORDS · ${jobData.records.length} JOB EVENTS · ${approvalData.records.length} APPROVAL RECORDS`;
    renderJobFeed(jobData.records);
    populateModels(modelData.tasks);
  } catch (error) { $('connection').textContent = 'OFFLINE'; document.querySelector('.connection').classList.add('offline'); }
}

document.querySelectorAll('[data-view]').forEach(item => item.addEventListener('click', () => showView(item.dataset.view)));
document.querySelectorAll('[data-view-target]').forEach(item => item.addEventListener('click', () => showView(item.dataset.viewTarget)));
$('dispatch-form').addEventListener('submit', async event => {
  event.preventDefault(); const result = $('result'); result.hidden = false; result.className = 'result'; result.textContent = 'VALIDATING GUARDRAILS…';
  try {
    const response = await fetch('/api/dispatch-plan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ model_id: $('model').value, task: $('task').value, objective: $('objective').value }) });
    const data = await response.json(); if (!response.ok) throw Error(data.error);
    result.textContent = `PLAN READY · ${data.model.name}\n\n${data.objective}\n\nMode: ${data.mode}\nExecution started: ${data.execution_started}\nHuman approval: ${data.guardrails.requires_human_approval}\nDeployment: ${data.guardrails.deployment}\n\n${data.next_step}`;
  } catch (error) { result.className = 'result error'; result.textContent = `BLOCKED BY GUARDRAIL\n\n${error.message}`; }
});
showView('overview'); load();
