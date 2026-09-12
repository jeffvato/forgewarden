# ForgeWarden Mission Control

ForgeWarden includes a local-only Mission Control interface. It is a control plane
for safety visibility and guardrail-checked task planning; it does not invoke a
model, clear the kill switch, deploy, restart services, or access remote
systems.

## Run locally

```bash
cd /home/jeff/hermes-swarm-phase1
PYTHONPATH=. python3 -m swarm.console --host 127.0.0.1 --port 8787
```

Open `http://127.0.0.1:8787/`. The console displays workflow safety state,
specialist model lanes, and a plan-only dispatch form.

Profiles live in `config/llm-profiles.json`. Each profile declares its role,
allowed task types, forbidden actions, and whether human approval is required.
The registry rejects profiles that weaken global restrictions. The dispatch
endpoint returns `PLAN_ONLY` and `execution_started: false`; execution adapters
must be added separately and must preserve these checks.

Initial lanes are Codex/Forge for local implementation, Gemini/Sentinel for
read-only review, Claude/Ledger for evidence and documentation audit, and
Fable/Compass for read-only analysis.

The console binds to loopback by default. Do not expose it publicly without a
separately reviewed authentication and deployment design.

## AI Security / Agent Defense

Mission Control must include a sanitized FW-AID projection of running agents,
provider/model, task and purpose, current authority, offered tools, MCP
connections, risk, anomalies, denied actions, egress and secret-access
attempts, containment status or inert proposal, related endpoint/identity
alerts, unified attack story, Evidence references, and kill-switch state.

The view consumes canonical FW-ID, FW-KEYS, FW-HARNESS, MCP Gateway,
NormalizedEventStore, FW-SOC, FW-EVID, FW-REC, and policy state. It neither
owns that state nor executes response. Prompt text, retrieved content,
credentials, tokens, and sensitive command arguments are excluded by default.


## AI Security read-only projection

Mission Control consumes `project_ai_security` for sanitized tenant-bound agent,
model, task, scoped authority-reference, anomaly, denial, threat, FW-SOC story,
Evidence, containment-proposal, and kill-switch visibility. Canonical and demo
views carry explicit labels. The projection is immutable and exposes no approval,
revocation, isolation, execution, policy, or kill-switch callback.
