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


## Incident detail and unified attack story

The deterministic demo provider supplies one reusable incident contract containing affected entities, detections, cross-domain chronology, simulated response actions, recovery posture, Action Ticket reference, and Evidence preview. The incident route renders that contract as a coherent investigation view and repeats the DEMO/SIMULATED and not-cryptographically-verified boundaries. It remains read-only and backend-disconnected.


### FW-UX-003 assurance workspaces

The Demo Mode AI Intrusion Defense route presents a single protected agent, deterministic risk score, scoped identity/task/session/lease bindings, approved tools, MCP denial, policy-only containment proposal, related incident, Evidence references, and a chronological allowed-to-denied attack narrative. All values come from the centralized `DEMO-AI-RANSOM-001` provider and remain explicitly simulated.

The AI Harness route explains the same incident through the governed execution lifecycle: requesting FW-ID and tenant, deterministic T3 routing rationale, Approved Model Registry result, narrow lease and tools, calls/token/time/diff budgets, validation, independent read-only review, exact demo artifact, and policy-controlled escalation. These views expose no mutation callback. They do not invoke a model, monitor a live agent, execute containment, verify cryptography, or connect to a production backend.


## FW-UX-003 assurance workspaces

The AI Intrusion Defense and AI Harness routes consume the same deterministic DEMO-AI-RANSOM-001 provider as Mission Control. The AI Defense workspace explains agent identity, scoped authority, tool and MCP context, anomaly chronology, policy denials, proposal-only containment, related incident, and Evidence references. The Harness workspace explains deterministic risk and model routing, requester and tenant binding, bounded lease, tools, capabilities, resource budgets, validation, independent review, exact demo artifact, and escalation history.

Mission Control also accepts an independent `/api/incident-activity` provider for existing canonical FW-SOC dry-run lifecycle projections. The provider revalidates tenant, chronology, incident/story/playbook bindings, safety state, reference bounds, dependency order, and secret-bearing text before returning `CANONICAL`, `EMPTY`, or `UNAVAILABLE`. Canonical incident data can replace the simulated incident panel without changing the centralized Demo Provider. Response steps remain visibly `PROPOSE ONLY`; the endpoint exposes no case mutation, response, recovery, approval, or deployment callback.

Both routes are read-only product projections. Every value is simulated and visibly labeled; no live model, telemetry, approval, containment, recovery, deployment, network, credential, or response integration is present.


## FW-UX-004 governance assurance workspaces

The Evidence Vault, Policy and Action Ticket, Model Broker, and MCP Control routes consume the centralized deterministic demo provider. Evidence displays bounded chronology and visibly simulated hashes and chain status. Policy explains the deterministic denial, scope, lease, blast radius, and required authority. The Action Ticket remains authorized but explicitly not executed, with a simulated unverified signature. Model Broker displays approval, assurance, classification, availability, latency, and cost posture without invoking a provider. MCP Control displays registered demo tools, trust, agent and lease scope, denials, security state, and the engaged kill switch.

These are responsive read-only product views. They provide no callbacks for approval, ticket issuance, policy mutation, model activation, MCP connection, Evidence verification or mutation, containment, recovery, deployment, or response. Production adapters remain disconnected.


## FW-UX-005 executive showcase

The Executive Security Posture route summarizes protection outcomes, the largest current risk, required operator attention, AI control, and recovery readiness in plain language. A deterministic six-step guided presentation navigates the existing DEMO-AI-RANSOM-001 views in a repeatable order. It changes only local view selection; it does not modify provider or Core state.

The demo banner, simulated decision and verification labels, disconnected-backend state, DRY_RUN, disabled deployment, and engaged kill switch remain visible. Guided controls are keyboard buttons with explicit labels, and reduced-motion preferences disable animation and transition behavior.

## Local Core status integration

Mission Control now obtains its safety strip from the existing loopback-only
`/api/status` Core endpoint while the showcase views continue to use the
centralized `DEMO-AI-RANSOM-001` provider. The client validates both sources
independently and labels the combined state `LOCAL CORE CONNECTED · DEMO
SCENARIO`; demo incident, asset, Evidence, policy, model, MCP, and response data
remain simulated.

The live status contract is read-only and must report `DRY_RUN`, deployment
`DISABLED`, kill switch `ENGAGED`, and a read-only workflow. Any missing,
malformed, or weaker state is discarded and labeled `LOCAL CORE UNAVAILABLE`;
the separately validated Demo Provider remains available without presenting the
rejected Core state as live. A Demo Provider failure still rejects the scenario
instead of presenting incomplete simulated data. This first integration adds no remote API,
authentication, mutation callback, execution, containment, recovery, or
deployment authority.

## Canonical Harness activity provider

The loopback console exposes `/api/harness-activity` as the read-only adapter for
the existing immutable `MissionControlView`. A trusted Harness controller may
inject its already validated projection; the adapter revalidates tenant, queue,
dependencies, current and next task, exact commit, bounded visible text, safety
state, and secret exclusion before serialization. It returns `CANONICAL`,
`EMPTY`, or `UNAVAILABLE` and never fabricates activity when no controller view
is attached.

The AI Harness screen retains its deterministic demo workflow and displays the
canonical provider state separately. A malformed or unavailable Harness view is
discarded without contaminating Demo Mode. The provider exposes no controller,
scheduler, Git, approval, review, model, credential, recovery, response, or
deployment callback.

## Canonical Evidence activity provider

The independent `/api/canonical-evidence-activity` endpoint accepts only
already-admitted immutable FW-EVID records. It recomputes each envelope digest
and previous-record link, enforces one tenant and bounded reference metadata,
and exposes no raw payload. Mission Control labels local digest and chain
validation separately from signature status. The canonical envelope currently
contains no signature field, so the view reports `SIGNATURE NOT_PRESENT`
instead of implying that cryptographic signing occurred.

Missing providers return `EMPTY`; rejected or unavailable providers return
`UNAVAILABLE` without replacing deterministic Demo data. The console receives
no Evidence append, sign, key, policy, approval, export, repair, or deletion
callback, and DRY_RUN, disabled deployment, and the engaged kill switch remain
mandatory.

## Canonical policy and Action Ticket provider

The `/api/policy-ticket-activity` endpoint projects one existing deterministic
`PolicyContext` and `PolicyDecision` with its exactly bound `ActionTicket` when
the decision allows work. Denials cannot carry tickets. Allowed projections
require a signed, unconsumed, unexpired ticket whose tenant, subject, lease,
capability, resource, action class, and policy version match the decision
context. Signature material is never returned; the view reports only
`PRESENT_NOT_VERIFIED` because Mission Control does not own key access or
signature verification.

The provider returns explicit `CANONICAL`, `EMPTY`, and `UNAVAILABLE` states.
It exposes explanatory facts only and contains no policy evaluator, approval,
ticket issue/consume/revoke, key, response, recovery, or deployment callback.

## Canonical Model Broker and MCP activity provider

The `/api/model-mcp-activity` endpoint projects existing Approved Model
Registry candidates and MCP Gateway catalog entries for one tenant. It reports
provider/model identity, assurance tier, approval and availability, catalog
tool/capability trust, enabled state, and the canonical gateway safety state.
Mission Control labels model invocation and tool execution as not performed;
the canonical catalog has no lease binding, so it reports `NOT_PRESENT`
instead of inventing one.

The adapter returns explicit `CANONICAL`, `EMPTY`, and `UNAVAILABLE` states and
rejects malformed, cross-tenant, duplicate, secret-bearing, excessive, unhealthy,
deployment-enabled, or kill-switch-cleared projections. It exposes no routing,
fallback, registry mutation, model invocation, MCP discovery, lease creation,
tool execution, credentials, network transport, policy, approval, response,
recovery, or deployment callback.
