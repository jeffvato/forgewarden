# FW-AID — AI Intrusion & Agent Defense

Status: permanent ForgeWarden Core requirement family  
Architecture decision: D-025  
Initial milestone: FW-AID-001

## Security objective and invariant

FW-AID detects, correlates, and coordinates deterministic defense against
compromised, manipulated, malfunctioning, or unexpectedly capable AI
workloads. It covers agents, LLM applications, coding workers, reviewers, MCP
clients and servers, tool calls, retrieval, generated commands, autonomous
workflows, and agent-to-agent communication.

> AI provides intelligence. ForgeWarden provides authority.

Every model output, prompt, tool call, MCP interaction, retrieved document,
webpage, attachment, API response, and generated command is untrusted input.
A model cannot decide or change its authority, containment, identity,
permissions, credentials, policy exemptions, deployment access, acceptance
criteria, Evidence, or kill-switch state. Detection is defense in depth;
filesystem, process, network, identity, secret, MCP, lease, ticket, policy, and
kill-switch enforcement remains effective when detection misses an attack.

FW-AID is integrated Core architecture, not a side project and not a second
detector, event store, policy engine, evidence store, recovery engine, or
orchestrator.

## Canonical integration and existing coverage

| Concern | Canonical component reused | Existing contribution | FW-AID gap |
|---|---|---|---|
| Traditional malware | `swarm.anti_malware`, TrustedSignatureCatalog, FW-AV | Offline signatures, YARA-compatible evaluation, warn/quarantine proposals | Correlate malware facts with agent identity, task, tool, process, and egress facts. |
| Endpoint/EDR | `swarm.endpoint_fixtures`, `swarm.android_fixtures`, `NormalizedEventStore` | Tenant-bound process/file/network fixture normalization and recovery-safe batches | Add AI workload attribution and safe future MicroSensor adapter fields. |
| Identity | `swarm.identity` | Immutable tenant/owner/provider/worker identity lifecycle and revocation | Bind every AI security event to exact active actor, model, session, task, and initiating user references. |
| Secrets | `swarm.keys`, `swarm.harness_credentials` | Opaque non-exportable handles and metadata lifecycle | Emit denied secret-discovery/use signals without storing secret values. |
| Agent authority | `swarm.asoc`, Action Tickets, approvals | Leases, budgets, blast radius, replay denial, deterministic authorization | Classify privilege expansion, coordination, and mission deviation against exact granted scope. |
| Model governance | `swarm.model_broker`, `swarm.harness_models` | Exact provider/model/role approval and no silent substitution | Detect model/deployment/version mismatch and anomalous call frequency. |
| MCP | `swarm.mcp_gateway` | Tenant/capability/tool allow-listing, replay and kill-switch denial | Normalize denied and anomalous MCP capability/tool/server activity. |
| Browser/email/retrieval | `swarm.browser_email` | Caller-supplied untrusted navigation, message, link and prompt-injection signals | Bind retrieval provenance and injection indicators to downstream tool behavior. |
| Deterministic policy | `swarm.policy_gate`, FW-ROOT/Z3 boundary | External policy decisions and immutable prohibitions | Define FW-AID signal inputs and containment action classes; AI scores never authorize action. |
| Evidence | `swarm.core.AuditLog`, `swarm.harness_evidence`, FW-EVID | Evidence-first lifecycle facts and exact review/checkpoint attribution | Add canonical AI incident chronology and privacy-safe context hashes. |
| Correlation/cases | `swarm.soc` | Incident projections, attack stories, timelines, inert playbooks | Add AI-specific signals to the same attack story rather than separate alerts. |
| Recovery | `swarm.harness_recovery`, FW-REC | Bounded Monitor → Repair → Review and safe checkpoint reconciliation | Bind containment proposals to verified checkpoint, rollback, and recovery proof. |
| Mission Control | `swarm.mission_control`, local console | Read-only canonical harness projection | Add sanitized AI Security views without state or response authority. |
| Engineering harness | FW-HARNESS | Identity, task, context, tools, paths, Git, validation, review, budgets, denied actions | Make the development harness the first fixture-driven protected environment while keeping enforcement separate. |

No live sensor, hook, credential backend, network control, process control,
container control, identity provider, or containment executor is authorized by
this architecture milestone.

## Requirement register and incremental route

| ID | Requirement | Acceptance boundary |
|---|---|---|
| FW-AID-001 | Architecture, threat, ownership, and implementation inventory | This document and cross-document registry make FW-AID explicit and testable without runtime authority. |
| FW-AID-002 | Canonical AI workload telemetry envelope | Strict tenant-bound immutable caller-supplied metadata; bounded values, classifications, hashes, and references; no prompt/secret capture by default. |
| FW-AID-003 | Deterministic AI threat classification | Closed rules for the ten threat classes below; Evidence-first findings; no model self-assessment or action authority. |
| FW-AID-004 | ForgeWarden harness monitoring adapter | Attribute worker/reviewer, context hash, scoped tools/paths/Git, denials, budgets, and coordination using existing harness facts. |
| FW-AID-005 | Cross-domain correlation and attack stories | Compose FW-AID, AV, endpoint, identity, network, browser/email, MCP, and cloud facts through NormalizedEventStore and FW-SOC references. |
| FW-AID-006 | Deterministic containment proposal and policy contract | Map severity and confidence to Z3/policy action classes, leases, Action Tickets, approvals, blast radius, Evidence, and Recovery; initially PROPOSE_ONLY. |
| FW-AID-007 | Mission Control AI Security projection | Sanitized running-agent, authority, anomaly, denial, risk, containment-proposal, related-alert/incident, and Evidence views. |
| FW-AID-008 | Dedicated adversarial simulation suite | Safe fixture tests for every required attack, detection, fail-closed denial, Evidence ordering, and inert containment output. |
| FW-AID-009 | Endpoint/MicroSensor and platform adapter integration | Versioned AI attribution fields and endpoint correlation contracts; live collection requires separate authorization. |
| FW-AID-010 | Integrated AI intrusion lifecycle proof | One exact tenant-bound injection-to-behavior-to-correlation-to-policy-to-proposal-to-Evidence-to-recovery fixture path with all authority boundaries proven. |

Implementation follows the currently authorized Core sequence. FW-AID-001 is
the bounded architecture milestone. FW-AID-002 and later milestones become
eligible only when their dependencies and the active ordered Core work permit
them; no placeholder successor loop is created.

## Canonical AI telemetry contract

FW-AID-002 extends the canonical event schema using references and
classifications rather than raw content. `AIWorkloadSecurityEvent` and the
`NormalizedEventStore` AI admission path implement this fixture-only boundary. The minimum logical fields are:

- event ID, schema version, tenant, timestamp, source, data classification;
- agent identity, model registry identity/provider/version, session identity,
  initiating user identity, task/workflow ID, and declared purpose;
- capability lease and Action Ticket references, policy/approval version,
  tools offered, tool invoked, MCP server/capability, and target resource;
- filesystem operation/path classification, process/parent/command hash,
  network destination class, DNS fact, API/cloud/container/Kubernetes action;
- credential/secret request class and opaque FW-KEYS handle reference when
  policy allows, never secret material;
- browser/email/retrieval source reference and prompt-injection indicators;
- denied action, policy violation, sandbox/boundary fact, agent coordination
  relationship, resource usage, model/tool call counts, and control-tamper fact;
- evidence, normalized-event, incident, checkpoint, and recovery references.

Raw prompts, retrieved content, source, credentials, tokens, private keys,
browser secrets, and sensitive command arguments are excluded by default.
Where investigation requires content, FW-EVID data classification, minimization,
retention, access, and cryptographic integrity rules govern it. Context and
commands should use keyed/signed references or hashes when sufficient.

## Threat model and deterministic detection classes

The threat model assumes an attacker can control prompts, documents, webpages,
retrieval results, MCP responses, tool output, model output, or an AI workload.
It also assumes a model may be deceptive, confused, compromised, or simply more
capable than expected.

1. **AID-ESCAPE — Sandbox / boundary escape:** host/namespace/device/path
   escape, prohibited runtime access, container exploit indicators, or
   destination-zone violations.
2. **AID-EGRESS — Unexpected network egress:** denied Internet access,
   unexpected DNS/domain/IP, tunneling, probing, C2, or exfiltration patterns.
3. **AID-SECRETS — Credential / secret discovery:** access to SSH, cloud,
   browser, service-account, Kubernetes, certificate, API-token, or
   ForgeWarden root/signing material.
4. **AID-PRIVILEGE — Privilege expansion:** permission probing, repeated
   denials, self-authorization, role/capability/lease/ticket expansion, or
   administrator/root acquisition.
5. **AID-LATERAL — Lateral movement:** access toward unrelated endpoints,
   repositories, services, clouds, databases, tenants, identities, or agents.
   Cross-tenant movement is always critical input to policy.
6. **AID-INJECTION — Prompt injection:** direct/indirect/hidden instructions,
   poisoned retrieval, tool manipulation, secret requests, system-constraint
   override, or redirection to attacker resources.
7. **AID-MISSION — Compromised agent behavior:** material deviation from the
   exact role, task, tools, data, paths, destinations, process tree, or purpose.
8. **AID-COORDINATION — Unapproved agent coordination:** communication,
   shared state, work assignment, covert channel, delegation, or capability
   transfer outside the deterministic orchestrator.
9. **AID-EVALUATION — Evaluation / goal manipulation:** tests, benchmarks,
   scores, acceptance criteria, reviewer inputs, logs, or failure evidence
   altered to redefine or conceal success.
10. **AID-TAMPER — Security-control tampering:** attempts against sensors,
    AV/EDR, policy, logging, Evidence, monitoring, network restrictions,
    incident history, or kill-switch controls.

`DeterministicAIThreatClassifier` now applies closed fact allowlists for all ten classes and emits Evidence-first immutable advisory findings. Detection rules consume canonical facts. They do not execute generated
commands, inspect live hosts, or trust model explanations. Baseline deviation
is a signal rather than proof of compromise.

## Behavioral baselines and correlation

Per tenant, identity, role, model, and task class, future baselines cover normal
tools, MCP servers, API calls, directories, destinations, commands/process
trees, privilege, model/provider, task types, duration, token/request volume,
data classifications, initiating users, working periods, and approved
agent-to-agent relationships. Baselines are versioned, bounded, explainable,
and excluded from authorization decisions except as policy inputs.

Correlation occurs through canonical normalized-event and FW-SOC references.
Examples include:

- agent mission anomaly + credential discovery + PowerShell child process +
  new egress + identity risk;
- injection indicator + sensitive-file request + MCP tool call + external POST;
- privilege probing + EDR stop attempt + audit deletion;
- malware match + AI-launched process + boundary denial;
- cross-tenant target + capability expansion + unusual coordination.

The result is one tenant-bound attack story with chronology and Evidence
references, not duplicate event stores or disconnected alerts.
`AICrossDomainCorrelator` now requires ordered unique facts from at least three
domains including Endpoint, revalidates the exact AI event/finding binding, and
uses canonical FW-SOC incident and attack-story projections.

## Deterministic containment and kill switch

FW-AID may recommend containment. The canonical policy/Action Broker decides,
and existing owners perform any authorized action. Candidate actions include
tool/MCP/connector denial, lease or ticket revocation, token/session/identity
freeze, egress denial, process/container/workload/endpoint isolation, file
quarantine, evidence snapshot, forensic timeline, rollback/recovery, operator
notification, and dual-control escalation.

During the current DRY_RUN phase FW-AID outputs only findings and inert
containment proposals. It cannot revoke, terminate, isolate, quarantine,
delete, restore, or alter a control. Later execution requires an exact policy
decision, active narrow capability, single-use Action Ticket, approval class,
blast-radius check, canonical Evidence, checkpoint/rollback, and recovery
validation. An agent never lifts its own containment.

The kill switch is enforced outside the AI layer. Engagement denies new
mutating work, checkpoints safe interruption, and emits Evidence. Models may
recommend engagement but cannot clear, bypass, alter, or self-restore after it.

## Evidence and Mission Control

FW-EVID preserves chronology for actor/model/task/session references, context
hash, leases/tickets, tool/MCP/API/filesystem/process/network/identity facts,
denials, policy decisions, containment proposals/actions, approvals, recovery,
timestamps, affected resources, and related canonical event/incident IDs.
Evidence is append-only and privacy-minimized; agent output cannot edit it.

Mission Control's **AI Security / Agent Defense** view must show running agents,
provider/model, task/purpose, current authority, tools/MCP connections, risk,
anomalies, denied actions, egress and secret-access attempts, containment
status/proposals, related endpoint/identity alerts, attack story, Evidence
references, and kill-switch state. It is a projection of canonical state and
cannot authorize or execute response.

## Harness protection and separation of duties

`HarnessAIDMonitorAdapter` now makes FW-HARNESS the first fixture-driven protected environment by converting validated lifecycle denials and attempts into privacy-minimized canonical telemetry through a separately owned `NormalizedEventStore`. FW-HARNESS is the first protected environment. Caller-supplied harness facts
cover Codex, reviewers, future approved specialists, identity/model, task,
context hash, offered/invoked tools, allowed/changed paths, Git scope,
validation/review outcomes, denials, budgets, provider calls, coordination, and
attempts to manipulate tests, policy, Evidence, or acceptance.

The harness controller cannot control the FW-AID enforcement state protecting
it. FW-AID cannot control harness Git or acceptance. Both consume FW-ROOT,
FW-ID, FW-KEYS, FW-EVID, FW-REC, policy, tickets, and kill-switch interfaces.

## Adversarial validation strategy

FW-AID-008 uses inert fixtures for prompt injection, poisoned documents,
malicious webpages, credential discovery, secret exfiltration, unauthorized Internet access, lateral movement, container escape, privilege escalation,
unauthorized MCP, abnormal shell, EDR tampering, log deletion, unapproved
coordination, test manipulation, policy bypass, and self-expansion.

Every scenario verifies normalization, detection, correlation, policy input,
inert containment proposal, Evidence-before-return, tenant isolation, bounded
resources, replay denial, malformed-input denial, kill-switch behavior, and
absence of real filesystem/process/network/credential/containment effects.
