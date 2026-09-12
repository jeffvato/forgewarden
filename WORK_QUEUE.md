# ForgeWarden Work Queue

This file is the persistent executable queue for the active ForgeWarden phase. Codex must claim the highest-priority READY task, complete the full validation/review/repair cycle, checkpoint state, and immediately continue to the next READY task unless a defined stop condition applies.

## States

`BLOCKED` · `READY` · `IN_PROGRESS` · `REVIEW` · `REPAIR` · `VALIDATED` · `DONE`

## Queue rules

- Only approved active-phase work may be claimed.
- Codex is the sole application-code writer.
- Claude Code or the authorized AnythingLLM/Qwen fallback reviews exact candidate commits and returns findings only. Gemini is not required or enabled for the active workflow (D-020/D-021).
- A task is DONE only when acceptance criteria, deterministic validation, and review requirements are satisfied.
- Do not mark placeholders, interfaces without behavior, untested code, or documentation-only claims as complete.
- If one task is blocked, record the blocker and move to another independent READY task when safe.
- Keep tasks bounded enough to implement, test, review, repair, and checkpoint coherently.

## Active queue

Completion reconciliation: see `docs/completion-audit-2026-09-09.md`. Historical implementation is not new work. FWQ-0008 VALIDATED preserves a provenance caveat, not a request to rebuild or automatically repeat review. FWQ-0012–0016 are reconciled DONE from existing implementation and recorded proof.

### FWQ-0079 — Self-hosted canonical development harness activation
- Requirement: FW-HARNESS-014 self-hosted engineering execution
- State: DONE
- Priority: P0
- Dependencies: FWQ-0078
- Approval: Jeff explicitly authorized the accepted Core harness to control coding of remaining ForgeWarden jobs; execution remains local, bounded, DRY_RUN, kill-switch governed, and non-deploying.
- Description: Connect the canonical GovernedHarnessController to the existing real CodexTaskAdapter, deterministic validation, trusted GitCheckpointController, ExactReviewAdapter, persistent queue/recovery, canonical Evidence, and Mission Control path through one supported self-hosting runtime rather than a second orchestrator.
- Target path: swarm/harness_runtime.py
- Allowed paths: swarm/harness_runtime.py, swarm/harness_controller.py, swarm/cli.py, swarm/control_manifest.py, tests/test_harness_runtime.py, tests/test_harness_controller.py, tests/test_autonomous_loop.py, tests/test_task_selection.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_runtime.py tests/test_harness_controller.py tests/test_autonomous_loop.py tests/test_task_selection.py
- Acceptance criteria:
  - one supported runtime maps the authoritative selected queue task and canonical task/execution records to the existing Codex, validation, trusted Git, exact review, Evidence, recovery, and Mission Control owners without duplicating them;
  - the worker never receives Git, policy, approval, credential, kill-switch, deployment, or self-expansion authority, and only the trusted callback path can validate, commit, review, accept, checkpoint, or continue;
  - restart resumes the exact durable task/stage, completed work is never replayed, and the next dependency-complete authorized task advances automatically;
  - missing identity, key/model/authority admission, malformed worker output, path escape, dirty Git, validation failure, review failure/unavailability, Evidence failure, exhausted budget/retry, or engaged stop decision fails closed before later stages;
  - fixture-driven self-hosting proof covers the complete lifecycle without launching a live model, deploying, accessing credentials, or modifying repositories outside disposable test fixtures.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: activation uses existing local CLI capability only through deterministic mediation; it adds no arbitrary shell, product network transport, credential resolution, protected-branch merge, deployment, containment, remediation, or response authority.
- Completion evidence: exact repaired candidate `975750bf8bbb13c84da99c7c3cb37dfcb1b40207`; focused 109 passed; exact Claude Code job `phase2a-975750bf8bbb13c84da99c7c` returned APPROVE/LOW with no blockers or missing tests after closing every requested failure-path proof; full 1326 passed/1 skipped; Product Integrity fresh full 1326 passed/1 skipped, 4 Golden Paths, and all hard checks passed with YELLOW only for the existing `tzdata` dependency and Defined FW-COMP/FW-AID owners.

### FW-AID-001 — Core architecture, threat, and ownership inventory
- Requirement: FW-AID permanent Core foundation
- State: DONE
- Priority: P0
- Dependencies: D-025
- Approval: FW-AID architecture and incremental fixture-only implementation are explicitly activated by D-025.
- Description: Register FW-AID as a permanent Core family and define its canonical integrations, threat classes, AI telemetry contract, deterministic containment boundary, Mission Control visibility, harness protection, adversarial strategy, and incremental requirements without duplicating existing owners.
- Target path: docs/fw-aid-architecture.md
- Allowed paths: ROADMAP.md, DECISIONS.md, docs/fw-aid-architecture.md, docs/fw-endpoint-sensor-contract.md, docs/fw-harness-inventory.md, docs/management-console.md, docs/security-analysis.md, docs/fw-integrity-dependency-graph.md, docs/fw-integrity-functionality-map.md, swarm/integrity.py, tests/test_fw_aid_architecture.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_fw_aid_architecture.py tests/test_integrity.py tests/test_endpoint_design.py tests/test_mission_control.py
- Acceptance criteria:
  - FW-AID-001 through FW-AID-010 have stable, substantive requirements and dependencies on canonical AV, endpoint, Identity, FW-KEYS, MCP, model, event, policy, SOC, Evidence, Recovery, harness, test, and Mission Control owners;
  - all ten required AI threat classes, privacy-minimized telemetry, behavioral baselines, cross-domain correlation, deterministic policy/containment, kill switch, Evidence, Mission Control, harness separation, and adversarial simulations are explicit;
  - Product Integrity reports FW-AID honestly as Defined rather than implemented or Proven;
  - the active D-024 Core sequence remains unchanged, with FW-KEYS-003 still next after this independent architecture milestone;
  - no runtime detector, live telemetry source, sensor/hook, credential access, network/process/container control, containment, quarantine, recovery execution, deployment, or response authority is added.
- Expected validation: focused documentation/registry proof and exact independent read-only review; no full product suite is required because this is an architecture-only change.
- Security considerations: architecture text and registry metadata cannot become authority; future execution remains gated by bounded milestones and canonical owners.
- Completion evidence: exact candidate `9e3e0230c5bc5aa3cfca740c9aae46b7d1e44438`; focused documentation/registry proof 31 passed after correcting one wording assertion. The first exact Claude attempt exhausted its bounded turn limit and was not counted; one bounded unchanged-candidate retry returned exact APPROVE/LOW with no blockers or missing tests under job `phase2a-9e3e0230c5bc5aa3cfca740c`. No full product suite was required for this architecture-only milestone.

### FWQ-0072 — Claude structured-review terminal turn
- Requirement: FW-HARNESS reviewer availability repair
- State: DONE
- Priority: P0
- Dependencies: FWQ-0067
- Approval: bounded reliability repair required by repeated exact-review verifier exhaustion.
- Description: Allow one additional bounded Claude structured-output turn so a permitted read/tool request can reach its terminal schema response without changing tools, permissions, timeout, model, or acceptance rules.
- Target path: swarm/claude_verifier.py
- Allowed paths: swarm/claude_verifier.py, tests/test_claude_verifier.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_claude_verifier.py tests/test_review_runner.py
- Acceptance criteria:
  - maximum turns increases only from two to three;
  - tool-free mode remains tool-free and oversized mode remains Read-only;
  - exact job/SHA/schema validation, snapshot isolation, timeout, and no-authority boundaries remain unchanged;
  - previously pending exact candidates receive at most one retry after repair;
  - no shell, Git, MCP, edit, browser, deployment, or network tool is granted to Claude.
- Expected validation: focused Linux proof and exact Claude review through the repaired bounded path.
- Security considerations: the extra terminal turn does not add a capability or relax acceptance.
- Completion evidence: exact candidate `83386cb09f38c97774db43ca4bc340396d617186`; focused 18 passed; Claude APPROVE/LOW with no blockers/missing tests; combined full 968 passed/1 skipped and integrity hard checks/4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fwq-0072-claude-review.json`, `docs/fw-harness-004-007-integrity.json`.

### FWQ-0071 — Azure Foundry exact-commit review adapter
- Requirement: FW-HARNESS-007 Azure independent review
- State: DONE
- Priority: P0
- Dependencies: FWQ-0067
- Approval: Azure read-only review is explicitly approved under D-019; live calls require verified credit-only spending protection and bounded cost evidence.
- Description: Add Microsoft Foundry as a read-only exact-commit reviewer in the existing review runner using the OpenAI v1-compatible route, transient Entra credentials, strict schema/SHA binding, and a fail-closed credit guard.
- Target path: swarm/azure_foundry_adapter.py
- Allowed paths: swarm/azure_foundry_adapter.py, swarm/review_runner.py, tests/test_azure_foundry_adapter.py, tests/test_review_runner.py, docs/azure-foundry-reviewer.md, DECISIONS.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_azure_foundry_adapter.py tests/test_review_runner.py tests/test_verification_adapters.py
- Acceptance criteria:
  - exact approved Azure HTTPS host, deployment, job ID, candidate SHA, and review schema binding;
  - transient Entra or approved API-key transport with credentials excluded from prompt, output, errors, Git, and evidence;
  - recent credit-only/spending-protection/remaining-balance evidence required before calls;
  - atomic worst-case cost reservation, retained credit reserve, completion-token cap, and daily-call limit;
  - missing/stale/expired/exhausted/pay-as-you-go evidence denies before credential resolution or network access;
  - provider output remains advisory and cannot accept, mutate, deploy, or expand authority.
- Expected validation: focused Linux proof, exact read-only review when available, then full suite/integrity once.
- Security considerations: no live call occurs until interactive Entra login, exact deployment discovery, and credit protection verification complete.
- Blocking reason: the cached Azure CLI identity is present, but Entra security defaults require an interactive management-scope login before resource/deployment and credit-protection evidence can be inspected without keys.
- Completion evidence: exact candidate `05843269712abd1952a90c1f1aac96c2b3209eaf`; focused 29 passed; Claude APPROVE/LOW with no blockers/missing tests; combined full 968 passed/1 skipped and integrity hard checks/4 Golden Paths pass with unchanged YELLOW findings. Live Azure activation remains safely disabled pending interactive Entra login and credit/deployment verification. Evidence: `docs/fw-harness-007-claude-review.json`, `docs/fw-harness-004-007-integrity.json`.

### FWQ-0078 — Integrated governed harness lifecycle proof
- Requirement: FW-HARNESS-013 initial permanent harness integration
- State: DONE
- Priority: P0
- Dependencies: FWQ-0077
- Approval: integration of accepted FW-HARNESS components is approved by the master requirement; external activation, new authority, and deployment remain prohibited.
- Description: Wire the accepted canonical task, context, budget, worker, authority, model, validation, review, Git/checkpoint, Evidence, recovery, continuation, and Mission Control interfaces into one deterministic fixture-driven lifecycle proving restart-safe automatic advancement.
- Target path: swarm/harness_controller.py
- Allowed paths: swarm/harness_controller.py, swarm/autonomous_loop.py, swarm/harness_context.py, tests/test_harness_controller.py, tests/test_autonomous_loop.py, tests/test_harness_context.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_controller.py tests/test_autonomous_loop.py tests/test_harness_task.py tests/test_harness_context.py tests/test_harness_worker.py tests/test_harness_authority.py tests/test_harness_models.py tests/test_harness_evidence.py tests/test_harness_recovery.py tests/test_mission_control.py
- Acceptance criteria:
  - one controller selects the next authorized dependency-complete task and advances through context, budget, authority/model admission, worker result, validation, exact review, trusted checkpoint, Evidence, and next task;
  - restart resumes from durable stage evidence without assuming interrupted work succeeded or replaying consumed authority;
  - bounded repair is generated only through the accepted recovery contract and repeated failure escalates;
  - Mission Control reflects the same canonical lifecycle and next-task decision without owning state;
  - deterministic failure injection proves stops for approval, authority, dependency, budget, identity/scope, validation/review, Evidence, and kill-switch boundaries;
  - fixture-only workers/reviewers are used; no live provider, credential resolution, network, deployment, remediation, or response authority is added.
- Expected validation: focused end-to-end Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: this integration may compose accepted interfaces but may not bypass any one of their fail-closed checks.
- Completion evidence: exact candidate `2ccc389e566daf6c4a46ed1c50b53bd8d86b0aa5`; focused 211 passed; Claude was unavailable after two bounded exact-commit attempts; AnythingLLM/Qwen exact APPROVE/LOW with no blockers or missing tests after canonical boundary-test reconciliation; full 1088 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings.

### FWQ-0077 — Harness Monitor → Repair → Review governance
- Requirement: FW-HARNESS-012 anomaly and recovery governance
- State: DONE
- Priority: P0
- Dependencies: FWQ-0076
- Approval: bounded monitoring and recovery classification are approved by the FW-HARNESS master requirement; repair execution remains subject to existing task/authority/ticket gates.
- Description: Deterministically classify harness anomalies and produce bounded monitor, repair-request, and recovery-review records for stuck work, retry/resource spikes, test degradation, file scope, privilege, provider/model substitution, and Evidence integrity failures.
- Target path: swarm/harness_recovery.py
- Allowed paths: swarm/harness_recovery.py, tests/test_harness_recovery.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_recovery.py tests/test_autonomous_loop.py tests/test_harness_authority.py tests/test_harness_evidence.py tests/test_harness_models.py
- Acceptance criteria:
  - monitor input and classification are deterministic, bounded, tenant/task/worker/model bound, and Evidence-first;
  - repair output is an authority-free request for an existing approved bounded task, never an executed action;
  - recovery review binds exact repair attempt, validation, reviewer, checkpoint/rollback, and final status;
  - repeated failures, budget exhaustion, scope/privilege anomalies, Evidence failure, and kill-switch state stop or escalate without silent authority expansion;
  - no process restart, filesystem rollback, provider connection, credential, deployment, remediation, or response authority is added.
- Expected validation: focused adversarial Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: monitor/recovery records are untrusted observations until deterministic validation and canonical Evidence succeed.
- Completion evidence: exact candidate `9b9ce277313d105b894608da3f33d8f39de126b2`; focused 150 passed; exact Claude APPROVE/LOW with no blockers/missing tests; full 1081 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-012-claude-review.json`, `docs/fw-harness-012-integrity-full.json`.

### FWQ-0076 — Harness Approved Model Registry admission
- Requirement: FW-HARNESS-011 approved model binding
- State: DONE
- Priority: P0
- Dependencies: FWQ-0075
- Approval: deterministic Model Broker/Approved Model Registry integration is approved by the FW-HARNESS master requirement; no new provider, model, route, or credential activation is approved.
- Description: Bind harness worker selection and fallback to existing exact Approved Model Registry/Model Broker decisions covering provider, model, role, data class, tool policy, context/resource limits, approval version, and reliability metadata.
- Target path: swarm/harness_models.py
- Allowed paths: swarm/harness_models.py, tests/test_harness_models.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_models.py tests/test_harness_worker.py tests/test_model_broker.py tests/test_asoc.py
- Acceptance criteria:
  - admission consumes an existing exact Model Broker decision and creates no second model registry or routing authority;
  - provider, model/deployment/version, worker role, tenant, data classification, tools, context/resource budgets, and approval version bind exactly;
  - silent fallback, router-selected substitution, unapproved model/provider, role/data/tool mismatch, stale approval, and budget expansion deny safely;
  - fallback is permitted only when an explicit ordered approved equivalent is separately admitted;
  - no provider connection, credential resolution, model registration, network transport, deployment, or response authority is added.
- Expected validation: focused adversarial Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: model availability and confidence never grant authority or permit silent substitution.
- Completion evidence: exact candidate `a6f60e429d43a0e6df44ed91e7156f5fe0e81ebd`; focused 135 passed; exact Claude APPROVE/LOW with no blockers/missing tests; full 1063 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-011-claude-review.json`, `docs/fw-harness-011-integrity-full.json`.

### FWQ-0075 — Harness capability and Action Ticket admission
- Requirement: FW-HARNESS-010 bounded execution authority
- State: DONE
- Priority: P0
- Dependencies: FWQ-0074
- Approval: deterministic capability/lease/Action Ticket integration is approved by the FW-HARNESS master requirement; no new capability class or authority expansion is approved.
- Description: Bind each harness execution request to existing FW-ASOC capability leases and, where mutation is requested, an existing single-use Action Ticket decision, while preserving task scope, expiry, tenant, identity, budget, kill-switch, and Evidence boundaries.
- Target path: swarm/harness_authority.py
- Allowed paths: swarm/harness_authority.py, tests/test_harness_authority.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_authority.py tests/test_asoc.py tests/test_harness_task.py tests/test_harness_worker.py
- Acceptance criteria:
  - admission consumes existing validated agent/capability/lease/Action Ticket decisions through narrow interfaces and creates no second authority registry;
  - exact tenant, task, actor, worker, capability, resource/path, operation, expiry, budget, policy version, and kill-switch state bind each decision;
  - read-only work cannot gain mutation and mutating work cannot proceed without the applicable single-use Action Ticket decision;
  - replay, expiry, revocation, scope escape, identity/provider substitution, missing Evidence, and authority inheritance deny safely;
  - no capability issuance, ticket signing, credential resolution, provider activation, deployment, remediation, or response authority is added.
- Expected validation: focused adversarial Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: AI requests are untrusted and cannot mint, widen, renew, inherit, or approve authority.
- Completion evidence: exact candidate `0b699536951464a085bd0beacd6b38a64929b38c`; focused 145 passed; exact Claude APPROVE/LOW with no blockers/missing tests; full 1045 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-010-claude-review.json`, `docs/fw-harness-010-integrity-full.json`.

### FWQ-0074 — Harness lifecycle Evidence integration
- Requirement: FW-HARNESS-009 canonical lifecycle evidence
- State: DONE
- Priority: P0
- Dependencies: FWQ-0073
- Approval: Evidence integration is approved by the FW-HARNESS master requirement; it must consume FW-EVID and may not create a competing log authority.
- Description: Map bounded harness task, context, worker, validation, review, acceptance, denial, checkpoint, and recovery lifecycle events into the canonical Evidence boundary with exact identity and commit references.
- Target path: swarm/harness_evidence.py
- Allowed paths: swarm/harness_evidence.py, tests/test_harness_evidence.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_evidence.py tests/test_harness_task.py tests/test_harness_context.py tests/test_harness_worker.py
- Acceptance criteria:
  - canonical evidence binds tenant, task, requirement, actor/worker/model, context hash, authorized capabilities, attempted/denied actions, files, tests, reviewer findings, policy/acceptance decision, timestamps, commit, and checkpoint references;
  - evidence consumes the existing FW-EVID sink and does not own signing, storage, deletion, mutation, or trust decisions;
  - malformed, secret-bearing, cross-tenant, mismatched, excessive, or mutable lifecycle input denies before Evidence emission;
  - Evidence failure denies the lifecycle transition without partial success or authority expansion;
  - no provider, credential, deployment, remediation, or response authority is added.
- Expected validation: focused adversarial Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: model output and operational logs remain untrusted; only validated bounded facts enter canonical Evidence.
- Completion evidence: exact candidate `f03998ea53f965641b8207139968daa3d0ae938d`; focused 56 passed; exact Claude APPROVE/LOW with no blockers/missing tests; full 1025 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-009-claude-review.json`, `docs/fw-harness-009-integrity-full.json`.

### FWQ-0073 — Harness Mission Control projection
- Requirement: FW-HARNESS-008 operator visibility
- State: DONE
- Priority: P0
- Dependencies: FWQ-0070
- Approval: read-only Mission Control integration is approved by the FW-HARNESS master requirement; new control authority or deployment remains prohibited.
- Description: Project canonical harness task, dependency, worker, validation, review, retry, budget, commit, decision, next-task, and kill-switch state into a bounded read-only Mission Control view using existing state owners.
- Target path: swarm/mission_control.py
- Allowed paths: swarm/mission_control.py, tests/test_mission_control.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_mission_control.py tests/test_harness_task.py tests/test_harness_context.py tests/test_autonomous_loop.py
- Acceptance criteria:
  - operator view exposes the current phase/requirement/task, queue/dependencies/blockers, exact worker/model, relevant files, commit, validation/review, retries, budget usage, recent decisions, next task, and kill-switch state;
  - projection consumes canonical task/context/budget/controller records without creating a second mutable state owner;
  - malformed, cross-tenant, inconsistent, oversized, or secret-bearing state denies safely;
  - view is deterministic, bounded, read-only, and grants no task, Git, credential, policy, approval, deployment, or kill-switch authority.
- Expected validation: focused adversarial Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: raw logs, prompts, credentials, and model output are not operator-state authority and are excluded from the projection.
- Completion evidence: exact candidate `5fd266cce1780061a39a2bd6bc465e5cfec043d9`; focused 119 passed; exact Claude APPROVE/LOW with no blockers/missing tests; full 1007 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-008-claude-review.json`, `docs/fw-harness-008-integrity-full.json`.

### FWQ-0070 — Provider OAuth and credential-broker contract
- Requirement: FW-HARNESS-006 provider authentication
- State: DONE
- Priority: P0
- Dependencies: FWQ-0069
- Approval: credential architecture is approved under D-023; provider activation and credential creation remain explicit approval gates.
- Description: Define deterministic OpenAI, Anthropic, and Google/Gemini provider-authentication profiles supporting only officially available OAuth flows or approved API-key classes, with FW-ID identity binding and FW-KEYS opaque secret handles; Gemini local CLI identity is `agy`.
- Target path: swarm/harness_credentials.py
- Allowed paths: swarm/harness_credentials.py, tests/test_harness_credentials.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_credentials.py tests/test_harness_worker.py tests/test_asoc.py
- Acceptance criteria:
  - exact provider, tenant, identity, authorization method, scopes, expiry, approval, and revocation metadata;
  - OAuth behavior is provider-specific and never inferred or silently substituted;
  - persistent records contain opaque FW-KEYS handles and sanitized outcomes only;
  - access/refresh tokens, client secrets, and API keys are rejected from task, context, log, Git, and Evidence schemas;
  - expiry, revocation, provider/model mismatch, absent approval, and unsupported flow deny safely;
  - no live OAuth exchange, credential creation, provider connection, network transport, or deployment authority.
- Expected validation: focused adversarial Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: credential material is isolated at the trusted adapter boundary and models cannot request broader scopes.
- Completion evidence: exact candidate `5d2cf3e2c6520b72e722d456c5c3df8a31b74658`; focused 133 passed; exact Claude APPROVE/LOW with no blockers/missing tests; full 991 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-006-claude-review.json`, `docs/fw-harness-006-integrity-full.json`.

### FWQ-0069 — Swarm execution-boundary hardening
- Requirement: FW-HARNESS-005 swarm resilience and isolation
- State: DONE
- Priority: P0
- Dependencies: FWQ-0068
- Approval: architecture is approved under D-023; implementation awaits worker-interface prerequisites.
- Description: Harden the single-controller, coding-worker, read-only-reviewer topology against crash, replay, stale lease, path escape, identity substitution, malformed output, resource exhaustion, and unsafe interruption using deterministic controls and adversarial fixtures.
- Target path: swarm/autonomous_loop.py
- Allowed paths: swarm/autonomous_loop.py, swarm/autonomous_adapters.py, swarm/harness_worker.py, tests/test_autonomous_loop.py, tests/test_harness_worker.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_autonomous_loop.py tests/test_harness_worker.py
- Acceptance criteria:
  - exact controller/worker/reviewer identity and configuration binding;
  - atomic stage checkpoints and deterministic restart reconciliation;
  - replay, stale leases, unexpected processes, scope escape, malformed output, and resource exhaustion deny safely;
  - active work checkpoints or terminates safely when the kill switch requires it;
  - denied actions and recovery decisions produce bounded evidence;
  - no provider activation, credential issuance, deployment, or response authority.
- Expected validation: focused adversarial Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: hostile model output and interrupted processes are untrusted inputs.
- Completion evidence: exact candidate `6ef3c6522187f9a11e805dbee19858c1bbed2dcf`; focused 87 passed; exact Claude APPROVE/LOW with no blockers/missing tests; full 972 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-005-claude-review.json`, `docs/fw-harness-005-integrity.json`.

### FWQ-0068 — Governed CLI and API worker interface
- Requirement: FW-HARNESS-004 model worker transport
- State: DONE
- Priority: P0
- Dependencies: FWQ-0067
- Approval: interface architecture is approved under D-023; any provider/model/credential/network activation remains separately approval-gated.
- Description: Define one generic worker interface supporting registered local CLI and approved API adapters with identical scoped tasks, context, capabilities, budgets, and output contracts, including the read-only Gemini CLI registered as `agy`.
- Target path: swarm/harness_worker.py
- Allowed paths: swarm/harness_worker.py, tests/test_harness_worker.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_worker.py tests/test_harness_task.py tests/test_harness_context.py
- Acceptance criteria:
  - exact worker/provider/model/transport registration and role binding;
  - CLI execution contract uses registered executables and sanitized bounded process configuration;
  - Gemini CLI identity binds exactly to registered executable `agy` and read-only roles; it cannot obtain Codex's source-writing role;
  - API contract accepts only FW-KEYS secret references, never raw keys in model-visible or persisted data;
  - provider/model/credential/network activation is denied without explicit approval evidence;
  - transport cannot expand task authority or bypass validation, review, Git, audit, budgets, or kill switch;
  - no live provider connection or credential material is introduced in this milestone.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: adapters mediate hostile output and never expose credentials to models.
- Completion evidence: exact candidate `005afed5525a5308a66c3eb387ef2a49e81724df`; focused 38 passed; Claude APPROVE/LOW with no blockers/missing tests after the bounded verifier repair; combined full 968 passed/1 skipped and integrity hard checks/4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-004-claude-review.json`, `docs/fw-harness-004-007-integrity.json`.

### FWQ-0067 — Auditable targeted context packets and task budgets
- Requirement: FW-HARNESS-003 context and budget controls
- State: DONE
- Priority: P0
- Dependencies: FWQ-0066
- Approval: FW-HARNESS is permanent Core under D-023.
- Description: Build deterministic bounded context packets from caller-supplied approved task material, hash their canonical content, and enforce per-task model-call, token, retry, and elapsed-time budgets without invoking a model.
- Target path: swarm/harness_context.py
- Allowed paths: swarm/harness_context.py, tests/test_harness_context.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_context.py tests/test_harness_task.py
- Acceptance criteria:
  - context contains only explicit approved requirement, constraints, files, contracts, commits, task state, failures, findings, interfaces, and forbidden changes;
  - deterministic canonical encoding and context hash;
  - strict item/byte/count limits and relative path validation;
  - deterministic task/session budget admission and exhaustion reasons;
  - model output cannot alter context selection or resource limits;
  - no file reading, model invocation, network, credentials, Git mutation, deployment, or response authority.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: all supplied context is untrusted data and cannot become authority.
- Completion evidence: exact candidate `6ad03207ebc9950df9c96fd7fee68f5757c15d21`; focused 27 passed; Claude APPROVE/LOW with no blockers/missing tests; full 945 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-003-claude-review.json`, `docs/fw-harness-003-integrity.json`.

### FWQ-0066 — Canonical FW-HARNESS task and transition contract
- Requirement: FW-HARNESS-002 persistent task engine
- State: DONE
- Priority: P0
- Dependencies: FWQ-0065
- Approval: FW-HARNESS is permanent Core under D-023.
- Description: Consolidate the existing queue item, autonomous TaskSpec/runtime record, and work checkpoint around one versioned canonical task schema and deterministic transition contract, preserving compatibility and fail-closed recovery.
- Target path: swarm/harness_task.py
- Allowed paths: swarm/harness_task.py, swarm/task_selection.py, swarm/autonomous_loop.py, tests/test_harness_task.py, tests/test_task_selection.py, tests/test_autonomous_loop.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_task.py tests/test_task_selection.py tests/test_autonomous_loop.py
- Acceptance criteria:
  - stable execution task ID and separate stable FW-HARNESS requirement ID;
  - required lifecycle states and deterministic validated transitions;
  - required task metadata represented with bounded validated values;
  - existing queue/autonomous state loads through explicit compatibility adapters;
  - models cannot mutate protected workflow state;
  - no new execution, Git, filesystem, credential, network, deployment, or response authority.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: persisted task data and model suggestions are untrusted input and must fail closed.
- Completion evidence: exact candidate `78fdf188a452b53c20895c2d024b265fc51621c0`; focused 96 passed; Claude APPROVE/LOW with no blockers/missing tests; full 929 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings. Evidence: `docs/fw-harness-002-claude-review.json`, `docs/fw-harness-002-integrity.json`.

### FWQ-0065 — FW-HARNESS existing architecture inventory
- Requirement: FW-HARNESS-001 harness inventory
- State: DONE
- Priority: P0
- Dependencies: FWQ-0064
- Approval: FW-HARNESS is permanent Core under D-023.
- Description: Inventory the existing orchestration, state, continuation, Codex, review, Git, safety, audit, testing, monitoring, and Mission Control components before changing runtime architecture.
- Target path: docs/fw-harness-inventory.md
- Allowed paths: docs/fw-harness-inventory.md, ROADMAP.md, DECISIONS.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_supervisor_state.py tests/test_task_selection.py
- Acceptance criteria:
  - existing canonical owners and overlaps are identified;
  - requested FW-HARNESS capabilities are mapped to existing components and concrete gaps;
  - consolidation order avoids duplicate orchestrator/evidence architecture;
  - next bounded implementation task is explicit;
  - DRY_RUN, disabled deployment, kill switch, and model no-authority boundaries remain unchanged.
- Expected validation: control-file parser/selector proof, diff check, and exact Claude review.
- Security considerations: documentation and queue metadata grant no runtime authority.
- Completion evidence: exact candidate `0d0585dbb37fc6f062ac9f66eaed3440da889d00`; focused 32 passed; `git diff --check` passed; Claude APPROVE/LOW with no blockers or missing tests. Evidence: `docs/fw-harness-001-claude-review.json`.

### FW-BME-03 — Deterministic dangerous-delivery classification
- Requirement: FW-BME dangerous download, redirect, HTML-smuggling, and prompt-injection signals
- State: DONE
- Priority: P0
- Dependencies: FW-BME-02
- Approval: FW-BME is active under D-022.
- Queue transition: FW-HARNESS-013 completed the explicit D-023 priority; resume the already approved D-022 milestone without expanding its scope.
- Description: Classify exact normalized dangerous-delivery indicators into Evidence-first warn-only findings without fetching links, opening content, scanning files, or invoking AV/quarantine behavior.
- Target path: swarm/browser_email.py
- Allowed paths: swarm/browser_email.py, tests/test_browser_email.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_browser_email.py
- Acceptance criteria:
  - exact HTML_SMUGGLING, DANGEROUS_DOWNLOAD, REDIRECT_CHAIN, and PROMPT_INJECTION tokens only;
  - deterministic LOW/MEDIUM/HIGH confidence based on distinct signals;
  - every finding recommends WARN and no quarantine or link action is proposed or executed;
  - Evidence failure denies output and raw URLs/sender content stay out of Evidence;
  - no browser/mailbox/network/filesystem/process/credential/deployment/response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: content and indicators remain caller-supplied untrusted data; AV trust/catalog boundaries are unchanged.
- Completion evidence: exact candidate `c5769c7002e8f2ffb3ae9885b20bbe8d81df88c6`; focused 28 passed; AnythingLLM/Qwen exact APPROVE/LOW with no blockers or missing tests; full 1095 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings.

### FW-SOC-01 — Tenant-bound incident projection
- Requirement: FW-SOC case and incident foundation
- State: DONE
- Priority: P0
- Dependencies: FW-BME-03
- Approval: FW-SOC follows completed FW-BME under D-022.
- Description: Produce one immutable tenant-bound incident projection from caller-supplied canonical normalized-event and Evidence references, without creating a second event/evidence store or adding response authority.
- Target path: swarm/soc.py
- Allowed paths: swarm/soc.py, tests/test_soc.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_soc.py tests/test_normalized_events.py
- Acceptance criteria:
  - strict bounded schema for incident ID, tenant, title, severity, status, timestamps, affected references, normalized-event references, Evidence references, and disposition;
  - normalized-event and Evidence payloads remain owned by their canonical systems and are referenced rather than copied;
  - immutable deterministic output requires tenant match and Evidence success before return;
  - malformed, duplicate, cross-tenant, excessive, unsupported-state, and Evidence-failure inputs deny safely;
  - no SIEM storage, correlation, playbook, network, filesystem, credential, deployment, containment, remediation, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: an incident projection is an untrusted case fact until deterministic validation and canonical Evidence succeed; it grants no action authority.
- Completion evidence: exact candidate `d036c4d101c08fdaf081d9070fdb6046e9f03fd4`; focused 46 passed; AnythingLLM/Qwen exact APPROVE/LOW with no blockers or missing tests; full 1113 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with unchanged YELLOW findings.

### FW-SOC-02 — Deterministic cross-domain attack-story projection
- Requirement: FW-SOC bounded cross-domain correlation
- State: DONE
- Priority: P0
- Dependencies: FW-SOC-01
- Approval: FW-SOC remains active under D-022.
- Description: Correlate a bounded caller-supplied set of validated incident projections into an immutable tenant-bound attack story using exact shared affected/event references and canonical Evidence, without storing incidents or executing response.
- Target path: swarm/soc.py
- Allowed paths: swarm/soc.py, tests/test_soc.py, swarm/integrity.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_soc.py tests/test_integrity.py
- Acceptance criteria:
  - strict same-tenant incident and reference binding with deterministic ordering and bounded incident/reference counts;
  - correlation requires exact shared affected or normalized-event references and records explicit contributing incident IDs;
  - canonical ownership metadata identifies `swarm.soc` without weakening other owners;
  - Evidence succeeds before immutable output and omits free-form incident titles;
  - malformed, duplicate, cross-tenant, uncorrelated, excessive, mutable-authority, and Evidence-failure inputs deny safely;
  - no SIEM persistence, event copying, model inference, playbook, network, filesystem, credential, deployment, containment, remediation, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: correlation is a reference-only case projection and grants no authority or confidence-based action.
- Completion evidence: exact candidate `c89987fcb7061ffebc858548d052b051c6f233cc`; focused 30 passed; AnythingLLM/Qwen exact APPROVE/LOW with no blockers or missing tests after one malformed self-correcting response and a fresh bounded retry; full 1117 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with SOC ownership now registered and only the existing dependency/identity/compliance YELLOW findings.

### FW-SOC-03 — Deterministic incident timeline projection
- Requirement: FW-SOC bounded case timeline
- State: DONE
- Priority: P0
- Dependencies: FW-SOC-02
- Approval: FW-SOC remains active under D-022.
- Description: Build one immutable tenant-bound chronological case timeline from bounded caller-supplied incident, normalized-event, Evidence, review, approval, recovery, and disposition references without copying source records or executing playbooks.
- Target path: swarm/soc.py
- Allowed paths: swarm/soc.py, tests/test_soc.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_soc.py
- Acceptance criteria:
  - exact bounded timeline-entry types, timestamps, actor references, source references, and Evidence references;
  - strict tenant/incident binding, unique entry IDs, deterministic chronological ordering, and terminal-disposition chronology;
  - source event, Evidence, approval, and recovery records remain owned by their canonical systems and are referenced rather than copied;
  - Evidence succeeds before immutable output and free-form source content is excluded;
  - malformed, duplicate, cross-tenant, excessive, out-of-order terminal, authority-bearing, and Evidence-failure inputs deny safely;
  - no case persistence, playbook execution, credential, network, filesystem, deployment, containment, remediation, recovery, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: a timeline is a reference-only audit projection and cannot authorize or execute an action.
- Completion evidence: exact candidate `01c29518727ea37f5db82980e0b0b174477c53d1`; focused 32 passed; AnythingLLM/Qwen exact APPROVE/LOW with no blockers or missing tests; full 1127 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only the existing dependency/identity/compliance YELLOW findings.

### FW-SOC-04 — Bounded response playbook proposal
- Requirement: FW-SOC deterministic Security Response Playbook seam
- State: DONE
- Priority: P0
- Dependencies: FW-SOC-03
- Approval: FW-SOC remains active under D-022; proposal generation grants no response authority.
- Description: Produce an immutable tenant/incident-bound response playbook proposal from exact approved action classes and canonical policy/approval/Action Ticket references, without issuing tickets, mutating incidents, or executing actions.
- Target path: swarm/soc.py
- Allowed paths: swarm/soc.py, tests/test_soc.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_soc.py tests/test_action_ticket.py tests/test_policy_gate.py
- Acceptance criteria:
  - exact bounded playbook/action-step schema with deterministic ordering, dependency references, and rollback/checkpoint requirements;
  - every proposed mutation step requires existing canonical policy-decision, approval, and Action Ticket references while read-only steps cannot claim mutation authority;
  - strict tenant/incident binding, DRY_RUN, engaged kill-switch evidence, disabled deployment, and no authority expansion;
  - Evidence succeeds before immutable output and contains references rather than credential, event, or free-form source payloads;
  - malformed, duplicate, cyclic, cross-tenant, unsupported-action, missing-authority-reference, excessive, and Evidence-failure inputs deny safely;
  - no ticket issuance/consumption, policy evaluation, incident mutation, playbook execution, deployment, containment, remediation, recovery, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the result is an inert proposal consumed only by later canonical authorization and execution gates.
- Completion evidence: exact candidate `a36d5a75f043720ac625aeaea4da99cf03f75bf3`; focused 65 passed; AnythingLLM/Qwen corrected an unsupported verdict token and returned exact APPROVE/LOW with no blockers or missing tests; full 1135 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only the existing dependency/identity/compliance YELLOW findings.

### FW-SOC-05 — Integrated incident-to-playbook dry-run proof
- Requirement: FW-SOC initial bounded lifecycle integration
- State: DONE
- Priority: P0
- Dependencies: FW-SOC-04
- Approval: composition of accepted FW-SOC interfaces is approved under D-022; execution and response authority remain prohibited.
- Description: Prove one deterministic fixture lifecycle from tenant-bound incident references through attack story, incident timeline, and inert playbook proposal using one canonical Evidence sink and no duplicated state owner.
- Target path: tests/test_soc.py
- Allowed paths: swarm/soc.py, tests/test_soc.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_soc.py tests/test_normalized_events.py tests/test_action_ticket.py tests/test_policy_gate.py
- Acceptance criteria:
  - one fixture-driven proof composes the accepted incident, story, timeline, and playbook interfaces with exact tenant/incident/reference binding;
  - canonical Evidence ordering is deterministic and failure at every stage prevents later projections;
  - cross-tenant, malformed reference, failed policy-reference, missing ticket-reference, and kill-switch/safety-state cases remain denied;
  - outputs remain immutable reference-only DRY_RUN projections and no stage owns or copies normalized events, Evidence, policy, approvals, or Action Tickets;
  - no model inference, persistence, playbook execution, credential, network, filesystem, deployment, containment, remediation, recovery, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: this is an integration proof over inert accepted interfaces, not a response engine.
- Completion evidence: exact candidate `a4c2534f9223a9af522838bbac7a0d8dadbbbc67`; focused 103 passed; AnythingLLM/Qwen exact APPROVE/LOW with no blockers or missing tests; full 1145 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only the existing dependency/identity/compliance YELLOW findings.

### FW-ID-001 — Canonical identity inventory and contract
- Requirement: FW-ID identity and authority foundation
- State: DONE
- Priority: P0
- Dependencies: FW-SOC-05
- Approval: FW-ID is explicitly activated under D-024.
- Description: Inventory existing identity consumers and establish one immutable tenant-bound canonical identity metadata contract without granting authority or duplicating FW-ASOC, FW-KEYS, FW-EVID, policy, approval, Action Ticket, Model Broker, or MCP ownership.
- Target path: swarm/identity.py
- Allowed paths: swarm/identity.py, tests/test_identity.py, swarm/integrity.py, tests/test_integrity.py, docs/fw-id-inventory.md, DECISIONS.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_identity.py tests/test_integrity.py tests/test_asoc.py tests/test_harness_worker.py
- Acceptance criteria:
  - stable immutable identity records bind exact schema version, identity ID, tenant, bounded kind, owner, purpose, lifecycle timestamps, and optional provider/FW-KEYS references;
  - identity metadata contains no permissions, capabilities, policy decision, approval, Action Ticket, model approval, Evidence payload, secret, or execution authority;
  - malformed schemas, unsupported kinds/states, invalid timestamps, unbounded references, and credential-like material fail closed;
  - existing identity consumers and their canonical owners are documented and Product Integrity no longer reports identity as roadmap-only;
  - no registry persistence, authentication, OAuth exchange, credential resolution, network, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: identity establishes attribution and binding only; all authority remains in canonical deterministic policy and ticket/lease owners.
- Completion evidence: exact candidate `2d89726dd8c5d69a61b86d33de3f3fc56c8d2bfd`; focused 145 passed; AnythingLLM/Qwen exact APPROVE/LOW with no blockers or missing tests; full 1168 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with identity ownership implemented and only the existing dependency/compliance YELLOW findings.

### FW-ID-002 — Deterministic tenant-bound identity registry
- Requirement: FW-ID lifecycle ownership
- State: DONE
- Priority: P0
- Dependencies: FW-ID-001
- Approval: FW-ID is explicitly activated under D-024.
- Description: Add the canonical in-memory identity registry with Evidence-first create-once registration, exact tenant lookup, and deterministic activation, revocation, and expiration transitions without authenticating actors or granting authority.
- Target path: swarm/identity.py
- Allowed paths: swarm/identity.py, tests/test_identity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_identity.py tests/test_asoc.py
- Acceptance criteria:
  - create-once registration rejects duplicate IDs across all tenants and records canonical Evidence before mutation;
  - lookup requires exact tenant binding and cannot enumerate another tenant;
  - lifecycle transitions are deterministic, timestamp-valid, terminal after revocation/expiration, and Evidence-first;
  - Evidence failure, replay, invalid transition, tenant mismatch, unknown identity, and stale timestamps leave state unchanged;
  - records remain immutable metadata and grant no role, capability, credential, policy, approval, Action Ticket, authentication, network, deployment, or response authority.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: registry membership establishes identity existence only; deterministic authority owners must separately authorize every action.
- Completion evidence: repaired exact candidate `1a082004f8e041afadd13d068189a5fabc92fe36` against accepted base `98603a37d016ca6daf73884a485bc897c524a8f0`; focused 134 passed; an initial AnythingLLM/Qwen review incorrectly inferred the already-frozen record was mutable but legitimately requested concurrency proof, which was added; cumulative re-review returned exact APPROVE/LOW with no blockers or missing tests; full 1176 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only existing dependency/compliance YELLOW findings.

### FW-ID-003 — Delegated provider identity reference binding
- Requirement: FW-ID delegated provider identity foundation
- State: DONE
- Priority: P0
- Dependencies: FW-ID-002
- Approval: FW-ID and bounded provider identity references are activated under D-024; live authentication remains prohibited.
- Description: Define immutable tenant/subject/provider/consent reference bindings for approved OpenAI, Anthropic, Google/Gemini, and Azure identities using only FW-ID records and opaque tenant-bound FW-KEYS handles.
- Target path: swarm/identity.py
- Allowed paths: swarm/identity.py, tests/test_identity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_identity.py tests/test_harness_worker.py tests/test_model_broker.py
- Acceptance criteria:
  - exact provider, subject identity, tenant, consent/approval reference, credential class, FW-KEYS handle, issue/expiry, and lifecycle binding is immutable and bounded;
  - subject and owner identities must exist, be ACTIVE, share the exact tenant, and use an approved provider identity kind;
  - handles are tenant-bound opaque references and raw tokens, secrets, authorization headers, unknown providers/classes, stale approvals, and expired/revoked identities fail closed;
  - binding creation emits canonical Evidence before return and grants no worker role, model approval, capability, authentication, or transport authority;
  - no OAuth exchange, token resolution, credential access, persistence, network, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: delegated provider metadata records consent attribution only; FW-KEYS retains secrets and trusted transport adapters remain inactive.
- Completion evidence: exact candidate `ef38dafa15a22c8a52c73c0d0c081685d5103155`; focused 62 passed; two AnythingLLM/Qwen responses were rejected as invalid evidence (one truncated, one wrong SHA with a false standard-library claim); exact Claude Code review job `phase2a-e3113ec9151641c89ecd128f` returned APPROVE/LOW with no blockers or missing tests; full 1193 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only existing dependency/compliance YELLOW findings.

### FW-ID-004 — Harness worker identity enforcement
- Requirement: FW-ID and FW-HARNESS worker admission binding
- State: DONE
- Priority: P0
- Dependencies: FW-ID-003
- Approval: FW-ID harness integration is activated under D-024; worker authority remains unchanged.
- Description: Require each harness worker request to bind an exact ACTIVE tenant-scoped FW-ID identity and, for API workers, an exact delegated provider identity reference before deterministic invocation admission.
- Target path: swarm/harness_worker.py
- Allowed paths: swarm/identity.py, swarm/harness_worker.py, tests/test_identity.py, tests/test_harness_worker.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_identity.py tests/test_harness_worker.py tests/test_harness_controller.py
- Acceptance criteria:
  - worker registration/request admission binds worker ID, FW-ID subject, tenant, role, provider/model registration, task/context/budget, and lifecycle state exactly;
  - API admission additionally requires a matching unexpired delegated provider binding and opaque FW-KEYS handle while CLI admission cannot claim one;
  - cross-tenant, unknown, inactive, owner/provider/handle mismatch, replayed/stale binding, and unapproved-role cases fail closed;
  - identity checks occur before an invocation plan is returned and do not let workers mutate identity or workflow state;
  - no process invocation, OAuth exchange, credential resolution, network activation, Git, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: FW-ID proves actor binding only; harness, Model Broker, policy, budgets, and leases retain their existing independent gates.
- Completion evidence: exact candidate `672b6ff99113a3b565c3dbbc33acaaad686e8c0d`; focused 67 passed; exact Claude Code job `phase2a-b532f38b788748c9962df546` returned APPROVE/LOW with no blockers or missing tests; full 1195 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only existing dependency/compliance YELLOW findings.

### FW-ID-005 — Integrated identity lifecycle proof
- Requirement: FW-ID initial lifecycle integration
- State: DONE
- Priority: P0
- Dependencies: FW-ID-004
- Approval: FW-ID integration is activated under D-024.
- Description: Prove one deterministic identity lifecycle from create-once owner/worker registration through provider-reference binding, harness admission, revocation, and replay denial using canonical Evidence and no duplicated authority owner.
- Target path: tests/test_identity.py
- Allowed paths: swarm/identity.py, swarm/harness_worker.py, tests/test_identity.py, tests/test_harness_worker.py, tests/test_harness_controller.py, swarm/integrity.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_identity.py tests/test_harness_worker.py tests/test_harness_controller.py tests/test_integrity.py
- Acceptance criteria:
  - one fixture lifecycle binds tenant, owner, worker, delegated provider identity, worker registration, task/context/budget, and invocation plan exactly;
  - canonical Evidence order is deterministic and any Evidence failure prevents the dependent identity/admission stage;
  - revocation, expiration, replay, cross-tenant substitution, provider/handle mismatch, and authority-shaped identity input remain denied;
  - Product Integrity marks the initial FW-ID slice Proven while accurately recording remaining production identity limitations;
  - no authentication, OAuth exchange, credential resolution, persistence, network activation, process execution, Git, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the proof demonstrates attribution and fail-closed admission; it does not authenticate a real principal or grant action authority.
- Completion evidence: repaired exact candidate `de01fef00bcd95ad04beab592ea053a6cb4491c2`; focused 78 passed. The initial exact Claude review approved the behavior at LOW risk and identified missing expiration-boundary proof; the repaired exact Claude Code job `phase2a-121d5b011d3a41d1837db7e9` returned APPROVE/LOW with no blockers or missing tests. Full 1198 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only the existing dependency/compliance YELLOW findings.

### FW-KEYS-001 — Canonical secret-handle inventory and metadata contract
- Requirement: FW-KEYS foundation
- State: DONE
- Priority: P0
- Dependencies: FW-ID-005
- Approval: FW-KEYS is activated under D-024; no new credential class or live secret backend is authorized.
- Description: Inventory existing key and credential references and establish one immutable tenant-bound metadata contract for opaque secret handles without accepting, storing, resolving, exporting, or logging secret material.
- Target path: swarm/keys.py
- Allowed paths: swarm/keys.py, tests/test_keys.py, swarm/identity.py, swarm/harness_worker.py, tests/test_identity.py, tests/test_harness_worker.py, swarm/integrity.py, tests/test_integrity.py, docs/fw-keys-001-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_keys.py tests/test_identity.py tests/test_harness_worker.py tests/test_integrity.py
- Acceptance criteria:
  - one immutable canonical metadata record binds handle ID, tenant, credential class, owner identity, purpose, backend reference class, lifecycle state/timestamps, generation, and non-export policy exactly;
  - opaque handle identifiers cannot contain raw secret material and secret-shaped fields are rejected rather than copied into state or Evidence;
  - the contract grants no credential access, authentication, provider approval, worker role, capability, policy, Git, deployment, or response authority;
  - existing key, signature, provider-binding, harness, Action Ticket, and evidence consumers are inventoried with their canonical owners and reuse boundaries;
  - Product Integrity recognizes FW-KEYS as the canonical partial owner while accurately recording remaining production limitations.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: this milestone defines metadata only; no vault, HSM, environment-variable, credential-file, OAuth, network, or backend access is added.
- Completion evidence: repaired exact candidate `ca866fdfb800c20ec89a804a83ed01a8572c9955`; initial focused 98 passed and exact Claude approved LOW with no blockers/missing tests. The first full suite found one repository-hygiene failure caused by a literal private-key marker in an adversarial test fixture; the fixture was repaired without weakening runtime secret rejection. Repair-focused 30 passed; repaired exact Claude job `phase2a-ca866fdfb800c20ec89a804a` returned APPROVE/LOW with no blockers or missing tests. Full 1224 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only the existing dependency/compliance YELLOW findings.

### FW-KEYS-002 — Evidence-first secret-handle registry and lifecycle
- Requirement: FW-KEYS deterministic metadata lifecycle
- State: DONE
- Priority: P0
- Dependencies: FW-KEYS-001
- Approval: FW-KEYS lifecycle metadata is activated under D-024; secret material and live backends remain unauthorized.
- Description: Add a create-once tenant-bound registry for validated secret-handle metadata with deterministic activation, revocation, expiration, generation replacement, replay denial, and canonical Evidence-before-state transitions.
- Target path: swarm/keys.py
- Allowed paths: swarm/keys.py, tests/test_keys.py, swarm/integrity.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_keys.py tests/test_integrity.py
- Acceptance criteria:
  - registration is create-once and tenant-scoped, with immutable tenant snapshots and exact handle lookup;
  - lifecycle transitions and generation replacement follow a closed deterministic graph with stale, duplicate, cross-tenant, expired, and replayed inputs denied;
  - canonical Evidence succeeds before every state mutation and contains only bounded metadata, never handle values, backend locators, or secret material;
  - concurrent or reentrant operations on one handle fail closed without corrupting registry state;
  - registry membership grants no credential access, authentication, signing, encryption, policy, approval, Action Ticket, Git, deployment, or response authority.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: all state remains in-memory DRY_RUN metadata; no backend, vault, HSM, environment, file, OAuth, network, or secret-resolution path is added.
- Completion evidence: exact candidate `328620664045ed01ff2028dfa6619a6ab25a9f4a`; focused 51 passed; exact Claude Code job `phase2a-328620664045ed01ff2028df` returned APPROVE/LOW with no blockers or missing tests; full 1241 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with only the existing dependency/compliance YELLOW findings.

### FW-KEYS-003 — Identity and harness secret-handle admission binding
- Requirement: FW-KEYS consumer integration
- State: DONE
- Priority: P0
- Dependencies: FW-KEYS-002
- Approval: deterministic secret-handle admission is activated under D-024; material resolution and provider activation remain unauthorized.
- Description: Require delegated provider identity binding and API worker admission to reference the exact ACTIVE tenant/owner/class-matched FW-KEYS registry record and generation before an invocation plan can be returned.
- Target path: swarm/identity.py
- Allowed paths: swarm/keys.py, swarm/identity.py, swarm/harness_worker.py, swarm/harness_controller.py, tests/test_keys.py, tests/test_identity.py, tests/test_harness_worker.py, tests/test_harness_controller.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_keys.py tests/test_identity.py tests/test_harness_worker.py tests/test_harness_controller.py
- Acceptance criteria:
  - delegated provider binding requires an exact ACTIVE non-expired registry record for the same handle, tenant, subject owner, and credential class;
  - API worker admission rechecks the bound handle lifecycle and generation at plan time so revocation, expiration, rotation, replay, or substitution denies safely;
  - CLI workers remain credential-handle free and existing identity/model/role/task/context/budget gates remain independently enforced;
  - handle metadata is consulted without resolving, exporting, logging, or passing secret material to a worker, reviewer, task state, or Evidence;
  - no authentication, provider call, network, process, Git, deployment, policy, Action Ticket, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: a valid handle proves only bounded metadata admission; it grants no permission to use the referenced material.
- Completion evidence: exact candidate `5569690c74569d56e0bb1d8336fa1ccbcb3b1b5f`; focused 121 passed; exact Claude Code job `phase2a-5569690c74569d56e0bb1d83` returned APPROVE/LOW with no blockers or missing tests; full 1255 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with YELLOW only for the existing dependency and Defined FW-COMP/FW-AID owners.

### FW-KEYS-004 — Trusted catalog verification-key lifecycle binding
- Requirement: FW-KEYS trusted verification consumer integration
- State: DONE
- Priority: P0
- Dependencies: FW-KEYS-003
- Approval: deterministic verification-key metadata binding is activated under D-024; signing material and live key backends remain unauthorized.
- Description: Bind TrustedSignatureCatalog definition admission and accepted-cache recovery to exact ACTIVE tenant/class/generation FW-KEYS verification metadata without moving signature policy or definition ownership into FW-KEYS.
- Target path: swarm/anti_malware.py
- Allowed paths: swarm/keys.py, swarm/anti_malware.py, tests/test_keys.py, tests/test_anti_malware.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_keys.py tests/test_anti_malware.py
- Acceptance criteria:
  - signed definition admission records an exact tenant-bound non-exportable SIGNING_KEY or TRUST_ANCHOR handle generation from the canonical registry;
  - inactive, expired, revoked, rotated, cross-tenant, owner/class, generation, signer-ID, or catalog substitution fails closed before a trusted snapshot/cache is accepted;
  - accepted-cache recovery rechecks current key metadata and denies stale key generations or lifecycle state;
  - TrustedSignatureCatalog retains definition/signature verification ownership and no key material or backend locator enters definitions, caches, logs, prompts, reviews, or Evidence;
  - no key generation, signing, secret resolution, vault/HSM access, filesystem hook, network, process, deployment, quarantine, remediation, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: FW-KEYS supplies lifecycle metadata only; cryptographic verification remains within the existing trusted catalog boundary.
- Completion evidence: repaired exact candidate `efec39cb2c91294473766908e7590bd433b0a9f8`; focused 100 passed; exact Claude Code job `phase2a-efec39cb2c91294473766908` returned APPROVE/LOW with no blockers or missing tests after the first candidate's three legitimate edge-test findings were added; full 1256 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with YELLOW only for the existing dependency and Defined FW-COMP/FW-AID owners.

### FW-KEYS-005 — Integrated secret-handle lifecycle proof
- Requirement: FW-KEYS integrated lifecycle acceptance
- State: DONE
- Priority: P0
- Dependencies: FW-KEYS-004
- Approval: deterministic metadata-only lifecycle integration is activated under D-024; secret resolution and live provider/key backends remain unauthorized.
- Description: Prove one canonical FW-KEYS lifecycle across identity-bound harness admission and trusted catalog verification, including lifecycle invalidation, generation replacement, Evidence minimization, and Product Integrity ownership.
- Target path: tests/test_keys.py
- Allowed paths: swarm/keys.py, swarm/identity.py, swarm/harness_worker.py, swarm/harness_controller.py, swarm/anti_malware.py, swarm/integrity.py, tests/test_keys.py, tests/test_identity.py, tests/test_harness_worker.py, tests/test_harness_controller.py, tests/test_anti_malware.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_keys.py tests/test_identity.py tests/test_harness_worker.py tests/test_harness_controller.py tests/test_anti_malware.py tests/test_integrity.py
- Acceptance criteria:
  - one deterministic proof composes canonical registration, activation, exact tenant/owner/class/generation consumer binding, harness API admission, and trusted catalog verification/accepted-cache recovery;
  - revocation, expiration, replacement generation, stale provider binding, and stale catalog verification independently fail closed at their consumer boundaries;
  - canonical Evidence records bounded lifecycle metadata and outcomes without handle values, backend locators, purposes, public/private key material, credentials, or secrets;
  - Product Integrity identifies SecretHandleRegistry and the existing identity/harness/catalog consumers as the canonical partial FW-KEYS implementation with an honest metadata-only limitation;
  - no backend, vault/HSM access, material resolution, authentication, signing, encryption, network, process, Git, deployment, containment, remediation, recovery execution, or response authority is added.
- Expected validation: focused Linux integrated proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: lifecycle proof must use disposable in-memory registries and caller-supplied public fixtures only; registry membership and public verification never grant material use.
- Completion evidence: exact candidate `30f99d8337af77fc02e405cf27cbd55f7ed7335a`; focused 187 passed; exact Claude Code job `phase2a-30f99d8337af77fc02e405cf` returned APPROVE/LOW with no blockers or missing tests; full 1257 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with YELLOW only for the existing dependency and Defined FW-COMP/FW-AID owners. Product Integrity now reports FW-KEYS Proven with its metadata-only limitation explicit.

### FW-EVID-001 — Evidence inventory and canonical envelope contract
- Requirement: FW-EVID canonical evidence ownership
- State: DONE
- Priority: P0
- Dependencies: FW-KEYS-005
- Approval: deterministic local Evidence metadata is activated under D-024; external storage, signing, export, and network transport remain unauthorized.
- Description: Inventory existing audit/evidence producers and establish one immutable tenant-bound canonical Evidence envelope that they can adopt without replacing their owned payload schemas or creating a competing log.
- Target path: swarm/evidence.py
- Allowed paths: swarm/evidence.py, swarm/core.py, swarm/harness_evidence.py, swarm/accepted_work_evidence.py, swarm/audit_integrity.py, swarm/integrity.py, docs/fw-evid-inventory.md, tests/test_evidence.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_evidence.py tests/test_audit_integrity.py tests/test_accepted_work_evidence.py tests/test_harness_evidence.py tests/test_integrity.py
- Acceptance criteria:
  - the inventory names existing producers, schemas, stores, integrity checks, canonical owners, overlaps, and concrete gaps without declaring existing payload formats obsolete;
  - the immutable envelope uses a stable schema/version and exact evidence, tenant, event, actor, subject, timestamp, classification, payload-schema, payload-digest, previous-record-digest, and correlation/reference fields with bounded values;
  - unknown fields, cross-tenant references, invalid timestamps/digests/classifications, duplicate references, mutable input, and secret-shaped metadata fail closed;
  - the envelope stores payload hashes and bounded references rather than raw sensitive payloads and grants no signing, append, storage, export, policy, ticket, Git, deployment, or response authority;
  - Product Integrity recognizes the canonical FW-EVID envelope while honestly retaining partial status until append-only lifecycle and chain verification are proven.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: this milestone defines metadata and ownership only; AuditLog migration, signing, retention, export, external stores, and incident evidence lifecycle require later bounded tasks.
- Completion evidence: source candidate `ad76ff095581a7a52a5a1c49574aefca227a89f8` and exact repair candidate `bf87e0c6c89e774d2c896772837648dd20e7e9c1`; focused 70 passed; the source review returned APPROVE/LOW but requested four boundary-test groups, all added in the repair; exact repair Claude Code job `phase2a-bf87e0c6c89e774d2c896772` returned APPROVE/LOW with no blockers or missing tests; full 1283 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with YELLOW only for the existing dependency and Defined FW-COMP/FW-AID owners.

### FW-EVID-002 — Evidence-first append-only ledger and chain verification
- Requirement: FW-EVID deterministic lifecycle integrity
- State: DONE
- Priority: P0
- Dependencies: FW-EVID-001
- Approval: bounded in-memory append and caller-supplied durability acknowledgement are activated under D-024; external storage, signing, export, and transport remain unauthorized.
- Description: Add a create-once tenant-scoped ledger for canonical envelopes with deterministic record hashes, exact previous-record linkage, duplicate/replay denial, and write-before-state ordering.
- Target path: swarm/evidence.py
- Allowed paths: swarm/evidence.py, tests/test_evidence.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_evidence.py
- Acceptance criteria:
  - append accepts only validated canonical envelopes for one exact tenant and requires the exact current previous-record digest;
  - a deterministic canonical record digest binds every envelope field, and tenant snapshots preserve append order without exposing mutable state;
  - duplicate evidence IDs, record hashes, stale/forked links, cross-tenant input, concurrent/reentrant append, and durability-sink failure fail closed without state mutation;
  - the durability sink receives only the validated envelope and resulting digest, with no raw payload, secret, signing key, backend locator, or expanded authority;
  - ledger membership grants no mutation of prior records, signing, export, policy, approval, Action Ticket, Git, deployment, containment, recovery, or response authority.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: this is an in-memory DRY_RUN lifecycle boundary; filesystem/database migration, cryptographic signing, retention, replication, and external export remain later milestones.
- Completion evidence: exact candidate `7ee285c6c655d05ff88c01eaa449af85cb7a46d1`; focused 30 passed; exact Claude Code job `phase2a-7ee285c6c655d05ff88c01ea` returned APPROVE/LOW with no blockers or missing tests. The first full run had one unrelated desktop MCP fixture child-reaping race after 1286 passes; that child had already exited and the exact failing test then passed once. Product Integrity's fresh full run passed 1287/1, all hard checks, and 4 Golden Paths, with YELLOW only for the existing dependency and Defined FW-COMP/FW-AID owners.

### FW-EVID-003 — Harness lifecycle canonical-envelope adapter
- Requirement: FW-EVID producer integration
- State: DONE
- Priority: P0
- Dependencies: FW-EVID-002
- Approval: deterministic in-memory harness Evidence adaptation is activated under D-024; durable migration, signing, export, and transport remain unauthorized.
- Description: Adapt the existing governed harness lifecycle payload into the canonical FW-EVID envelope and ledger without changing harness payload ownership or creating a second controller.
- Target path: swarm/harness_evidence.py
- Allowed paths: swarm/evidence.py, swarm/harness_evidence.py, swarm/harness_controller.py, tests/test_evidence.py, tests/test_harness_evidence.py, tests/test_harness_controller.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_evidence.py tests/test_harness_evidence.py tests/test_harness_controller.py
- Acceptance criteria:
  - canonical adaptation hashes the exact validated HarnessLifecycleEvidence payload and emits an envelope bound to the same tenant, task, actor, event time, classification, correlation, and prior ledger record;
  - existing harness payload validation and sink ownership remain authoritative, and the adapter cannot accept an unvalidated mapping or substitute task/tenant/actor/event bindings;
  - ledger failure denies canonical admission without claiming harness acceptance, while duplicate, replayed, stale-chain, and cross-tenant lifecycle facts fail closed;
  - raw prompts, context content, model output, secrets, handles, backend locators, and unrestricted file content do not enter the envelope or ledger;
  - no worker, reviewer, Git, policy, approval, Action Ticket, credential, deployment, containment, recovery, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the adapter remains in-memory and DRY_RUN; durable AuditLog migration and signed chain-of-custody are separate milestones.
- Completion evidence: exact candidate `3a4044c60a79ae440ff58edadf227df947d96500`; focused 61 passed; exact Claude Code job `phase2a-3a4044c60a79ae440ff58eda` returned APPROVE/LOW with no blockers or missing tests; full 1294 passed/1 skipped; Product Integrity fresh full 1294 passed/1 skipped, 4 Golden Paths, and all hard checks passed with YELLOW only for the existing `tzdata` dependency and Defined FW-COMP/FW-AID owners.

### FW-EVID-004 — Canonical ledger durable AuditLog adapter
- Requirement: FW-EVID durable lifecycle integration
- State: DONE
- Priority: P0
- Dependencies: FW-EVID-003
- Approval: bounded local DRY_RUN persistence through the existing private AuditLog boundary is activated under D-024; schema migration, signing, export, replication, and transport remain unauthorized.
- Description: Provide the canonical Evidence ledger with a deterministic durability sink backed by the existing restricted append-only AuditLog owner, without replacing its legacy event format or weakening its filesystem protections.
- Target path: swarm/evidence.py
- Allowed paths: swarm/evidence.py, swarm/core.py, swarm/audit_integrity.py, tests/test_evidence.py, tests/test_swarm.py, tests/test_audit_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_evidence.py tests/test_swarm.py tests/test_audit_integrity.py
- Acceptance criteria:
  - the adapter durably records the exact canonical envelope and record digest before ledger state advances, using the existing restricted local AuditLog writer and its locking, no-follow, permissions, flush, and fsync guarantees;
  - restart reconstruction verifies every canonical record digest and exact tenant chain before admitting the recovered ledger state, and malformed, truncated, duplicate, replayed, forked, cross-tenant, or mixed legacy/canonical substitution fails closed;
  - legacy AuditLog readers and accepted historical records remain compatible and no competing filesystem writer or Evidence format is created;
  - raw producer payloads, prompts, model output, secrets, handles, and backend locators are never persisted by the canonical adapter;
  - no signing, export, transport, policy, approval, Action Ticket, Git, deployment, containment, recovery execution, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: persistence remains local, private, append-only, and DRY_RUN; retention, signing, external storage, replication, and export require later milestones.
- Completion evidence: exact repaired candidate `c2b5b46967e65ddc6676aad1631f268370829a7c`; focused 78 passed; exact Claude Code job `phase2a-c2b5b46967e65ddc6676aad1` returned APPROVE/LOW with no blockers or missing tests after two bounded provider-unavailable attempts and repair of all earlier boundary-test findings; full 1308 passed/1 skipped; Product Integrity fresh full 1308 passed/1 skipped, 4 Golden Paths, and all hard checks passed with YELLOW only for the existing `tzdata` dependency and Defined FW-COMP/FW-AID owners.

### FW-EVID-005 — Accepted-work canonical-envelope adapter
- Requirement: FW-EVID acceptance lifecycle integration
- State: DONE
- Priority: P0
- Dependencies: FW-EVID-004
- Approval: bounded adaptation of already-validated accepted-work records is activated under D-024; reviewer policy migration, signing, export, replication, and transport remain unauthorized.
- Description: Bind the existing accepted-work evidence bundle to the canonical tenant ledger while retaining accepted-work validation, exact-commit/reviewer ownership, and create-once storage semantics.
- Target path: swarm/accepted_work_evidence.py
- Allowed paths: swarm/accepted_work_evidence.py, swarm/evidence.py, tests/test_accepted_work_evidence.py, tests/test_evidence.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_accepted_work_evidence.py tests/test_evidence.py
- Acceptance criteria:
  - only an exact bundle already validated by the accepted-work owner can be hashed and adapted, with exact job, candidate/accepted commit, review, validation, policy, and prior-event bindings preserved;
  - the canonical envelope binds the same tenant, accepted task/job, controller actor, canonical timestamp, classification, correlation, payload digest, Evidence references, and exact current ledger chain;
  - invalid, stale, duplicate, replayed, cross-tenant, commit-substituted, reviewer-substituted, or durability-failed acceptance records fail closed without ledger mutation;
  - provider prose, raw prompts/context/model output, secrets, handles, backend locators, and unrestricted file content do not enter the canonical envelope;
  - no reviewer-policy change, signing, export, transport, Git mutation, deployment, containment, recovery execution, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: this adapter consumes the existing accepted-work schema unchanged; any future reviewer-policy schema evolution requires its own explicit deterministic migration.
- Completion evidence: exact candidate `8b86578dbf6ede0236b45d00b856c648cd39198e`; focused 59 passed; exact Claude Code job `phase2a-8b86578dbf6ede0236b45d00` returned APPROVE/LOW with no blockers or missing tests; full 1312 passed/1 skipped; Product Integrity fresh full 1312 passed/1 skipped, 4 Golden Paths, and all hard checks passed with YELLOW only for the existing `tzdata` dependency and Defined FW-COMP/FW-AID owners.

### FW-EVID-006 — Integrated canonical Evidence lifecycle proof
- Requirement: FW-EVID lifecycle acceptance
- State: DONE
- Priority: P0
- Dependencies: FW-EVID-005
- Approval: deterministic local DRY_RUN lifecycle proof is activated under D-024; signing, retention enforcement, external export, replication, and transport remain unauthorized.
- Description: Prove one tenant-bound lifecycle from validated harness facts through canonical append, accepted-work binding, durable AuditLog persistence, restart reconstruction, and replay/tamper denial using the existing owners.
- Target path: tests/test_evidence_lifecycle.py
- Allowed paths: swarm/evidence.py, swarm/harness_evidence.py, swarm/accepted_work_evidence.py, swarm/integrity.py, tests/test_evidence_lifecycle.py, tests/test_evidence.py, tests/test_harness_evidence.py, tests/test_accepted_work_evidence.py, docs/fw-evid-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_evidence.py tests/test_harness_evidence.py tests/test_accepted_work_evidence.py tests/test_evidence_lifecycle.py
- Acceptance criteria:
  - one deterministic proof composes validated harness lifecycle payloads, exact accepted-work evidence, canonical envelopes, tenant chain admission, durable private AuditLog persistence, and exact restart reconstruction;
  - restart continues only from the exact recovered tail and denies duplicate, stale, forked, cross-tenant, tampered, truncated, or durability-failed evidence without claiming acceptance;
  - payload owners remain authoritative and canonical Evidence retains only hashes and bounded references, with no raw prompts, context, provider prose, model output, secrets, handles, or backend locators;
  - Product Integrity reports FW-EVID Proven only within its explicit local DRY_RUN, unsigned, non-exporting boundary;
  - no policy, approval, Action Ticket, Git mutation, signing, deployment, containment, recovery execution, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: proof covers deterministic lifecycle and restart integrity only; cryptographic signing, retention execution, replication, and external export remain separately gated.
- Completion evidence: exact candidate `bb8f2a64adf3563581b8e81fab21598cc95ad2fc`; focused 95 passed; exact Claude Code job `phase2a-bb8f2a64adf3563581b8e81f` returned APPROVE/LOW with no blockers or missing tests; full 1329 passed/1 skipped; Product Integrity fresh full 1329 passed/1 skipped, 4 Golden Paths, and all hard checks passed with YELLOW only for the existing `tzdata` dependency and Defined FW-COMP/FW-AID owners. Product Integrity now reports FW-EVID Proven within its local unsigned DRY_RUN boundary.


### FW-HARNESS-017 — Bounded failure escalation and failure packets
- Requirement: FW-HARNESS deterministic repair/escalation control
- State: DONE
- Priority: P0
- Dependencies: FW-HARNESS-016 and FW-HARNESS-012
- Approval: metadata-only failure classification, escalation, and Evidence packets are authorized; repair/rollback execution and authority expansion remain unauthorized.
- Description: Classify repeated failures and scope/reviewer/security conditions into same-tier repair, tier escalation, block, or human escalation, and emit one bounded canonical Failure Packet.
- Target path: swarm/harness_failure.py
- Allowed paths: swarm/harness_failure.py, swarm/harness_risk.py, swarm/harness_recovery.py, tests/test_harness_failure.py, docs/fw-harness-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_failure.py tests/test_harness_risk.py tests/test_harness_recovery.py
- Acceptance criteria:
  - first ordinary failure permits at most one same-tier repair; repeated same error escalates one tier;
  - security/architecture findings, unexpected cross-subsystem impact, unknown security implications, scope escape, exhausted budgets, and T4 boundaries deterministically escalate or block;
  - model confidence and requested tier are advisory and cannot lower the outcome;
  - Failure Packet binds task/tier/attempts/models/validations/failures/files/diff/reviewer/escalation/evidence/recommended action with bounded redacted fields;
  - Evidence failure emits no packet and no repair/escalation admission;
  - no worker invocation, repair, rollback, Git/filesystem/process/network/deployment/credential/containment or authority mutation is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: escalation is deterministic metadata consumed by existing controllers and cannot grant a model additional capability.
- Completion evidence: exact candidate `9d196c4032da456d2d2274eecdd15e3a8d33ebf9`; focused 75 passed after closing every reviewer-requested boundary test; exact Claude review `phase2a-9d196c4032da456d2d2274ee` APPROVE/LOW with no blockers or missing tests; full 1421 passed/1 skipped; Product Integrity fresh full 1421 passed/1 skipped, all hard checks and 4 Golden Paths passed with only pre-existing `tzdata` and Defined FW-COMP/FW-AID YELLOW findings.


### FW-HARNESS-016 — Risk-bound approved model routing
- Requirement: FW-HARNESS Model Broker assurance integration
- State: DONE
- Priority: P0
- Dependencies: FW-HARNESS-015 and FW-HARNESS-011
- Approval: deterministic registry eligibility and routing metadata are authorized; provider activation and model invocation remain separately gated.
- Description: Bind an exact RiskDecision minimum tier into the existing Approved Model Registry admission so only same-or-higher assurance candidates can be selected, with equivalent failover and no vendor names in policy logic.
- Target path: swarm/harness_models.py
- Allowed paths: swarm/harness_models.py, swarm/harness_risk.py, tests/test_harness_models.py, tests/test_harness_risk.py, docs/fw-harness-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_models.py tests/test_harness_risk.py
- Acceptance criteria:
  - registry candidates declare capability tier, approved roles/data classes/tools, tenant and environment;
  - selection deterministically chooses the lowest-cost eligible approved candidate satisfying the risk tier and exact task constraints;
  - T4/human-required and denied decisions never select or invoke a model;
  - provider failure permits only an explicitly approved equivalent at the same or higher tier, never a silent downgrade;
  - no approved candidate returns NO_APPROVED_MODEL_AVAILABLE_FOR_REQUIRED_ASSURANCE_LEVEL;
  - model suggestions cannot alter risk, tier, registry approval, capabilities, budgets, or authority.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: Model Broker remains the model-eligibility owner; FW-HARNESS supplies deterministic assurance requirements and cannot approve models.
- Completion evidence: exact candidate `b647df6b8b78c5703da99909e247a03d21653ae1`; focused 65 passed; exact Claude review `phase2a-b647df6b8b78c5703da99909` APPROVE/LOW with no blockers or missing tests; full 1396 passed/1 skipped; Product Integrity fresh full 1396 passed/1 skipped, all hard checks and 4 Golden Paths passed with only pre-existing `tzdata` and Defined FW-COMP/FW-AID YELLOW findings.


### FW-HARNESS-015 — Deterministic risk classification and assurance tiers
- Requirement: FW-HARNESS deterministic task risk and routing assurance
- State: DONE
- Priority: P0
- Dependencies: FW-HARNESS-014
- Approval: deterministic classification metadata is authorized; model invocation, provider activation, and authority expansion are not.
- Description: Add policy-configured T0-T4 classification, security path/component and dangerous-capability promotion, and hard invariant denial before Model Broker selection.
- Target path: swarm/harness_risk.py
- Allowed paths: swarm/harness_risk.py, tests/test_harness_risk.py, docs/fw-harness-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_harness_risk.py
- Acceptance criteria:
  - configurable scoring and exact 0/20/40/60/80 boundaries assign T0-T4 deterministically;
  - security components/paths and dangerous capabilities impose minimum tiers independently of model suggestions;
  - self-authority expansion, Z3/ticket/tenant/Evidence/kill-switch/deployment/approval bypass and unrestricted host authority deny before model routing;
  - T4 records require human authorization and no eligible model is selected by the classifier;
  - unknown signals, malformed policy, tier downgrade requests, and cross-tenant facts fail closed;
  - output is immutable auditable metadata and grants no model, tool, Git, deployment, credential, network, filesystem, process, or response authority.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: classification is deterministic policy input to the existing Model Broker; no router LLM or model authorization is introduced.
- Completion evidence: exact candidate `dda243e755c4f21b565aca762d5f9cb949ec35df`; focused 32 passed; exact Claude review `phase2a-dda243e755c4f21b565aca76` APPROVE/LOW with no blockers or missing tests; full 1381 passed/1 skipped; Product Integrity fresh full 1381 passed/1 skipped, all hard checks and 4 Golden Paths passed with only pre-existing `tzdata` and Defined FW-COMP/FW-AID YELLOW findings.


### FW-INTEGRITY-001 — Machine-readable Core invariants and ownership drift gate
- Requirement: FW-INTEGRITY invariant enforcement and architecture drift prevention
- State: DONE
- Priority: P0
- Dependencies: FW-HARNESS-017 and FW-UX-001
- Approval: deterministic metadata and validation inside existing FW-ROOT/FW-INTEGRITY owners are authorized; no new policy language or authority is added.
- Description: Encode the approved project-wide AI authority and safety invariants as immutable machine-readable policy metadata and make Product Integrity fail closed on incomplete invariants or duplicate canonical implementations.
- Target path: swarm/policy_gate.py
- Allowed paths: swarm/policy_gate.py, swarm/integrity.py, tests/test_policy_gate.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_policy_gate.py tests/test_integrity.py
- Acceptance criteria:
  - stable invariant IDs bind existing owners, plain-language statements, and deterministic enforcement classes for self-authority, Z3/Action Tickets, tenancy, Evidence, kill switch/deployment, review, model assurance, MCP/tool authority, and monitoring separation;
  - the immutable manifest rejects malformed, duplicate, missing, or unversioned entries;
  - Product Integrity validates the manifest and canonical ownership registry on every run and treats validation failure as a hard failure;
  - duplicate canonical implementations and malformed ownership records fail closed without creating a competing registry;
  - no model, tool, Git, credential, network, deployment, containment, recovery, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: this milestone makes existing rules machine-consumable; domain controls remain the enforcement owners.
- Completion evidence: exact candidate `ace85ab00d187b4836826ad6a3ce8c532b209a6d`; focused 36 passed after adding every malformed invariant/ownership boundary requested by the prior review; exact Claude review `phase2a-ace85ab00d187b4836826ad6` returned APPROVE/LOW with no blockers or missing tests; full 1431 passed/1 skipped; Product Integrity fresh full 1431 passed/1 skipped, invariant and canonical-ownership checks plus 4 Golden Paths passed, with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-COMP/FW-AID owners.

### FW-UX-001 — Mission Control showcase foundation
- Requirement: FW-UX Mission Control and honest Demo Mode
- State: DONE
- Priority: P0
- Dependencies: FW-HARNESS-008, FW-AID-001, FW-SOC-03, and FW-EVID-006
- Approval: the project-wide Mission Control showcase directive authorizes a reusable read-only UI and explicitly labeled deterministic demo data; live backend activation and response execution remain unauthorized.
- Description: Replace the legacy operations overview with the first reusable ForgeWarden Mission Control experience backed by one bounded provider contract and the deterministic `DEMO-AI-RANSOM-001` scenario.
- Target path: swarm/mission_control_demo.py
- Allowed paths: swarm/mission_control_demo.py, swarm/console.py, console/index.html, console/app.js, console/styles.css, tests/test_console.py, docs/management-console.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_console.py tests/test_mission_control.py
- Acceptance criteria:
  - a single read-only provider snapshot identifies schema, DEMO mode, scenario, provenance, safety state, implementation status, posture, assets, incident, AI security, Harness, simulated actions, and Evidence preview;
  - `DEMO-AI-RANSOM-001` is deterministic and returned as a fresh projection, with production backend disconnected, mutation denied, deployment disabled, kill switch engaged, and no cryptographic verification claim;
  - Mission Control visibly presents the demo boundary plus posture, asset counts, one correlated AI/ransomware attack story, AI Defense, Harness lifecycle, actions, executive posture, and Evidence preview;
  - the browser client validates the provider envelope before rendering and escapes provider strings;
  - the existing dependency-free frontend and loopback read-only server remain canonical, with no package, external font, credential, network transport, deployment, containment, recovery, or response authority added.
- Expected validation: focused Linux proof, visual desktop/tablet inspection, exact independent read-only review, then full suite/integrity once.
- Security considerations: every showcased action and review is explicitly simulated; the demo provider cannot authorize, execute, attest, or write state.
- Completion evidence: exact candidate `d68b457590986e29d3403d935480a0c4ae8559ad`; focused 26 passed; desktop visual inspection confirmed demo, safety, posture, attack-story, Harness, simulated action, and Evidence labels; exact Claude review `phase2a-68b457590986e29d3403d935` returned APPROVE/LOW with no blockers or missing tests; full 1423 passed/1 skipped; Product Integrity fresh full 1423 passed/1 skipped and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-COMP/FW-AID owners.

### FW-REC-003 — Deterministic interruption and resume admission
- Requirement: FW-REC safe resume coordination
- State: DONE
- Priority: P0
- Dependencies: FW-REC-002
- Approval: metadata-only resume admission is authorized under D-024; executing resume or rollback remains unauthorized.
- Description: Deterministically classify an interruption against a reconstructed checkpoint and issue an immutable resume, block, or rollback-proposal admission record without invoking recovery.
- Target path: swarm/recovery.py
- Allowed paths: swarm/recovery.py, tests/test_recovery.py, docs/fw-rec-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_recovery.py
- Acceptance criteria:
  - classification binds exact checkpoint digest, tenant, task, current Git/Evidence facts, kill switch, authority freshness, validation/review state, and remaining budgets;
  - only a consistent resumable nonterminal stage may produce RESUME; unknown interruption, stale bindings, exhausted limits, failed gates, terminal state, or disengaged kill switch blocks or requires a rollback proposal;
  - admission records are immutable, bounded, tenant isolated, Evidence-first, and replay protected;
  - Evidence failure returns no admission and consumes no replay identifier;
  - no task execution, restore, rollback execution, restart, deletion, repair, Git mutation, containment, deployment, credential, network, filesystem, or process authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: resume admission is deterministic decision evidence consumed later by the trusted controller; it is not permission to perform recovery.
- Completion evidence: exact candidate `f94d24570bfe87fc1047bf31c761f05e35dfedcb`; focused 38 passed; exact Claude review `phase2a-f94d24570bfe87fc1047bf31` returned APPROVE/LOW with no blockers or missing tests; full 1449 passed/1 skipped; Product Integrity fresh full 1449 passed/1 skipped, invariant/ownership checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-COMP/FW-AID owners.

### FW-REC-004 — Integrated recovery checkpoint and resume lifecycle proof
- Requirement: FW-REC lifecycle acceptance
- State: DONE
- Priority: P0
- Dependencies: FW-REC-003 and FW-EVID-006
- Approval: deterministic local DRY_RUN lifecycle proof is authorized; recovery, rollback, restart, repair, containment, deletion, and deployment execution remain unauthorized.
- Description: Prove one tenant-bound lifecycle from immutable checkpoint creation through durable reconstruction, exact interruption admission, Evidence-first decision recording, safe retry after Evidence failure, and replay/stale/tamper denial.
- Target path: tests/test_recovery_lifecycle.py
- Allowed paths: swarm/recovery.py, tests/test_recovery.py, tests/test_recovery_lifecycle.py, docs/fw-rec-inventory.md, swarm/integrity.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_recovery.py tests/test_recovery_lifecycle.py tests/test_integrity.py
- Acceptance criteria:
  - one deterministic proof composes the canonical RecoveryCheckpoint, private atomic persistence, restart reconstruction, exact checkpoint digest, ResumeAdmission, and Evidence record;
  - only exact nonterminal safe state produces RESUME while terminal, exhausted, stale, cross-tenant, tampered, unknown, failed-gate, disengaged-kill-switch, and replay conditions fail closed or require a rollback proposal;
  - Evidence failure returns no admission, consumes no replay identifier, and permits a bounded retry only from the unchanged exact facts;
  - Product Integrity reports FW-REC Proven only within its local metadata-only DRY_RUN boundary;
  - no restore, rollback execution, process restart, deletion, repair, Git mutation, containment, deployment, credential, network, filesystem, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the proof validates coordination and denial semantics only; it cannot execute the decision it records.
- Completion evidence: exact candidate `037873cfc7b69a8cc2e3c5b7226369af79d85dda`; focused 51 passed; exact Claude review `phase2a-37873cfc7b69a8cc2e3c5b72` returned APPROVE/LOW with no blockers or missing tests; full 1452 passed/1 skipped; Product Integrity fresh full 1452 passed/1 skipped, invariant/ownership checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-COMP/FW-AID owners. Product Integrity now reports FW-REC Proven within its local metadata-only DRY_RUN boundary.

### FW-COMP-001 — Compliance ownership inventory and canonical control mapping contract
- Requirement: FW-COMP compliance ownership and control mapping
- State: DONE
- Priority: P0
- Dependencies: FW-REC-004 and FW-EVID-006
- Approval: read-only inventory and deterministic metadata-only mapping are authorized; certification claims, external reporting, control execution, and compliance authority remain unauthorized.
- Description: Inventory existing control, requirement, Evidence, policy, tenant, and implementation-status references and establish one canonical tenant-bound mapping contract that references existing owners without claiming compliance from documentation or demo state.
- Target path: docs/fw-comp-inventory.md
- Allowed paths: docs/fw-comp-inventory.md, swarm/compliance.py, swarm/integrity.py, tests/test_compliance.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_compliance.py tests/test_integrity.py
- Acceptance criteria:
  - inventory names canonical owners for requirements, controls, implementation status, policy decisions, Evidence, tenants, approvals, tests, and external-framework references;
  - immutable mapping metadata binds tenant, internal control ID, requirement IDs, owner, implementation status, evidence references, validation state, framework/control references, timestamp, and explicit claim status;
  - unknown fields, duplicate mappings, cross-tenant references, invalid status, missing Evidence, unsupported frameworks, secret-bearing text, and any claimed certification or enforcement authority fail closed;
  - mapping consumes existing FW-EVID and policy/status owners rather than creating a competing audit, policy, requirement, or certification system;
  - no compliance certification, external submission, credential, network, deployment, remediation, recovery, containment, filesystem/process, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: a control mapping is descriptive evidence metadata and never proves certification or authorizes an action by itself.

- Completion evidence: exact repaired candidate c7be16605726f1bcb289fbb06258018715b6128; focused 29 passed after adding all identifier-format boundaries named by the first review; exact Claude review phase2a-c7be16605726f1bcb289fbb0 returned APPROVE/LOW with no blockers or missing tests; full 1471 passed/1 skipped; Product Integrity fresh full 1471 passed/1 skipped, invariant/ownership checks and 4 Golden Paths passed with YELLOW only for the pre-existing 	zdata dependency and Defined FW-AID owner.

### FW-COMP-002 — Canonical compliance mapping Evidence adapter
- Requirement: FW-COMP lifecycle Evidence integration
- State: DONE
- Priority: P0
- Dependencies: FW-COMP-001 and FW-EVID-006
- Approval: deterministic metadata-only Evidence admission is authorized; certification, external reporting, control execution, and compliance authority remain unauthorized.
- Description: Bind an accepted canonical ControlMapping to the existing tenant Evidence ledger using a bounded lifecycle payload and exact mapping digest, without duplicating Evidence storage or treating mappings as proof of certification.
- Target path: swarm/compliance.py
- Allowed paths: swarm/compliance.py, tests/test_compliance.py, docs/fw-comp-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_compliance.py tests/test_evidence.py
- Acceptance criteria:
  - adapter revalidates the exact registered mapping and tenant before producing canonical FW-EVID input;
  - Evidence binds the mapping digest, internal control, requirement set, owner, validation state, claim status, and bounded framework references without raw narrative or secrets;
  - missing, stale, substituted, duplicate, replayed, cross-tenant, or durability-failed mappings deny admission without advancing state;
  - the existing FW-EVID ledger remains the sole Evidence owner;
  - no certification, external submission, credential, network, deployment, remediation, recovery, containment, filesystem/process, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: Evidence records that a mapping was admitted; it does not certify the mapped control or authorize execution.

- Completion evidence: exact candidate `eadc358389da26c487c5ce70f5e0a89add6638b0`; focused 68 passed; exact Claude review `phase2a-eadc358389da26c487c5ce70` returned APPROVE/LOW with no blockers or missing tests; full 1476 passed/1 skipped; Product Integrity fresh full 1476 passed/1 skipped, invariant/ownership checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-COMP/FW-AID ownership metadata.

### FW-COMP-003 — Evidence-backed control assessment observation contract
- Requirement: FW-COMP deterministic assessment observations
- State: DONE
- Priority: P0
- Dependencies: FW-COMP-002
- Approval: bounded metadata-only assessment observations are authorized; certification, attestation, external reporting, control execution, and compliance authority remain unauthorized.
- Description: Define immutable tenant-bound observations that reference an exact admitted mapping and canonical Evidence/test/policy facts, with explicit observed/not-observed outcomes and expiry, without converting observations into certification claims.
- Target path: swarm/compliance.py
- Allowed paths: swarm/compliance.py, tests/test_compliance.py, docs/fw-comp-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_compliance.py tests/test_evidence.py
- Acceptance criteria:
  - observation binds exact mapping digest, tenant, control, assessor identity, observation type/outcome, canonical Evidence references, policy/test references, observed time, and expiry;
  - missing/stale mappings, cross-tenant facts, unsupported outcomes, expired observations, replay, secret-bearing values, and claimed certification or authority fail closed;
  - observations remain descriptive inputs and cannot mutate mappings, policy, Evidence, validation results, or implementation status;
  - no certification, external submission, credential, network, deployment, remediation, recovery, containment, filesystem/process, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: an observation records bounded facts at a point in time and never proves continuous compliance or authorizes an action.

- Completion evidence: exact candidate `b7f7b785f2de6b1a27fbceb1f2bc952728cc4bef`; focused proof passed 86 tests after one bounded test correction; exact Claude review `phase2a-b7f7b785f2de6b1a27fbceb1` returned APPROVE/LOW with no blockers or missing tests; full 1494 passed/1 skipped; Product Integrity fresh full 1494 passed/1 skipped, invariant/ownership checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-COMP/FW-AID ownership metadata.

### FW-COMP-004 — Integrated compliance mapping and assessment lifecycle proof
- Requirement: FW-COMP integrated lifecycle proof
- State: DONE
- Priority: P0
- Dependencies: FW-COMP-003
- Approval: deterministic metadata-only lifecycle composition and honest integrity status are authorized; certification, external reporting, control execution, and compliance authority remain unauthorized.
- Description: Prove one deterministic tenant lifecycle from canonical control mapping through FW-EVID admission and bounded assessment observation, including replay, substitution, expiry, cross-tenant, and durability failure, then report FW-COMP honestly in Product Integrity.
- Target path: tests/test_compliance.py
- Allowed paths: swarm/compliance.py, swarm/integrity.py, tests/test_compliance.py, tests/test_integrity.py, docs/fw-comp-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_compliance.py tests/test_integrity.py tests/test_evidence.py
- Acceptance criteria:
  - one integrated proof composes the canonical mapping registry, canonical FW-EVID ledger adapter, and assessment registry without alternate owners;
  - mapping, Evidence record, and observation retain exact tenant/control/digest/reference bindings through the lifecycle;
  - replay, stale/substituted mapping, cross-tenant input, expiry, and durability failure fail closed without advancing protected state;
  - Product Integrity reports FW-COMP Proven only within the explicit local metadata-only DRY_RUN boundary;
  - no certification, external submission, credential, network, deployment, remediation, recovery, containment, filesystem/process, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: lifecycle proof establishes deterministic metadata integrity only; it is not a compliance certification or control effectiveness attestation.

- Completion evidence: exact candidate `602507c85dd075c0444c3a1f26e3d22363c5034d`; focused 97 passed; exact Claude review `phase2a-602507c85dd075c0444c3a1f` returned APPROVE/LOW with no blockers or missing tests; full 1495 passed/1 skipped; Product Integrity fresh full 1495 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-AID owner. Product Integrity now reports FW-COMP Proven within its explicit local metadata-only DRY_RUN boundary.

### FW-AID-002 — Canonical AI workload security telemetry contract
- Requirement: FW-AID privacy-minimized normalized telemetry
- State: DONE
- Priority: P0
- Dependencies: FW-AID-001, FW-ID, FW-KEYS, FW-EVID, FW-HARNESS-014
- Approval: fixture-only normalized AI security event contracts and deterministic validation are authorized under D-025; live sensors, hooks, transport, containment, and response remain unauthorized.
- Description: Extend the canonical normalized-event boundary with a bounded tenant/agent/model/task/capability/tool/MCP/resource/policy telemetry contract for AI workloads, retaining identifiers, hashes, classifications, and denials while excluding prompts, secrets, raw content, credentials, and unrestricted command data.
- Target path: swarm/normalized_events.py
- Allowed paths: swarm/normalized_events.py, tests/test_normalized_events.py, tests/test_fw_aid.py, docs/fw-aid-architecture.md, docs/fw-endpoint-sensor-contract.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_normalized_events.py tests/test_fw_aid.py
- Acceptance criteria:
  - canonical event binds tenant, agent/model/session/task identities, declared purpose hash, capability lease and Action Ticket references, tool/MCP/resource category, decision, anomaly indicators, event time, and bounded Evidence references;
  - unknown fields, raw prompts/content/commands, secret-bearing values, cross-tenant references, unapproved event classes, malformed hashes, oversized collections, duplicates, and replay fail closed;
  - the existing NormalizedEventStore remains the sole normalized-event owner and admits AI workload events without adding a parallel telemetry store;
  - no live collection, authentication, credential access, network/process/filesystem hook, containment, quarantine, remediation, recovery execution, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: telemetry is untrusted fixture input and descriptive evidence; it cannot grant capability or trigger an action by itself.

- Completion evidence: exact candidate `239069eaf02b9df127060f851243348ef899145b`; focused 50 passed; exact Claude review `phase2a-239069eaf02b9df127060f85` returned APPROVE/LOW with no blockers or missing tests; full 1517 passed/1 skipped; Product Integrity fresh full 1517 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and Defined FW-AID owner.

### FW-AID-003 — Deterministic AI threat classification
- Requirement: FW-AID closed-rule threat detection
- State: DONE
- Priority: P0
- Dependencies: FW-AID-002
- Approval: deterministic fixture-only classification and Evidence-first findings are authorized under D-025; model self-assessment, live collection, containment, and response remain unauthorized.
- Description: Classify canonical AI workload telemetry into the ten registered FW-AID threat classes using closed deterministic rules, bounded severity/confidence inputs, and explicit matched-fact references without relying on model judgment.
- Target path: swarm/ai_agent_defense.py
- Allowed paths: swarm/ai_agent_defense.py, swarm/normalized_events.py, tests/test_fw_aid.py, docs/fw-aid-architecture.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_fw_aid.py tests/test_normalized_events.py
- Acceptance criteria:
  - classifier covers all ten registered threat classes from canonical enum/fact combinations and produces immutable tenant/event-bound DETECT_ONLY findings;
  - severity/confidence are policy-bounded metadata and cannot authorize containment or change the source event;
  - unknown rules, conflicting/insufficient facts, cross-tenant input, replay, malformed values, and Evidence failure fail closed without admitting a finding;
  - classification uses closed deterministic rules and never trusts a model's self-reported safety, risk, or authority;
  - no live sensor, model call, credential, network/process/filesystem hook, containment, quarantine, remediation, recovery execution, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: findings are advisory policy inputs and Evidence; deterministic policy remains the sole action authority.

- Completion evidence: exact candidate `e62de434510351338ecadf00f46357865e4bdbb7`; focused 66 passed; exact Claude review `phase2a-e62de434510351338ecadf00` returned APPROVE/LOW with no blockers or missing tests; full 1533 passed/1 skipped; Product Integrity fresh full 1533 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and partial FW-AID ownership status.

### FW-AID-004 — Governed harness monitoring adapter
- Requirement: FW-AID protection for ForgeWarden's AI development harness
- State: DONE
- Priority: P0
- Dependencies: FW-AID-003 and FW-HARNESS-014
- Approval: fixture-only conversion of existing harness lifecycle facts into canonical FW-AID telemetry is authorized; live hooks, interception, containment, and response remain unauthorized.
- Description: Deterministically translate existing sanitized harness lifecycle records for worker/reviewer identity, model, task, context hash, leases/tickets, tools, path/Git scope, denials, budgets, coordination, and manipulation indicators into canonical AI workload security events without letting the harness control its monitor.
- Target path: swarm/ai_agent_defense.py
- Allowed paths: swarm/ai_agent_defense.py, swarm/harness_evidence.py, swarm/normalized_events.py, tests/test_fw_aid.py, tests/test_harness_evidence.py, docs/fw-aid-architecture.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_fw_aid.py tests/test_harness_evidence.py tests/test_normalized_events.py
- Acceptance criteria:
  - adapter consumes already-validated sanitized harness facts and emits exact tenant/agent/model/session/task/context/capability/tool/path/Git/denial/budget/reviewer indicators through the canonical NormalizedEventStore;
  - suspicious permission expansion, secret access, unexpected MCP/tool/model/path/Git activity, coordination, reviewer manipulation, Evidence tampering, and test manipulation map to closed FW-AID indicators without model judgment;
  - missing bindings, raw output/prompt/command data, cross-tenant facts, unknown fields, replay, malformed hashes, and Evidence failure fail closed;
  - adapter cannot mutate harness tasks, leases, Git, policy, review, Evidence history, monitoring state, or kill-switch state;
  - no live hook, model call, credential, filesystem/process/network access, containment, remediation, recovery execution, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the harness supplies untrusted observations; the separately owned deterministic FW-AID adapter and event store validate them.

- Completion evidence: exact candidate `5ede6beece0707973b4f018a92ebd3553bee7609`; focused 94 passed after one bounded import/test correction; exact Claude review `phase2a-5ede6beece0707973b4f018a` returned APPROVE/LOW with no blockers or missing tests; full 1536 passed/1 skipped; Product Integrity fresh full 1536 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and partial FW-AID ownership status.

### FW-AID-005 — Cross-domain AI intrusion correlation and attack story
- Requirement: FW-AID canonical cross-domain correlation
- State: DONE
- Priority: P0
- Dependencies: FW-AID-004, FW-SOC-03, FW-AV, FW-ENDPOINT, FW-ID, FW-MCP
- Approval: deterministic fixture-only correlation and inert attack-story projection are authorized; live collection, containment, and response remain unauthorized.
- Description: Correlate canonical FW-AID findings with existing endpoint, AV, identity, browser/email, MCP, and network fact references into one tenant-bound immutable FW-SOC attack story without duplicating event or incident ownership.
- Target path: swarm/ai_agent_defense.py
- Allowed paths: swarm/ai_agent_defense.py, swarm/soc.py, swarm/normalized_events.py, tests/test_fw_aid.py, tests/test_soc.py, docs/fw-aid-architecture.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_fw_aid.py tests/test_soc.py tests/test_normalized_events.py
- Acceptance criteria:
  - correlation binds one tenant, AI finding/event, agent/task/model, and bounded AV/endpoint/identity/browser-email/MCP/network references in deterministic chronological order;
  - defined high-confidence combinations produce an inert severity/risk story while baseline deviation alone remains insufficient;
  - missing domains, duplicate/replayed facts, cross-tenant references, inconsistent chronology, malformed values, and Evidence failure fail closed without incident admission;
  - existing NormalizedEventStore and FW-SOC projection remain canonical owners; no parallel event, risk, or case store is created;
  - no live sensor, model call, credential, network/process/filesystem hook, containment, quarantine, remediation, recovery execution, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the attack story is an Evidence-backed correlation result and advisory policy input, never an authorization to act.

- Completion evidence: exact candidate `49743ac430e24a6518e0a8e81f0fa99a2f976472`; focused 122 passed after bounded test corrections; exact Claude review `phase2a-49743ac430e24a6518e0a8e8` returned APPROVE/LOW with no blockers or missing tests; full 1539 passed/1 skipped; Product Integrity fresh full 1539 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and partial FW-AID ownership status.

### FW-AID-006 — Deterministic containment proposal and policy contract
- Requirement: FW-AID inert containment policy input
- State: DONE
- Priority: P0
- Dependencies: FW-AID-005, FW-ROOT/Z3, Action Tickets, FW-REC
- Approval: deterministic PROPOSE_ONLY containment metadata and policy-input validation are authorized; containment execution, revocation, isolation, quarantine, and response remain unauthorized.
- Description: Map exact accepted FW-AID findings and attack stories to bounded inert containment proposal classes with required policy, lease, Action Ticket, approval, blast-radius, Evidence, checkpoint, and recovery references while executing nothing.
- Target path: swarm/ai_agent_defense.py
- Allowed paths: swarm/ai_agent_defense.py, swarm/policy_gate.py, swarm/soc.py, tests/test_fw_aid.py, tests/test_policy_gate.py, docs/fw-aid-architecture.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_fw_aid.py tests/test_policy_gate.py tests/test_soc.py
- Acceptance criteria:
  - closed severity/threat policy maps to supported proposal classes and exact target/blast-radius bounds;
  - mutating proposals require tenant-matched policy decision, short lease, single-use Action Ticket, approval, checkpoint, rollback/recovery, and Evidence references;
  - AI self-containment lifting, policy bypass, kill-switch clearing, authority expansion, unsupported action, missing/stale/substituted references, cross-tenant input, replay, and Evidence failure fail closed;
  - every result remains immutable DRY_RUN/PROPOSE_ONLY with deployment disabled and no execution callback;
  - no credential, live network/process/filesystem control, containment, quarantine, remediation, recovery execution, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the proposal is advisory metadata; canonical deterministic policy and authorized executors remain the only action boundary.

- Completion evidence: exact candidate `63ca1c903590a212c750ea7bb3261e0e0bf10473`; focused 137 passed; exact Claude review `phase2a-63ca1c903590a212c750ea7b` returned APPROVE/LOW with no blockers or missing tests; full 1556 passed/1 skipped; Product Integrity fresh full 1556 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and partial FW-AID ownership status.

### FW-AID-007 — Mission Control AI Security projection
- Requirement: FW-AID operator-visible read-only state
- State: DONE
- Priority: P0
- Dependencies: FW-AID-006 and FW-UX-001
- Approval: sanitized read-only Mission Control projections and clearly labeled demo fixtures are authorized; control mutation, live telemetry, containment, and response remain unauthorized.
- Description: Project canonical FW-AID agent telemetry, findings, attack stories, denied actions, and containment proposals into a bounded tenant-filtered AI Security view that clearly distinguishes demo/fixture data and exposes no secrets or control callbacks.
- Target path: swarm/mission_control.py
- Allowed paths: swarm/mission_control.py, swarm/mission_control_demo.py, tests/test_mission_control.py, tests/test_fw_aid.py, docs/fw-aid-architecture.md, docs/management-console.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_mission_control.py tests/test_fw_aid.py
- Acceptance criteria:
  - projection shows agent/model/task, current scoped authority references, risk/threat, anomalies, denials, MCP/tool category, related incident/story/Evidence, containment proposal state, and kill-switch state;
  - tenant filtering, bounded collections, deterministic ordering, sensitive-field exclusion, and DEMO/SIMULATED labels fail closed on malformed input;
  - view is immutable/read-only and cannot approve, revoke, isolate, execute, clear kill switch, change policy, or mutate source state;
  - existing Mission Control and canonical FW-AID/FW-SOC owners are reused without a parallel operational store;
  - no live sensor, credential, network/process/filesystem access, containment, remediation, recovery execution, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: operator visibility consumes sanitized canonical facts and does not become an action surface.

- Completion evidence: repaired exact candidate `731bb5bf65a309b5b70ca4336896879baad13b43`; focused 82 passed after fixing the prior review's legitimate optional-proposal set-union defect; exact Claude review `phase2a-731bb5bf65a309b5b70ca433` returned APPROVE/LOW with no blockers or missing tests; full 1561 passed/1 skipped; Product Integrity fresh full 1561 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing `tzdata` dependency and partial FW-AID ownership status.

### FW-AID-008 — Dedicated adversarial simulation suite
- Requirement: FW-AID safe adversarial validation
- State: DONE
- Priority: P0
- Dependencies: FW-AID-007
- Approval: inert fixture simulations across existing FW-AID contracts are authorized; real exploit execution, live sensors, containment, and response remain unauthorized.
- Description: Add a dedicated deterministic adversarial suite covering prompt injection, poisoned retrieval, credential discovery/exfiltration, egress, lateral movement, sandbox escape, privilege expansion, unauthorized MCP/shell, EDR/Evidence/log tampering, unapproved coordination, test/reviewer manipulation, policy bypass, self-authority, and kill-switch clearing through the canonical telemetry/detection/correlation/proposal boundaries.
- Target path: tests/test_fw_aid_adversarial.py
- Allowed paths: tests/test_fw_aid_adversarial.py, tests/fixtures/fw_aid/, swarm/ai_agent_defense.py, swarm/normalized_events.py, docs/fw-aid-architecture.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_fw_aid_adversarial.py tests/test_fw_aid.py
- Acceptance criteria:
  - safe deterministic fixtures cover every required attack class and verify normalization, detection, Evidence ordering, tenant isolation, replay denial, bounded resources, and inert proposal output;
  - attempts to self-authorize, weaken policy/tests/review, access secrets, escape scope, cross tenants, disable monitoring/Evidence, clear kill switch, activate deployment, or execute containment fail closed;
  - simulations use references/hashes and never execute commands, access credentials, contact networks, mutate hosts, or perform containment;
  - failures identify the exact denied invariant and do not game or weaken existing tests;
  - no live sensor, exploit, credential, network/process/filesystem access, containment, remediation, recovery execution, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: adversarial inputs are inert metadata fixtures and cannot become executable instructions or authority.
- Completion evidence: exact candidate `906f98b28c8cbf63832d359a6f4d117e665aa1ee`; focused 89 passed; exact Claude review `phase2a-906f98b28c8cbf63832d359a` APPROVE/LOW with no blockers or missing tests; full 1589 passed/1 skipped; Product Integrity fresh full 1589 passed/1 skipped, all hard checks and 4 Golden Paths passed with YELLOW only for the pre-existing dependency and partial FW-AID ownership status.

### FW-AID-009 — Endpoint and MicroSensor AI attribution adapter
- Requirement: FW-AID endpoint correlation contract
- State: REVIEW
- Priority: P0
- Dependencies: FW-AID-008
- Approval: caller-supplied fixture attribution and deterministic correlation are authorized; live collection and response remain unauthorized.
- Description: Add versioned, tenant-bound AI workload attribution fields to the existing endpoint fixture boundary and correlate them with canonical FW-AID events without creating a second event store.
- Target path: swarm/endpoint_adapter.py
- Allowed paths: swarm/endpoint_adapter.py, swarm/normalized_events.py, swarm/ai_agent_defense.py, tests/test_endpoint_adapter.py, tests/test_fw_aid.py, docs/fw-aid-architecture.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_endpoint_adapter.py tests/test_fw_aid.py
- Acceptance criteria:
  - bounded caller-supplied fixtures bind endpoint activity to opaque agent, session, task, capability-lease, and Action Ticket references;
  - tenant, schema, replay, chronology, and Evidence failures fail closed;
  - correlation reuses NormalizedEventStore and FW-AID classifiers and stores no prompt, command, credential, or secret material;
  - no live collection, sensor hook, filesystem/process/network access, containment, remediation, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: adapter input is inert caller-supplied metadata and cannot grant authority or execute endpoint actions.

### FW-REC-002 — Durable recovery checkpoint persistence and reconstruction
- Requirement: FW-REC persistent recovery metadata
- State: DONE
- Priority: P0
- Dependencies: FW-REC-001
- Approval: bounded local DRY_RUN persistence is authorized under D-024; recovery execution remains unauthorized.
- Description: Persist and reconstruct the canonical RecoveryCheckpoint through one bounded atomic local store that detects corruption, truncation, replay, symlink paths, and stale Evidence/Git bindings without performing recovery.
- Target path: swarm/recovery.py
- Allowed paths: swarm/recovery.py, tests/test_recovery.py, docs/fw-rec-inventory.md, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_recovery.py
- Acceptance criteria:
  - atomic restricted-permission checkpoint replacement with an exact schema/version/content digest;
  - restart reconstruction revalidates the complete canonical contract before returning state;
  - corrupt, truncated, oversized, symlinked, replayed, stale Git/Evidence, and cross-tenant records fail closed;
  - persistence failure never reports a successful checkpoint;
  - no restore, rollback execution, restart, deletion, repair, Git mutation, containment, deployment, credential, network, or process authority is added.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: the store contains bounded metadata and opaque references only; it cannot execute the recorded resume decision.
- Completion evidence: exact candidate `70b881390e8f7aeb204a09098cbdfbba22579440`; focused 20 passed; exact Claude review `phase2a-70b881390e8f7aeb204a0909` APPROVE/LOW with no blockers or missing tests; full 1349 passed/1 skipped; Product Integrity fresh full 1349 passed/1 skipped, all hard checks and 4 Golden Paths passed with only pre-existing `tzdata` and Defined FW-COMP/FW-AID YELLOW findings.


### FW-REC-001 — Recovery ownership inventory and canonical checkpoint contract
- Requirement: FW-REC recovery and rollback coordination
- State: DONE
- Priority: P0
- Dependencies: FWQ-0079
- Approval: deterministic metadata-only recovery/checkpoint contract is activated under D-024; restore, rollback mutation, process restart, deletion, repair, containment, and deployment remain unauthorized.
- Description: Inventory existing recovery, resume, checkpoint, worktree, Evidence, and rollback-proposal owners and establish one immutable tenant/task/stage checkpoint contract without replacing their implementations.
- Target path: swarm/recovery.py
- Allowed paths: swarm/recovery.py, swarm/autonomous_loop.py, swarm/work_checkpoint.py, swarm/harness_recovery.py, swarm/evidence.py, tests/test_recovery.py, tests/test_autonomous_loop.py, tests/test_work_checkpoint.py, tests/test_harness_recovery.py, docs/fw-rec-inventory.md, swarm/integrity.py, tests/test_integrity.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_recovery.py tests/test_autonomous_loop.py tests/test_work_checkpoint.py tests/test_harness_recovery.py tests/test_integrity.py
- Acceptance criteria:
  - inventory names the canonical owners for task state, stage checkpoints, Git/worktree state, Evidence, accepted commit, retry/budget state, interruption classification, rollback proposals, and operator decisions;
  - one exact immutable contract binds tenant, task, requirement, stage, starting/current commit, changed-file digest, validation/review status, consumed authority references, budget/retry counters, Evidence tail, timestamp, and safe resume decision;
  - unknown fields, malformed timestamps/hashes, cross-tenant references, impossible stage/state combinations, stale authority, secret-shaped input, and any claimed recovery execution authority fail closed;
  - the contract contains no method that restores, rolls back, restarts, deletes, repairs, deploys, contains, or mutates Git/files/processes;
  - existing autonomous-loop, work-checkpoint, harness-recovery, quarantine-recovery, and domain recovery owners remain authoritative through documented adapters.
- Expected validation: focused Linux proof, exact independent read-only review, then full suite/integrity once.
- Security considerations: FW-REC-001 is metadata and decision evidence only; later bounded milestones may coordinate existing recovery mechanisms but cannot execute response without separate authority.

- Completion evidence: exact candidate `4ffa96f611f5588850922d821ae0047699a94c76`; focused recovery validation 133 passed and verifier repair validation 20 passed; exact Claude review `phase2a-4ffa96f611f5588850922d82` APPROVE/LOW with no blockers or missing tests; full suite 1343 passed/1 skipped; Product Integrity repeated the full 1343/1 proof, all hard checks and 4 Golden Paths passed, with only pre-existing `tzdata` and Defined FW-COMP/FW-AID YELLOW findings.

### FW-BME-02 — Deterministic phishing and spoof classification
- Requirement: FW-BME phishing/BEC/authentication signal evaluation
- State: DONE
- Priority: P0
- Dependencies: FW-BME-01
- Approval: FW-BME is active under D-022.
- Description: Evaluate bounded normalized browser/email observations for exact phishing, lookalike, BEC, QR-phishing, redirect, and SPF/DKIM/DMARC failure combinations, with Evidence-first warn-only findings.
- Target path: swarm/browser_email.py
- Allowed paths: swarm/browser_email.py, tests/test_browser_email.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_browser_email.py
- Acceptance criteria:
  - deterministic exact-token classification with explicit LOW/MEDIUM/HIGH confidence;
  - authentication-result combinations apply only to email observations;
  - every finding recommends WARN and none executes link blocking, message movement, account action, or containment;
  - tenant binding and immutable untrusted observation state remain enforced;
  - Evidence failure denies findings and no browser/mailbox/network/credential authority is added.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: signals and content remain caller-supplied untrusted data; confidence grants no authority.
- Completion evidence: exact candidate `87a2d15f29504679d35b7c84f4c7e6a940f1dfd9`; focused 21 passed; Claude APPROVE/LOW with no blockers/missing tests; full 918 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-bme-02-claude-review.json`, `docs/fw-bme-02-integrity.json`.

### FW-BME-01 — Bounded browser/email fixture normalization
- Requirement: FW-BME caller-supplied browser and email metadata boundary
- State: DONE
- Priority: P0
- Dependencies: FW-MCP-05
- Approval: FW-BME follows completed FW-MCP under D-022.
- Description: Normalize bounded caller-supplied browser-navigation and email-message/link fixtures into immutable tenant-bound observations after Evidence succeeds, without accessing browsers, mailboxes, DNS, HTTP, files, or endpoints.
- Target path: swarm/browser_email.py
- Allowed paths: swarm/browser_email.py, tests/test_browser_email.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_browser_email.py
- Acceptance criteria:
  - strict fixture schema, source/event-type allow-list, size/depth/count limits, and exact tenant binding;
  - URLs, senders, authentication results, and indicators remain caller-supplied untrusted data;
  - deterministic immutable output and Evidence before return;
  - malformed/cross-tenant/oversized/Evidence-failure inputs deny safely;
  - outputs remain DRY_RUN/DETECT_ONLY with no browser, email, network, credential, filesystem, or response authority.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: fixture content may contain prompt injection and cannot become instructions or authority.
- Completion evidence: exact candidate `dea7ca0d90924888556783aa3b3e98c1615ce324`; focused 11 passed; Claude APPROVE/LOW with no blockers/missing tests; full 908 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-bme-01-claude-review.json`, `docs/fw-bme-01-integrity.json`.

### FW-MCP-05 — Fail-closed MCP health and kill-switch admission
- Requirement: FW-MCP gateway health and kill-switch enforcement
- State: DONE
- Priority: P0
- Dependencies: FW-MCP-04
- Approval: FW-MCP is active under D-022.
- Description: Add optional strict dry-run admission prerequisites that require explicit healthy gateway state and the safety kill switch to remain engaged, without adding tool execution or state-changing control surfaces.
- Target path: swarm/mcp_gateway.py
- Allowed paths: swarm/mcp_gateway.py, tests/test_mcp_gateway.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_mcp_gateway.py tests/test_asoc.py
- Acceptance criteria:
  - strict mode admits only when health is HEALTHY and kill switch is ENGAGED;
  - unhealthy, unknown, malformed, or disengaged states deny before Evidence/quota/request-ID mutation;
  - existing compatibility mode remains unchanged;
  - state is caller-supplied immutable configuration, not a gateway authority control;
  - no tool connection/execution, transport, credentials, filesystem, shell, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: health metadata cannot clear the kill switch or grant tool authority.
- Completion evidence: exact candidate `ef5dec5a97888ab1b325c208eea85e54cb0505da`; focused 148 passed; Claude APPROVE/LOW with no blockers/missing tests; full 897 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-mcp-05-claude-review.json`, `docs/fw-mcp-05-integrity.json`.

### FW-MCP-04 — Tenant-bound MCP tool catalog and discovery
- Requirement: FW-MCP registry, discovery, and trust levels
- State: DONE
- Priority: P0
- Dependencies: FW-MCP-03
- Approval: FW-MCP is active under D-022.
- Description: Add a bounded in-memory catalog of exact tenant-owned MCP tool metadata with explicit trust levels and deterministic read-only discovery, without connecting to or invoking tools.
- Target path: swarm/mcp_gateway.py
- Allowed paths: swarm/mcp_gateway.py, tests/test_mcp_gateway.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_mcp_gateway.py tests/test_asoc.py
- Acceptance criteria:
  - catalog entries bind exact tenant, tool, capability, trust level, and enabled state;
  - registration and discovery are bounded, deterministic, duplicate-safe, and tenant isolated;
  - disabled/untrusted entries cannot satisfy admission preconditions;
  - Evidence failure denies catalog mutation;
  - no tool connection, invocation, transport, credential, filesystem, shell, deployment, or response authority is added.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: catalog metadata is untrusted configuration and cannot grant authority by itself.
- Completion evidence: exact candidate `dd2cad59ede185a4f8eeac3ac7d7f6ee486329bc`; focused 139 passed; Claude APPROVE/LOW with no blockers/missing tests after provider reset; full 888 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-mcp-04-claude-review.json`, `docs/fw-mcp-04-integrity.json`.

### FW-MCP-03 — Bounded untrusted MCP result envelope
- Requirement: FW-MCP output sanitization and Evidence
- State: DONE
- Priority: P0
- Dependencies: FW-MCP-02
- Approval: FW-MCP is active under D-022.
- Description: Validate and wrap caller-supplied MCP tool-result data in a bounded immutable untrusted-data envelope, with exact request/admission binding and Evidence before return.
- Target path: swarm/mcp_gateway.py
- Allowed paths: swarm/mcp_gateway.py, tests/test_mcp_gateway.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_mcp_gateway.py tests/test_asoc.py
- Acceptance criteria:
  - only results for an exact admitted request can be wrapped once;
  - payload size, shape, depth, keys, strings and collection counts are bounded;
  - result content remains explicitly untrusted data and cannot become instructions or authority;
  - replay, mismatch, malformed data, or Evidence failure denies safely;
  - no tool invocation, network transport, credentials, filesystem, shell, or response authority is added.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: MCP output may contain prompt injection; the envelope never interprets or executes it.
- Completion evidence: exact candidate `ed8b0a915b9ff8f1a3c85507066595afd79b171d`; focused 130 passed; Claude APPROVE/LOW with no blockers/missing tests; full 879 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-mcp-03-claude-review.json`, `docs/fw-mcp-03-integrity.json`.

### FW-MCP-02 — Bounded MCP admission budgets
- Requirement: FW-MCP gateway resource limits
- State: DONE
- Priority: P0
- Dependencies: FW-MCP-01
- Approval: FW-MCP is active under D-022.
- Description: Apply a deterministic bounded admission budget per exact tenant/agent/tool scope inside the canonical MCPGateway, without invoking tools or adding transport.
- Target path: swarm/mcp_gateway.py
- Allowed paths: swarm/mcp_gateway.py, tests/test_mcp_gateway.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_mcp_gateway.py tests/test_asoc.py
- Acceptance criteria:
  - configured limits are positive, bounded, and deny safely when exhausted;
  - budgets are isolated by exact tenant, agent, and tool;
  - denied and Evidence-failed requests do not consume quota or request IDs;
  - concurrent admission cannot exceed the configured limit;
  - no tool execution, transport, credentials, or response authority is added.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: admission budgets are deterministic resource controls, not grants or authority.
- Completion evidence: exact candidate `a6d1232e841861b41da00c49b95c82ef6ffe6c5e`; focused 119 passed; Claude APPROVE/LOW with no blockers/missing tests; full 868 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-mcp-02-claude-review.json`, `docs/fw-mcp-02-integrity.json`.

### FW-MCP-01 — Replay-protected exact tool-request admission
- Requirement: FW-MCP canonical gateway request admission
- State: DONE
- Priority: P0
- Dependencies: FW-RANSOM-05 and existing MCPGateway grant registry
- Approval: FW-MCP follows completed FW-RANSOM under D-022.
- Description: Add a bounded request-ID admission path to the existing canonical MCPGateway that checks exact tenant/agent/capability/resource/tool/policy grants, rejects replay, and writes Evidence before recording admission.
- Target path: swarm/mcp_gateway.py
- Allowed paths: swarm/mcp_gateway.py, tests/test_mcp_gateway.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_mcp_gateway.py tests/test_asoc.py
- Acceptance criteria:
  - exact grant matching remains deny-by-default with no wildcards;
  - request IDs are bounded and single-use, including concurrent replay;
  - denied/revoked/cross-tenant requests never become admitted;
  - Evidence failure denies and does not consume the request ID;
  - no tool execution, network transport, credentials, filesystem, shell, or response authority is added.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: MCP request metadata and tool output remain untrusted; admission is policy evidence, not execution authority.
- Completion evidence: exact candidate `87dda89c410ec0d563719476b7564a833b1c7177`; focused 110 passed; Claude APPROVE/LOW with no blockers/missing tests; full 859 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-mcp-01-claude-review.json`, `docs/fw-mcp-01-integrity.json`.

### FW-RANSOM-05 — Defensive-control tamper signal correlation
- Requirement: FW-RANSOM deterministic credential/service/recovery tamper detection
- State: DONE
- Priority: P0
- Dependencies: FW-RANSOM-04
- Approval: FW-RANSOM is active first under D-022.
- Description: Extend the bounded activity evaluator with exact credential, service, and shadow-copy tamper indicators while preserving deterministic confidence and warn/proposal policy.
- Target path: swarm/ransomware.py
- Allowed paths: swarm/ransomware.py, tests/test_ransomware.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_ransomware.py
- Acceptance criteria:
  - exact canonical tamper tokens only, with noncanonical case ignored;
  - two distinct tamper signals produce a bounded finding without requiring filesystem or process inspection;
  - every finding warns and isolation remains only a recommendation at HIGH confidence;
  - Evidence failure denies output and DRY_RUN/DETECT_ONLY remains fixed.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: indicators are caller-supplied untrusted data and cannot authorize response.
- Completion evidence: exact candidate `05e7b34b0cadd28d58adc094b1c9264f50276f42`; focused 20 passed; Claude APPROVE/LOW with no blockers/missing tests; full 853 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-ransom-05-claude-review.json`, `docs/fw-ransom-05-integrity.json`.

### FW-RANSOM-04 — Bounded SMB propagation correlation
- Requirement: FW-RANSOM deterministic lateral-propagation signal
- State: DONE
- Priority: P0
- Dependencies: FW-RANSOM-03
- Approval: FW-RANSOM is active first under D-022.
- Description: Correlate a bounded caller-supplied tenant event window across devices for exact SMB propagation indicators, with deterministic Evidence-first warn-only findings.
- Target path: swarm/ransomware.py
- Allowed paths: swarm/ransomware.py, tests/test_ransomware.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_ransomware.py
- Acceptance criteria:
  - one tenant only, bounded events/devices/window, deterministic ordering;
  - exact SMB and lateral-movement tokens only;
  - duplicate, cross-tenant, malformed, over-limit and Evidence-failure paths deny safely;
  - no network access, containment, or response behavior;
  - outputs remain DRY_RUN/DETECT_ONLY and recommend WARN only.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: event metadata is caller-supplied untrusted data; correlation grants no response authority.
- Completion evidence: exact candidate `7c28fedfa04e925c47c305ab4c1cb4b6a30ed65b`; focused 18 passed; Claude APPROVE/LOW with no blockers/missing tests; full 851 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-ransom-04-claude-review.json`, `docs/fw-ransom-04-integrity.json`.

### FW-RANSOM-03 — Bounded ransomware canary registry and touch detection
- Requirement: FW-RANSOM deterministic canary signal
- State: DONE
- Priority: P0
- Dependencies: FW-RANSOM-02
- Approval: FW-RANSOM is active first under D-022.
- Description: Register bounded caller-supplied tenant/device canary identifiers in memory and detect exact canary touches from canonical normalized fixture events with Evidence-first DRY_RUN findings.
- Target path: swarm/ransomware.py
- Allowed paths: swarm/ransomware.py, tests/test_ransomware.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_ransomware.py
- Acceptance criteria:
  - registry and lookup remain tenant/device isolated and bounded;
  - exact identifiers only, with duplicate and malformed input rejection;
  - detection consumes normalized caller-supplied observations only;
  - Evidence failure denies findings and no endpoint/filesystem access is added;
  - outputs remain DRY_RUN/DETECT_ONLY and recommend WARN only.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: canaries and event metadata are untrusted fixture data; detection grants no response authority.
- Completion evidence: exact candidate `55edcd4c98b2e05f493fa3bd79162daa72c10654`; focused 14 passed; Claude APPROVE/LOW with no blockers/missing tests; full 847 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-ransom-03-claude-review.json`, `docs/fw-ransom-03-integrity.json`.

### FW-RANSOM-02 — Ticket-bound ransomware isolation proposal
- Requirement: FW-RANSOM deterministic response proposal boundary
- State: DONE
- Priority: P0
- Dependencies: FW-RANSOM-01
- Approval: FW-RANSOM is active first under D-022.
- Description: Convert only a HIGH FW-RANSOM-01 finding into a tenant/device-bound, single-use Action Ticket-authorized, Evidence-first dry-run isolation proposal without executing containment.
- Target path: swarm/ransomware.py
- Allowed paths: swarm/ransomware.py, tests/test_ransomware.py, WORK_QUEUE.md, SWARM_STATUS.md
- Test command: python3 -m pytest -q tests/test_ransomware.py
- Acceptance criteria:
  - LOW/MEDIUM findings cannot propose isolation;
  - ticket binds tenant, device resource, agent, lease, capability, class, policy, and validity;
  - ticket replay, mismatch, expiry, kill-switch change, or Evidence failure denies safely;
  - successful output remains DRY_RUN/DETECT_ONLY and cannot execute containment.
- Expected validation: focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: proposal metadata is non-authoritative; Action Ticket validation grants no endpoint access.
- Completion evidence: exact candidate `0ce44dcd92d5a14576ceff5fba859fccb7398847`; focused 11 passed; Claude APPROVE/LOW with no blockers/missing tests; full 844 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-ransom-02-claude-review.json`, `docs/fw-ransom-02-integrity.json`.

### FW-RANSOM-01 — Bounded ransomware activity evaluator
- Requirement: FW-RANSOM deterministic detection over canonical endpoint fixtures
- State: DONE
- Priority: P0
- Dependencies: completed NormalizedEventStore and FW-ENDPOINT fixture controls
- Approval: Jeff explicitly activated FW-RANSOM first under D-022.
- Description: Evaluate a bounded caller-supplied tenant/device event window for exact ransomware activity signals, write canonical Evidence before returning, warn for every finding, and recommend isolation only for high-confidence combinations without executing a response.
- Target path: swarm/ransomware.py
- Allowed paths: swarm/ransomware.py, tests/test_ransomware.py, WORK_QUEUE.md, SWARM_STATUS.md, DECISIONS.md
- Test command: python3 -m pytest -q tests/test_ransomware.py
- Acceptance criteria:
  - deterministic results independent of input order;
  - strict tenant/device binding, duplicate rejection, bounded event count and time window;
  - exact normalized operation/indicator tokens only;
  - Evidence written before any result is returned and Evidence failure denies the result;
  - every finding recommends WARN; only HIGH may additionally recommend isolation;
  - mode remains DRY_RUN/DETECT_ONLY with deployment disabled and no live response authority.
- Expected validation: one focused Linux proof, exact Claude review, then one full suite/integrity gate.
- Security considerations: observations are untrusted caller-supplied data; recommendations are non-authoritative and cannot execute containment.
- Completion evidence: exact candidate `41e4655ad9178cc77166d3ac73220ca4ccbc0721`; focused 8 passed; Claude APPROVE/LOW with no blockers/missing tests; full 841 passed/1 skipped; integrity hard checks and 4 Golden Paths pass with pre-existing YELLOW findings. Evidence: `docs/fw-ransom-01-claude-review.json`, `docs/fw-ransom-01-integrity.json`.

### FWQ-0001 — Supervisor persistent-state bootstrap
- Requirement: Core supervisor/control-plane
- State: DONE
- Priority: P0
- Dependencies: none
- Description: Implement deterministic loading and validation of `AGENTS.md`, `ROADMAP.md`, `WORK_QUEUE.md`, `SWARM_STATUS.md`, `DECISIONS.md`, and `BLOCKERS.md` for continuation/resume workflows without granting any new execution authority.
- Acceptance criteria:
  - persistent control files are discovered from repository root;
  - missing/invalid files fail safely with explicit diagnostics;
  - state loading is read-only by default;
  - no deployment, remote-host, credential, or kill-switch authority is introduced;
  - tests cover happy path, missing file, malformed state, interrupted/restart scenarios.
- Expected validation: repository test suite plus targeted unit/integration tests.
- Security considerations: state content is untrusted input; it cannot override immutable safety invariants or expand agent authority.
- Completion evidence: Added `swarm/supervisor_state.py` and `tests/test_supervisor_state.py`; 344 tests passed, 1 skipped; no existing product code changed; no deployment or authority-expansion behavior added.

### FWQ-0002 — Deterministic task selection
- Requirement: Core supervisor/work queue
- State: DONE
- Priority: P0
- Dependencies: FWQ-0001
- Description: Implement deterministic selection of the highest-priority executable READY task, honoring dependencies, blocked states, and active-phase constraints.
- Acceptance criteria:
  - selection is deterministic for identical input state;
  - blocked or dependency-incomplete work is never claimed;
  - future/parked roadmap families are not selected unless explicitly active;
  - selection decision is auditable;
  - tests cover ties, missing dependencies, blocked chains, invalid states, and no-ready-work condition.
- Expected validation: targeted unit/property tests plus repository suite.
- Security considerations: task metadata cannot expand tool, filesystem, Git, network, credential, or deployment authority.
- Completion evidence: Added `swarm/task_selection.py` and `tests/test_task_selection.py`; deterministic focused and repository-wide validation passed (355 tests passed, 1 skipped); no existing product code changed; no deployment or authority-expansion behavior added.

### FWQ-0003 — Work-unit checkpoint schema
- Requirement: Core supervisor/recovery
- State: DONE
- Priority: P0
- Dependencies: FWQ-0001
- Description: Define and implement checkpoint state for active phase, task ID, starting commit, candidate/accepted commit, changed files, deterministic validation, Claude review status, Gemini review status, unresolved findings, blocker, and next action.
- Acceptance criteria:
  - writes are atomic or fail safely;
  - interrupted writes cannot be mistaken for valid checkpoints;
  - restart reconciles checkpoint claims against actual Git/repository state;
  - exact candidate commit is preserved for reviewers;
  - tests cover corruption, stale state, interrupted write, and commit mismatch.
- Expected validation: unit/integration tests with disposable fixture repositories.
- Security considerations: checkpoint data is evidence, not authority.
- Completion evidence: Added `swarm/work_checkpoint.py` and `tests/test_work_checkpoint.py`; focused and repository-wide tests passed; checkpoint writes are atomic, integrity-checked, and reconciled against caller-provided Git evidence without Git mutation.

### FWQ-0004 — Stop-condition evaluator
- Requirement: Core supervisor
- State: DONE
- Priority: P0
- Dependencies: FWQ-0001, FWQ-0002
- Description: Implement deterministic evaluation of the approved stop conditions from `AGENTS.md`.
- Acceptance criteria:
  - ordinary test failures, reviewer findings, or task completion do not trigger stop;
  - Jeff-authority requirements, unavailable required resources with no safe work, policy/invariant conflict, unsafe repository ambiguity, hard platform/resource limits, all-active-work-complete, and explicit supervisor termination are represented distinctly;
  - stop reason is persisted with first resume action.
- Expected validation: table-driven tests for every stop and non-stop condition.
- Security considerations: ambiguous state must fail closed rather than silently continue into privileged actions.
- Completion evidence: Added `swarm/stop_conditions.py` and `tests/test_stop_conditions.py`; focused and repository-wide tests passed; stop decisions are local evidence only and preserve DRY_RUN/no-authority constraints.

### FWQ-0005 — Review handoff contract
- Requirement: Core exact-commit review
- State: DONE
- Priority: P1
- Dependencies: FWQ-0003
- Description: Formalize deterministic handoff metadata so Claude and Gemini review the exact same candidate commit and Codex receives structured findings for repair.
- Acceptance criteria:
  - candidate SHA is immutable for one review cycle;
  - review result records model role, exact SHA, findings, severity, and disposition;
  - stale reviews against superseded commits cannot validate a new candidate;
  - rejected findings require recorded rationale;
  - tests cover stale/mismatched review data.
- Expected validation: unit/integration tests.
- Security considerations: reviewers cannot write production source or grant themselves authority.
- Completion evidence: Added `swarm/review_handoff.py` and `tests/test_review_handoff.py`; focused and repository-wide tests passed (372 tests passed, 1 skipped); review handoff is immutable exact-commit evidence only.

### FWQ-0006 — Supervisor continuation loop
- Requirement: Core supervisor/orchestration
- State: DONE
- Priority: P1
- Dependencies: FWQ-0002, FWQ-0003, FWQ-0004, FWQ-0005
- Description: Implement the bounded persistent loop: select → inspect/dispatch Codex work unit → deterministic validation → Claude review → Gemini exact-commit review → Codex repair → revalidate → accept/checkpoint → immediately select next READY task.
- Acceptance criteria:
  - one completed work unit automatically advances to the next READY task;
  - individual Codex process exit does not imply project completion;
  - loop can resume after interruption from persistent state;
  - stop only occurs under explicit stop conditions;
  - every transition is auditable;
  - dry-run and deployment prohibitions remain enforced.
- Expected validation: integration tests with mocked agent adapters and disposable repositories; failure/restart tests.
- Security considerations: supervisor may sequence work but must not create new authority or bypass Z3/policy.
- Completion evidence: Candidate `514217e474e46872c12efdad181d11ae90bfe57e` passed authoritative detached-worktree validation (388 passed, 1 skipped). Claude exact-SHA evidence is APPROVE/LOW in `docs/fwq-0006-claude-review-514217e.json`; Jeff-mediated manual independent Gemini exact-SHA evidence is APPROVE/LOW and schema-valid in `docs/fwq-0006-gemini-manual-review-514217e.json`. The configured automated Gemini adapter remained unavailable and was not treated as successful. No unresolved critical/high-confidence finding remains.

### FWQ-0007 — Immutable policy/invariant gate contract
- Requirement: Core trust model and deterministic safety
- State: DONE
- Priority: P0
- Dependencies: FWQ-0001, FWQ-0004, FWQ-0006
- Description: Centralize the immutable DRY_RUN, deployment-disabled, and kill-switch policy contract used by authoritative safety reporting and activation admission without granting authority or changing the current safety defaults.
- Acceptance criteria:
  - the contract is read-only and deterministic;
  - missing, malformed, or unsafe invariant evidence fails closed;
  - activation admission uses the contract before proceeding;
  - tests cover safe evidence, each invariant violation, missing fields, and optional cleared-for-dry-run reporting;
  - no deployment, kill-switch clearing, credential, remote-host, or authority-expansion behavior is added.
- Expected validation: focused policy-gate tests plus repository suite and safety-invariant validation.
- Security considerations: policy evidence is untrusted input; it cannot override immutable safety values or grant execution authority.
- Completion evidence: Candidate `dd51951b628886c13e07ff8cddccf170da99d6e4` passed the focused policy-gate checks and the full Linux-style suite. Claude returned `APPROVE` / `LOW` with no blocking findings, and independent manual Gemini review returned schema-valid `APPROVE` / `LOW` with no blocking findings or missing tests in `docs/fwq-0007-gemini-manual-review-dd51951.json`. DRY_RUN, deployment-disabled, and engaged-kill-switch policy remain unchanged.

### FWQ-0008 — Immutable accepted-work evidence bundle
- Requirement: Core trust model and immutable evidence (FW-EVID)
- State: VALIDATED
- Priority: P1
- Dependencies: FWQ-0003, FWQ-0005, FWQ-0007
- Description: Define and implement a deterministic, redacted evidence bundle for an accepted dry-run work unit, binding its job ID, exact candidate and accepted commits, changed files, deterministic validation, Claude/Gemini review outcomes, policy state, and evidence hash without creating execution authority.
- Target path: swarm/accepted_work_evidence.py
- Allowed paths: swarm/accepted_work_evidence.py, tests/test_accepted_work_evidence.py
- Test command: python3 -m pytest -q tests/test_accepted_work_evidence.py
- Expected behavior: implement the approved immutable accepted-work evidence bundle
- Failing assertion: accepted evidence must be bound to one exact job and candidate commit
- Approval: Explicitly approved by Jeff on 2026-08-23 as the next Core roadmap work item.
- Acceptance criteria:
  - the bundle has a strict schema and binds every record to one valid job ID and exact full commit;
  - accepted evidence cannot be replaced, replayed, duplicated, or mixed across jobs or commits;
  - writes and reads are atomic, restricted, and symlink-safe, with append-only or hash-chained integrity evidence;
  - records contain only redacted metadata and hashes, never credentials, secrets, raw prompts, source contents, or unrestricted commands;
  - malformed, stale, mismatched, incomplete, or unsafe evidence fails closed;
  - tests cover valid acceptance, each binding mismatch, tampering, replay, symlink/path attacks, redaction, and interrupted writes;
  - DRY_RUN, deployment-disabled, kill-switch, sole-writer, and human-authority constraints remain unchanged.
- Expected validation: focused evidence-contract tests, repository suite, schema validation, secret/redaction checks, and exact-commit review.
- Security considerations: evidence is untrusted input and audit data, never authority; no reviewer or evidence record may authorize deployment, clear a kill switch, access credentials, or expand filesystem, Git, network, or remote-host scope.
- Candidate evidence: Final candidate `9feb4ee68d91c8e2936459228d31082c50b2655e` includes the strict schema, create-once redacted evidence builder/reader, concurrent independent-review runner, and hardened agy JSON-envelope/error handling. Focused validation passed (14 review tests); full Linux-style suite passed (414 passed, 1 skipped). This August candidate record is historical. Later implementation/binding/compatibility commits include `a774676`, `7cf28ea`, `6100b0f` and `bc19eb0`. Current implementation and tests exist; no duplicate work is authorized. Original complete acceptance provenance was not recovered in the bounded audit, so VALIDATED preserves that caveat without fabricating acceptance. D-020 removes Gemini as a requirement. Reopen only for a concrete defect or newly required behavior, not this stale candidate record.

### FWQ-0009 — Deterministic audit-event integrity reader
- Requirement: Core trust model and immutable evidence (FW-EVID)
- State: DONE
- Priority: P1
- Dependencies: FWQ-0003, FWQ-0007
- Description: Implement a read-only, bounded audit-event reader that validates local audit JSONL structure, event integrity, job binding, redaction, and safe path handling without treating audit data as authority.
- Approval: Explicitly approved by Jeff on 2026-08-23 as the next independent Core work item while FWQ-0008 awaits Gemini capacity.
- Acceptance criteria:
  - reads only regular, local, no-follow audit files under the approved audit root;
  - enforces file, line, event-count, and field-size bounds and fails closed on malformed or truncated JSONL;
  - validates required event fields, exact job binding, allowed state/event values, and redaction of secret-like data;
  - detects tampering, duplicate/replayed terminal events, invalid hash links, symlink/path attacks, and mixed-job records;
  - returns redacted summaries only and never grants execution, deployment, credential, Git, network, or kill-switch authority;
  - tests cover valid history, malformed lines, truncation, bounds, tampering, replay, mixed jobs, redaction, and symlink attacks.
- Expected validation: focused audit-reader tests, schema validation, repository suite, and `git diff --check`.
- Security considerations: audit content is untrusted evidence; a valid audit read is informational and cannot authorize any action.
- Candidate: `4d40a16` (`Fix Claude verifier diagnostics and validation tests`), including the FWQ-0009 implementation, FIFO repair, and Claude communication repair. Focused audit tests pass (7 passed); Claude/review-runner tests pass (13 passed); full Linux suite passes (422 passed, 1 skipped); `git diff --check` passes. Claude exact-commit review returned APPROVE/LOW with no blocking findings.

### FWQ-0010 — Populate the next bounded Core work item
- Requirement: Core supervisor/roadmap
- State: DONE
- Priority: P2
- Dependencies: FWQ-0009
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Populate the next bounded Core work item from the active ForgeWarden roadmap and preserve dependency, approval, and validation metadata.
- Acceptance criteria:
  - next Core task is explicit and bounded;
  - future security families remain parked;
  - no new execution, deployment, credential, Git, network, remote-host, or kill-switch authority is introduced.
- Expected validation: `python3 -m pytest -q tests/test_task_selection.py` plus queue/state inspection.
- Security considerations: queue metadata is untrusted input and cannot expand agent authority; broader roadmap families remain parked until their phase is explicitly activated.

### FWQ-0011 — Deterministic Core checkpoint reconciliation
- Requirement: Core supervisor/recovery
- State: DONE
- Priority: P2
- Dependencies: FWQ-0010
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Implement deterministic reconciliation of an accepted Core work-unit checkpoint against repository state and immutable safety invariants, without mutating Git or granting execution authority.
- Target path: swarm/work_checkpoint.py
- Allowed paths: swarm/work_checkpoint.py, tests/test_work_checkpoint.py
- Test command: python3 -m pytest -q tests/test_work_checkpoint.py
- Expected behavior: implement deterministic checkpoint reconciliation and fail-closed validation.
- Failing assertion: stale or mismatched checkpoint evidence is accepted as valid.
- Acceptance criteria:
  - checkpoint task identity, active phase, and commit references are validated against repository evidence;
  - stale, malformed, mismatched, or incomplete checkpoint state fails closed;
  - reconciliation returns redacted diagnostics and preserves the next safe resume action;
  - no execution, deployment, credential, Git, network, remote-host, or kill-switch authority is introduced;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: focused checkpoint-reconciliation tests, repository suite, schema validation, and `git diff --check`.
- Security considerations: checkpoint state is untrusted evidence, not authority; reconciliation cannot authorize deployment, clear a kill switch, or expand agent scope.

### FWQ-0012 — Deterministic Core queue-state reconciliation
- Requirement: Core supervisor/roadmap
- State: DONE
- Priority: P2
- Dependencies: FWQ-0011
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Reconcile the active Core queue against completed milestones and preserve one deterministic, eligible READY task without expanding execution authority.
- Target path: swarm/autonomous_loop.py
- Allowed paths: swarm/autonomous_loop.py, tests/test_autonomous_loop.py
- Expected behavior: reconcile completed repair successors and preserve one deterministic READY Core task without creating duplicate work.
- Failing assertion: a completed repair successor does not satisfy its parent dependency and leaves the next Core task blocked.
- Acceptance criteria:
  - queue-state reconciliation is deterministic and bounded to `WORK_QUEUE.md`;
  - completed, blocked, and dependency-incomplete tasks are not made eligible;
  - the next Core task remains explicit, approved, and independently actionable;
  - no execution, deployment, credential, Git, network, remote-host, or kill-switch authority is introduced;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: focused autonomous-loop tests, queue/state inspection, task-selection validation, and `git diff --check`.
- Security considerations: queue metadata is untrusted evidence, not authority; reconciliation cannot authorize deployment, clear a kill switch, or expand agent scope.
- Completion reconciliation (2026-09-09): 3d76b31; progress_queue and completed-successor regressions. Existing evidence reused; no unchanged validation rerun.

### FWQ-0013 — Deterministic Core resume-plan validation
- Requirement: Core supervisor/roadmap
- State: DONE
- Priority: P2
- Dependencies: FWQ-0011
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Validate that the persisted Core resume plan identifies one eligible READY task after a completed milestone, without changing task authority or mutating Git state.
- Target path: WORK_QUEUE.md
- Allowed paths: WORK_QUEUE.md
- Expected behavior: preserve a deterministic, bounded next-task declaration and fail closed when no eligible READY task exists.
- Failing assertion: the active queue has no eligible READY task after current milestone completion.
- Acceptance criteria:
  - the resume plan names an explicit Core task with complete dependency and approval metadata;
  - completed, blocked, dependency-incomplete, and parked roadmap work is not made eligible;
  - the selected task remains bounded to its declared paths and validation requirements;
  - no execution, deployment, credential, Git, network, remote-host, or kill-switch authority is introduced;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: queue/state inspection and `git diff --check`.
- Security considerations: queue metadata is untrusted evidence, not authority; resume-plan validation cannot authorize deployment, clear a kill switch, or expand agent scope.
- Completion reconciliation (2026-09-09): 16b32da; derive_next_core_task and duplicate-ID/dependency regressions. Existing evidence reused; no unchanged validation rerun.

### FWQ-0014 — Deterministic Core continuation transition record
- Requirement: Core supervisor/control-plane
- State: DONE
- Priority: P2
- Dependencies: FWQ-0013
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Record the deterministic transition from an accepted Core work unit to its next eligible queue task without granting execution authority or mutating Git state.
- Target path: swarm/continuation.py
- Allowed paths: swarm/continuation.py, tests/test_continuation.py
- Test command: python3 -m pytest -q tests/test_continuation.py
- Expected behavior: persist a bounded, redacted continuation transition and fail closed when the accepted task or next task does not match validated queue state.
- Failing assertion: an accepted work unit can advance without a validated next-task transition record.
- Acceptance criteria:
  - the transition binds the completed task, accepted commit, next task, and active Core phase to validated repository state;
  - stale, malformed, mismatched, duplicate, or incomplete transition evidence fails closed;
  - the record preserves the next safe resume action and cannot authorize execution, deployment, credentials, Git, network, remote hosts, or kill-switch changes;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: focused continuation-transition tests, repository suite, schema validation, and `git diff --check`.
- Security considerations: transition records are untrusted evidence, not authority; recording a queue advance cannot authorize deployment, clear a kill switch, or expand agent scope.
- Completion reconciliation (2026-09-09): 7d47595; run_bounded_work_unit/plan_continuation and continuation regressions. Existing evidence reused; no unchanged validation rerun.

### FWQ-0015 — Deterministic Core continuation replay guard
- Requirement: Core supervisor/control-plane
- State: DONE
- Priority: P2
- Dependencies: FWQ-0014
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Validate that a persisted Core continuation transition is consumed exactly once and remains bound to the accepted work unit and next eligible task, without granting execution authority or mutating Git state.
- Target path: swarm/continuation.py
- Allowed paths: swarm/continuation.py, tests/test_continuation.py
- Test command: python3 -m pytest -q tests/test_continuation.py
- Expected behavior: reject replayed, stale, malformed, or mismatched continuation records and preserve a deterministic safe resume decision.
- Failing assertion: a valid continuation transition can be replayed or consumed for a different accepted work unit.
- Acceptance criteria:
  - continuation consumption binds the transition to the exact accepted task, commit, next task, and active Core phase;
  - duplicate, replayed, stale, malformed, or mismatched records fail closed;
  - consumption returns redacted diagnostics and cannot authorize execution, deployment, credentials, Git, network, remote hosts, or kill-switch changes;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: focused continuation-replay tests, repository suite, schema validation, and `git diff --check`.
- Security considerations: continuation records are untrusted evidence, not authority; replay protection cannot authorize deployment, clear a kill switch, or expand agent scope.
- Completion reconciliation (2026-09-09): 7aa31fb / 582af73; focused 12 passed, full 813 passed/1 skipped, exact Claude approval and gate recorded. Existing evidence reused; no unchanged validation rerun.

### FWQ-0016 — Deterministic Core continuation admission validation
- Requirement: Core supervisor/control-plane
- State: DONE
- Priority: P2
- Dependencies: FWQ-0015
- Approval: Explicitly authorized by Jeff for bounded job `codex-fwq-0016`.
- Description: Validate that a consumed Core continuation admits exactly one declared next READY task under the active phase, without granting execution authority or mutating Git state.
- Target path: swarm/continuation.py
- Allowed paths: swarm/continuation.py, tests/test_continuation.py
- Test command: python3 -m pytest -q tests/test_continuation.py
- Expected behavior: reject continuation admission when the accepted work unit, active phase, dependency state, or next-task identity does not match the validated queue.
- Failing assertion: a consumed continuation can admit a task that is not the validated eligible READY successor.
- Acceptance criteria:
  - admission binds the consumed continuation to the exact accepted task, commit, active Core phase, and next READY task;
  - missing, stale, malformed, duplicate, mismatched, or dependency-incomplete admission evidence fails closed;
  - the result preserves a redacted safe resume decision and cannot authorize execution, deployment, credentials, Git, network, remote hosts, or kill-switch changes;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: focused continuation-admission tests, repository suite, schema validation, and `git diff --check`.
- Security considerations: continuation metadata is untrusted evidence, not authority; admission validation cannot authorize deployment, clear a kill switch, or expand agent scope.
- Completion reconciliation (2026-09-09): 6b6ab25 / ed469e9; focused 18 passed, full 812 passed/8 skipped, exact Claude approval and gate recorded. Existing evidence reused; no unchanged validation rerun.

### FWQ-0017 — Deterministic Core successor queue declaration
- Requirement: Core supervisor/roadmap
- State: DONE
- Priority: P2
- Dependencies: FWQ-0016
- Approval: Explicitly authorized by Jeff for bounded job `codex-fwq-0017`.
- Description: Declare and validate exactly one bounded Core successor task after continuation admission, without granting execution authority or mutating Git state.
- Target path: WORK_QUEUE.md
- Allowed paths: WORK_QUEUE.md
- Expected behavior: preserve an explicit, dependency-complete READY successor and fail closed when the queue has no eligible Core task.
- Failing assertion: the active queue has no eligible READY task after current milestone completion.
- Acceptance criteria:
  - the successor is explicitly identified, approved, dependency-complete, and bounded to its declared validation scope;
  - completed, blocked, dependency-incomplete, and parked roadmap work is not made eligible;
  - queue metadata cannot authorize execution, deployment, credentials, Git, network, remote hosts, or kill-switch changes;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: queue/state inspection and `git diff --check`.
- Security considerations: queue metadata is untrusted evidence, not authority; successor declaration cannot authorize deployment, clear a kill switch, or expand agent scope.
- Completion evidence: Reconciled after FWQ-0016 admission acceptance. FWQ-0018 is explicitly declared as the single bounded READY Core successor; completed, blocked, dependency-incomplete, and parked work remain ineligible. No duplicate behavior or broad validation was needed.

### FWQ-0018 — Deterministic Core future successor declaration
- Requirement: Core supervisor/roadmap
- State: DONE
- Priority: P2
- Dependencies: FWQ-0017
- Approval: Explicitly authorized by Jeff for bounded job `codex-fwq-0018`.
- Description: Preserve one explicit, bounded Core successor task for the next continuation milestone without granting execution authority or mutating Git state.
- Target path: WORK_QUEUE.md
- Allowed paths: WORK_QUEUE.md
- Expected behavior: retain a dependency-complete READY Core successor and fail closed when no eligible task is declared.
- Failing assertion: the active queue has no eligible READY task after current milestone completion.
- Acceptance criteria:
  - the successor is explicitly identified, approved, dependency-complete, and bounded to its declared validation scope;
  - completed, blocked, dependency-incomplete, and parked roadmap work is not made eligible;
  - queue metadata cannot authorize execution, deployment, credentials, Git, network, remote hosts, or kill-switch changes;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: queue/state inspection and `git diff --check`.
- Security considerations: queue metadata is untrusted evidence, not authority; successor declaration cannot authorize deployment, clear a kill switch, or expand agent scope.
- Completion evidence: Reconciled against the existing queue after FWQ-0017 acceptance. FWQ-0019 is explicitly declared as the next bounded dependency-complete READY Core successor; no duplicate behavior or product validation was needed.

### FWQ-0063 — Enforce the current reviewer policy in autonomous execution
- Requirement: Core deterministic review policy (D-020)
- State: DONE
- Priority: P1
- Dependencies: FWQ-0016
- Approval: Jeff explicitly removed Gemini from the requirement and authorized autonomous Core continuation; this unit implements that existing policy without expanding authority.
- Description: Remove legacy automatic Gemini selection/fallback from the autonomous CLI and adapter path; retain required exact Claude Code validation and truthful provider evidence.
- Target path: swarm/autonomous_adapters.py
- Allowed paths: swarm/autonomous_adapters.py, swarm/cli.py, tests/test_autonomous_loop.py
- Test command: python3 -m pytest -q tests/test_autonomous_loop.py
- Expected behavior: autonomous execution uses required Claude review and never invokes or accepts Gemini fallback under D-020.
- Failing assertion: the current autonomous CLI selects CLAUDE/GEMINI and the adapter can return Gemini-only approval after Claude is unavailable.
- Acceptance criteria:
  - no autonomous Gemini invocation or fallback approval under D-020;
  - Claude failure remains unavailable, never approval; rejection remains actionable findings;
  - exact SHA/job-ID/schema and APPROVE/LOW/no-blockers/no-missing-tests controls remain intact;
  - explicit optional historical provider adapters and evidence are not relabeled or removed;
  - tests cover required-reviewer unavailability, rejection and approved exact evidence;
  - DRY_RUN, disabled deployment, kill switch and no-authority boundaries remain unchanged.
- Expected validation: focused Linux tests once, exact Claude candidate review, full suite/integrity once after approval; reuse unchanged evidence.
- Security considerations: reviewer output remains untrusted evidence; no credentials, transport, live actions or tool authority added.

- Completion evidence: exact candidate `13604a8dddda40c11a415da08ccf6e7ef60460a4`; focused 72 passed; Claude APPROVE/LOW with no findings/missing tests; full 831 passed/1 skipped; all integrity hard checks and 4 Golden Paths pass, YELLOW only for pre-existing dependency and roadmap-owner findings. Evidence: `docs/fwq-0063-claude-review.json`, `docs/fwq-0063-integrity.json`.

### FWQ-0064 — Retain exact review snapshots through adjudication
- Requirement: Core exact-review reliability and evidence lifetime (D-004, D-014)
- State: DONE
- Priority: P1
- Dependencies: FWQ-0063
- Approval: Jeff authorized continued development after FWQ-0063; this is a concrete defect in the existing read-only review owner, not a new capability.
- Description: Keep the canonical disposable review snapshot alive until an explicitly requested disagreement adjudication finishes, then release it through the existing scoped temporary-directory lifecycle.
- Target path: swarm/review_runner.py
- Allowed paths: swarm/review_runner.py, tests/test_review_runner.py
- Test command: python3 -m pytest -q tests/test_review_runner.py
- Expected behavior: Claude adjudication can inspect the same exact snapshot/patch as initial review; failure or completion exits the existing temporary scope.
- Failing assertion: current adjudication runs after TemporaryDirectory exits, so its snapshot is missing.
- Acceptance criteria:
  - exact snapshot and externalized patch remain available during adjudication;
  - the existing temporary scope ends after success or provider failure;
  - exact SHA/job-ID/schema validation and no-authority boundaries remain unchanged;
  - regression uses isolated fixtures and fake read-only providers, with no real external requests.
- Expected validation: one focused Linux proof, exact Claude review, then full suite/integrity once.
- Security considerations: no new filesystem/cleanup/product authority; retain existing trusted temporary-directory lifecycle and read-only provider limits. No autonomous Gemini selection is re-enabled.

- Completion evidence: exact candidate `bb185c3be81c41df55a58adb0bddde1471573ce8`; regression reproduced before fix, focused 11 passed afterward; exact Claude APPROVE/LOW with no blockers/missing tests; full 833 passed/1 skipped; integrity all hard checks and 4 Golden Paths pass. Saved review/gate: `docs/fwq-0064-claude-review.json`, `docs/fwq-0064-integrity.json`.

## Queue cleanup

FWQ-0019 through FWQ-0062 were repetitive successor/population placeholders. They are retired rather than treated as executable work. FWQ-0008 already has implementation and follow-up hardening; FWQ-0009 has recorded acceptance and unchanged source/tests. Neither is a new implementation task. FWQ-0017/0018 successor references are historical and do not authorize recreating FWQ-0019. The completion audit supersedes stale next-task prose.
## Future queue population

After the supervisor/control-plane work is validated, populate subsequent Core tasks from the active phase of `ROADMAP.md` and existing repository requirements. FW-ASOC is an approved cross-cutting requirement family: register/map it and add bounded primitives/tests incrementally after Core sequencing permits; do not duplicate existing subsystems or activate broad implementation from roadmap presence alone. Broader FW-BME/FW-SOC/FW-SAAS/FW-SUPPLY/FW-NET/FW-ASM/FW-DSPM implementation remains parked until its phase is explicitly activated.
