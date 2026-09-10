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
- State: READY
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
