# ForgeWarden Work Queue

This file is the persistent executable queue for the active ForgeWarden phase. Codex must claim the highest-priority READY task, complete the full validation/review/repair cycle, checkpoint state, and immediately continue to the next READY task unless a defined stop condition applies.

## States

`BLOCKED` · `READY` · `IN_PROGRESS` · `REVIEW` · `REPAIR` · `VALIDATED` · `DONE`

## Queue rules

- Only approved active-phase work may be claimed.
- Codex is the sole application-code writer.
- Claude and Gemini review exact candidate commits and return findings only.
- A task is DONE only when acceptance criteria, deterministic validation, and review requirements are satisfied.
- Do not mark placeholders, interfaces without behavior, untested code, or documentation-only claims as complete.
- If one task is blocked, record the blocker and move to another independent READY task when safe.
- Keep tasks bounded enough to implement, test, review, repair, and checkpoint coherently.

## Active queue

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
- State: BLOCKED
- Priority: P1
- Dependencies: FWQ-0003, FWQ-0005, FWQ-0007
- Description: Define and implement a deterministic, redacted evidence bundle for an accepted dry-run work unit, binding its job ID, exact candidate and accepted commits, changed files, deterministic validation, Claude/Gemini review outcomes, policy state, and evidence hash without creating execution authority.
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
- Candidate evidence: Final candidate `9feb4ee68d91c8e2936459228d31082c50b2655e` includes the strict schema, create-once redacted evidence builder/reader, concurrent independent-review runner, and hardened agy JSON-envelope/error handling. Focused validation passed (14 review tests); full Linux-style suite passed (414 passed, 1 skipped). Exact Claude and independent Gemini review remain required before acceptance.

### FWQ-0009 — Deterministic audit-event integrity reader
- Requirement: Core trust model and immutable evidence (FW-EVID)
- State: REVIEW
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
- State: READY
- Priority: P2
- Dependencies: FWQ-0010
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Implement deterministic reconciliation of an accepted Core work-unit checkpoint against repository state and immutable safety invariants, without mutating Git or granting execution authority.
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
- State: BLOCKED
- Priority: P2
- Dependencies: FWQ-0011
- Approval: Explicitly authorized by the active Core queue-population plan.
- Description: Reconcile the active Core queue against completed milestones and preserve one deterministic, eligible READY task without expanding execution authority.
- Acceptance criteria:
  - queue-state reconciliation is deterministic and bounded to `WORK_QUEUE.md`;
  - completed, blocked, and dependency-incomplete tasks are not made eligible;
  - the next Core task remains explicit, approved, and independently actionable;
  - no execution, deployment, credential, Git, network, remote-host, or kill-switch authority is introduced;
  - broader security families remain parked until their phase is explicitly activated.
- Expected validation: queue/state inspection, task-selection validation, and `git diff --check`.
- Security considerations: queue metadata is untrusted evidence, not authority; reconciliation cannot authorize deployment, clear a kill switch, or expand agent scope.

## Future queue population

After the supervisor/control-plane work is validated, populate subsequent Core tasks from the active phase of `ROADMAP.md` and existing repository requirements. Broader FW-BME/FW-SOC/FW-SAAS/FW-SUPPLY/FW-NET/FW-ASM/FW-DSPM implementation remains parked until its phase is explicitly activated.
