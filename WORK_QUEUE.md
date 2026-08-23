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
- State: REVIEW
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

## Future queue population

After the supervisor/control-plane work is validated, populate subsequent Core tasks from the active phase of `ROADMAP.md` and existing repository requirements. Broader FW-BME/FW-SOC/FW-SAAS/FW-SUPPLY/FW-NET/FW-ASM/FW-DSPM implementation remains parked until its phase is explicitly activated.
