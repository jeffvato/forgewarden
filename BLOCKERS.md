# ForgeWarden Blockers

This file records only genuine blockers that require Customer Root authority, unavailable external resources, or a condition that makes further safe work impossible.

## Current blockers

### B-008 — Untracked user artifact blocks integrity gate

- Related task/requirement: FW-AV-51 acceptance and clean-tree integrity proof
- Exact condition: the user-created `Claude outputs/` directory is untracked inside the repository, so the integrity gate reports `repository` RED even though all tests and other hard checks pass.
- Why work cannot complete safely: deleting or moving a user artifact is destructive/scope-expanding without Jeff's direction, and acceptance cannot ignore a RED clean-tree check.
- Evidence: full suite passed (666 passed, 1 skipped); integrity report `.swarm-state/fw-av-51-integrity.json` records only the untracked directory as RED plus pre-existing YELLOW findings.
- First resume action: Jeff moves `Claude outputs/` outside the repository or authorizes a safe alternative; then rerun the integrity gate once.

### B-007 — Exact Claude review pending for FW-AV-51

- Related task/requirement: FW-AV-51 — exact seven-day approval freshness boundary regression; exact-commit review contract
- Exact condition: candidate `807580245f74c1fd8e248ccd9fc088921f18f1be` requires a valid exact Claude Co-Work review before broader acceptance validation.
- Why work cannot complete safely: deterministic tests and local inspection cannot substitute for the required exact external reviewer; no acceptance may be inferred without exact APPROVE/LOW.
- Evidence: focused FW-AV proof passed (21 tests); the candidate is test-only and narrow, but no valid exact external approval exists yet.
- First resume action: obtain exact Claude APPROVE/LOW for `8075802`, then run full suite/integrity gate and checkpoint acceptance only on valid approval.

### B-004 — Exact Claude review unavailable for FW-AV-48 (resolved)

- Related task/requirement: FW-AV-48 Evidence-backed source-candidate approval before ClamAV admission; exact-commit review contract
- Exact condition: canonical Claude verifier timed out after its 180-second bounded review window for repair candidate `07842a614a5557b914946b065070e71199ce2f37`.
- Resolution: Jeff supplied an exact Claude Co-Work read-only review for `07842a6`; the payload was schema-valid, exact-commit bound, APPROVE/LOW, with no missing tests or blocking findings. Deterministic focused proof, full suite, and integrity gate passed.
- First resume action: none; FW-AV-48 is accepted and work proceeds to FW-AV-49.

### B-002 — Independent Gemini review capacity unavailable

- Related task/requirement: FWQ-0008 — Immutable accepted-work evidence bundle; D-004 and D-014 exact-commit review/evidence requirements
- Exact condition: agy launches but either ignores the no-tools boundary and times out, or reports `Individual quota reached`; no valid Gemini payload has been returned for candidate `9feb4ee68d91c8e2936459228d31082c50b2655e`.
- Why work cannot complete safely: FWQ-0008 requires an independent exact-commit Gemini review; provider output cannot be fabricated or replaced by Claude evidence.
- Required resource: a functioning Gemini/agy review capacity bound to the exact candidate.
- Independent READY work: FWQ-0009 audit-event integrity reader.
- Current candidate/checkpoint: `9feb4ee68d91c8e2936459228d31082c50b2655e` / FWQ-0008.
- First resume action: obtain a valid Gemini payload for the exact candidate, validate its job ID and SHA, then resume FWQ-0008 acceptance.

## Resolved blockers

### B-006 — Exact Claude review pending for FW-AV-50 (resolved)

- Resolution: Jeff supplied an exact Claude Co-Work read-only review for `3060a0d`; the payload was schema-valid, exact-commit bound, APPROVE/LOW, with no missing tests or blocking findings. Full validation passed at `464ffb8`.

### B-005 — Exact Claude review unavailable for FW-AV-49 (resolved)

- Resolution: Jeff supplied an exact Claude Co-Work read-only review for `d729ca4`; the payload was schema-valid, exact-commit bound, APPROVE/LOW, with no missing tests or blocking findings. Full validation passed at `28562fd`.

### B-003 — FW-AV Stage 2 definition-intake scope (resolved)

- Resolution: Customer Root authorized a ClamAV-compatible signed definition bundle under an appropriate non-commercial/testing license, with local caller-supplied input only. FW-AV-47 implemented the bounded adapter at `405503e` and accepted it after deterministic validation and exact Claude review.
- Remaining boundaries: source transport, endpoints, credentials, network access, quarantine, remediation, deployment, and response authority remain disabled.

### B-001 — Required exact-commit review resources failed closed (resolved)

- Related task/requirement: FWQ-0006 — Supervisor continuation loop; D-004 and D-014 exact-commit review/evidence requirements
- Resolution: Jeff supplied a complete manual Gemini payload. It validates against `schemas/gemini-review.schema.json` and the repository exact-SHA contract for candidate `514217e474e46872c12efdad181d11ae90bfe57e`; it is preserved in `docs/fwq-0006-gemini-manual-review-514217e.json`. The automated adapter remained unavailable and was not used as success evidence.

## What is not a blocker

The following do not justify stopping the swarm:

- a failing test;
- a reviewer finding;
- a need to refactor;
- a failed implementation approach;
- documentation that can be resolved from repository evidence;
- completion of the current task;
- the next task being difficult;
- ordinary model disagreement.

When these occur, investigate, repair, revalidate, or move to another independent READY task.

## Blocker record format

When a genuine blocker exists, record:

- Blocker ID
- Related task/requirement
- Exact condition
- Why work cannot continue safely
- What authority/resource/decision is required
- Independent READY work still available, if any
- Current commit/checkpoint
- First action to resume after resolution

Do not convert uncertainty into permission. If the issue is an authority boundary, fail closed and record it here.
