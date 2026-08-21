# ForgeWarden Blockers

This file records only genuine blockers that require Customer Root authority, unavailable external resources, or a condition that makes further safe work impossible.

## Current blockers

### B-001 — Required exact-commit review resources unavailable

- Related task/requirement: FWQ-0006 — Supervisor continuation loop; D-004 and D-014 exact-commit review/evidence requirements
- Exact condition: repository reconciliation found FWQ-0006 marked DONE while `SWARM_STATUS.md` recorded Claude and Gemini reviews as not started. No exact-commit review artifact is present. Local Claude and Gemini client executables are installed, but invoking them would contact external model services; `AGENTS.md` prohibits remote-host access without an explicit Jeff-authorized workflow.
- Why work cannot continue safely: synthesizing, proxying, or inferring independent reviewer approval would violate the required-role and exact-commit evidence controls. FWQ-0006 cannot be accepted without both actual reviews.
- What authority/resource/decision is required: approved, read-only Claude architecture/adversarial review and Gemini independent exact-commit review access for candidate `514217e474e46872c12efdad181d11ae90bfe57e` (or a subsequently repaired candidate).
- Independent READY work still available, if any: none; FWQ-0006 is the only active Core task after reconciliation and is in REVIEW.
- Current commit/checkpoint: the current HEAD is the control-state checkpoint; the unreviewed Core candidate remains `514217e474e46872c12efdad181d11ae90bfe57e`. See `SWARM_STATUS.md`.
- First action to resume after resolution: record both exact-SHA reviews, repair legitimate findings if any, rerun deterministic validation, accept/checkpoint FWQ-0006, and select the next READY task.

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
