# ForgeWarden Blockers

This file records only genuine blockers that require Customer Root authority, unavailable external resources, or a condition that makes further safe work impossible.

## Current blockers

### B-001 — Required exact-commit review resources failed closed

- Related task/requirement: FWQ-0006 — Supervisor continuation loop; D-004 and D-014 exact-commit review/evidence requirements
- Exact condition: repository reconciliation found FWQ-0006 marked DONE while `SWARM_STATUS.md` recorded Claude and Gemini reviews as not started. Jeff subsequently authorized limited external read-only review of candidate `514217e474e46872c12efdad181d11ae90bfe57e`. Reviewer-path repair `8efd8eb9b1eada5a287e4934f265474042992cef` restored Gemini's native schema request and authorized external-review network path without changing the default deny policy. Claude then returned a schema-valid exact-SHA `REJECT` / `MEDIUM` result, but its findings were not retained by the prior invocation path; Gemini still terminates before input processing or emitting a payload. Neither review can be used for acceptance.
- Why work cannot continue safely: synthesizing, proxying, or inferring independent reviewer approval would violate the required-role and exact-commit evidence controls. FWQ-0006 cannot be accepted without both actual reviews.
- What authority/resource/decision is required: a preserved, schema-valid read-only Claude result and a functioning non-interactive read-only Gemini sandbox/permission configuration for candidate `514217e474e46872c12efdad181d11ae90bfe57e` (or a subsequently repaired candidate). The prior authorization remains limited to reviews only; `--dangerously-skip-permissions` is not authorized.
- Independent READY work still available, if any: none; FWQ-0006 is the only active Core task after reconciliation and is in REVIEW.
- Current commit/checkpoint: the current HEAD is the control-state checkpoint; the unreviewed Core candidate remains `514217e474e46872c12efdad181d11ae90bfe57e`. See `SWARM_STATUS.md`.
- First action to resume after resolution: record both schema-valid exact-SHA reviews, repair legitimate findings if any, rerun deterministic validation, accept/checkpoint FWQ-0006, and select the next READY task.

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
