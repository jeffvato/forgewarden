# ForgeWarden Blockers

This file records only genuine blockers that require Customer Root authority, unavailable external resources, or a condition that makes further safe work impossible.

## Current blockers

None.

## Resolved blockers

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
