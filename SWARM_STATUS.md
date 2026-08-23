# ForgeWarden Swarm Status

## Current state

- Active phase: ForgeWarden Core
- Current focus: FWQ-0008 exact-commit review
- Current task: FWQ-0008 — candidate awaiting Claude and independent Gemini review
- Queue source: `WORK_QUEUE.md`
- Repository safety mode: DRY_RUN
- Deployment: disabled
- Kill-switch policy: remains engaged where configured
- Codex role: sole application-code writer
- Claude role: architecture/requirements/adversarial reviewer
- Gemini role: independent read-only exact-commit reviewer

## Resume protocol

On every restart or continuation:

1. Read `AGENTS.md`, `ROADMAP.md`, `WORK_QUEUE.md`, `SWARM_STATUS.md`, `DECISIONS.md`, `BLOCKERS.md`, and relevant specs.
2. Inspect Git status, HEAD, recent commits, and repository tests.
3. Reconcile this status file with actual repository evidence.
4. If a task was interrupted, resume from the last provably valid checkpoint rather than restarting the project.
5. Otherwise claim the highest-priority READY task whose dependencies are complete.
6. Run the full Codex → deterministic validation → Claude review → Gemini exact-commit review → Codex repair/revalidation cycle.
7. After acceptance, checkpoint and immediately continue to the next READY task.

## Work-unit checkpoint

- Task ID: FWQ-0008
- Starting commit: `82520fe`
- Candidate commit: `17866de76ec26685e4b2d1379509d7beebabfd1b`
- Candidate context: strict create-once, redacted, hash-bound accepted dry-run work evidence
- Accepted commit: pending exact-commit review
- Files changed: `schemas/accepted-work-evidence.schema.json`, `swarm/accepted_work_evidence.py`, and `tests/test_accepted_work_evidence.py`
- Deterministic validation: focused FWQ-0008/checkpoint/continuation tests — 24 passed; schema validation passed; full Linux-style suite on the candidate — 410 passed, 1 skipped; `git diff --check` passed.
- Claude review: pending exact candidate review.
- Gemini review: pending independent exact candidate review.
- Unresolved findings: none from deterministic validation; review findings pending.
- Blocker: none; required review resources are available through the established manual/CLI process.
- Next action: review exact candidate `17866de76ec26685e4b2d1379509d7beebabfd1b`; repair any legitimate findings, rerun validation, and accept only after both reviews approve.

## Stop conditions

Do not stop merely because a task or review cycle finished. Stop only under the explicit conditions in `AGENTS.md`, and record the exact reason and first resume action here.

## Current stop condition

- Reason: NONE
- Exact condition: FWQ-0008 has a validated exact candidate and is awaiting the required independent reviews.
- First resume action: run the exact-commit Claude/Gemini review cycle for candidate `17866de76ec26685e4b2d1379509d7beebabfd1b`.
