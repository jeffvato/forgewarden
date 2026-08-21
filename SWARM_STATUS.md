# ForgeWarden Swarm Status

## Current state

- Active phase: ForgeWarden Core
- Current focus: persistent supervisor/work-queue control plane
- Current task: none claimed yet
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

- Task ID: none
- Starting commit: none
- Candidate commit: none
- Accepted commit: none
- Files changed: none
- Deterministic validation: not started
- Claude review: not started
- Gemini review: not started
- Unresolved findings: none
- Blocker: none
- Next action: claim `FWQ-0001` from `WORK_QUEUE.md` after these control-plane files are merged into the working branch used by Codex.

## Stop conditions

Do not stop merely because a task or review cycle finished. Stop only under the explicit conditions in `AGENTS.md`, and record the exact reason and first resume action here.
