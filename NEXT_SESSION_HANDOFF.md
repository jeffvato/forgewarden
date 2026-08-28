# ForgeWarden Core — Next Coding Session Handoff

Updated: 2026-08-28

## What was accomplished

ForgeWarden Core now runs as a durable, bounded orchestration loop. The queue persists task state, leases, checkpoints, exact candidate commits, review evidence, retries, repairs, dependency promotion, orphan recovery, and stop reasons. Codex is the only application-code writer. Reviewers are read-only.

The queue was moved forward by reviewing one exact-commit candidate per bounded run. Claude is the primary reviewer and Gemini is the authorized fallback when Claude is unavailable. OpenRouter and NVIDIA remain explicit optional providers and must not delay the autonomous queue. Provider failures are recorded with their cause and do not become approvals.

Recent fixes:

- `3eb24f8` — pass the generated commit-bound JSON schema to Gemini.
- `541d763` — use Claude/Gemini as the autonomous primary/fallback pair.
- `75bc285` — parse complete Gemini results nested inside a partial provider envelope.
- `34dc46f` — terminate the entire reviewer process group on timeout so child CLIs cannot survive a bounded run.
- `7cf28ea` — bind accepted-evidence reads and writes to the expected job ID and candidate commit; update callers/tests accordingly.
- `e49ce46` — add FW-ASOC as a first-class cross-cutting architecture and roadmap requirement family.
- `27ca947` — latest accepted queue work at the time of this handoff.

## Safety contract

Keep all of these unchanged during Core development:

- `DRY_RUN=true`
- deployment disabled
- kill switch engaged
- Codex sole writer
- reviewers read-only
- no push or deployment until review evidence is complete

Never place API keys, Cloudflare tokens, SSH private keys, or other secrets in this file, Git, prompts, or review snapshots.

## How to continue

Run one bounded queue cycle from WSL:

```bash
cd /mnt/c/Users/jeffv/forgewarden
DRY_RUN=true python3 -u -m swarm.cli autonomous-loop-run \
  --repository /mnt/c/Users/jeffv/forgewarden \
  --state-dir /tmp/fw-auto-state-codex6 \
  --max-steps 1 \
  --allow-external-review
```

The durable state is `/tmp/fw-auto-state-codex6/autonomous-loop.json`. Read it before acting. Do not rerun the full suite when the commit and test inputs are unchanged. Run targeted tests after a code change, repair, or failed test; run the full suite before release/review completion.

Each cycle must do exactly one of the following first:

1. Re-evaluate one eligible `REVIEW` task or internally resolvable `BLOCKED` task.
2. Dispatch one `READY` Codex task.
3. If the current milestone is complete and no external blocker exists, derive exactly one authorized Core successor.

Do not manufacture work merely because the queue contains review-held tasks. A review-held task preserves its exact commit and evidence. A failed but repairable item should become a `READY` repair task; an external reviewer/quota outage stays parked with the provider’s diagnostic. A task blocked by a human or authority requirement must remain blocked.

## Review and failure handling

Claude approval is authoritative when Claude is available. Gemini may approve only as the explicit fallback when Claude is recorded unavailable. Confidence, consensus, or a provider’s suggested action never creates authority. Reviewers must receive the exact candidate commit and must not edit, commit, push, deploy, or access secrets.

When a provider fails, preserve the diagnostic in the durable execution log, identify the actual cause, and continue independent authorized work. Common causes seen in this session were Gemini quota exhaustion, provider formatting/envelope mismatches, and reviewer CLI timeouts. The timeout fix must remain in `swarm/adapters.py`; killing only the wrapper process can leave a child reviewer running.

## Verification commands

Targeted reviewer/evidence checks:

```bash
python3 -m pytest -q tests/test_gemini_reviewer.py tests/test_review_runner.py tests/test_systemd_scope.py tests/test_accepted_work_evidence.py
```

Before release or final review:

```bash
python3 -m pytest -q
git diff --check
git status --short
```

Expected behavior is a clean worktree after each accepted change, with no deployment marker and no kill-switch clearance. If the repository is dirty before a cycle, inspect the diff first; never discard it blindly because it may be an uncommitted worker repair.

## Current state and next priorities

At the last verified snapshot, the queue contained completed work plus review/repair history, one external blocked item, and retained failed evidence. The queue had advanced through FWQ-0044, with later accepted repair commits including FWQ-0048 and FWQ-0049. Continue the oldest eligible review first. When reviewer quota or availability is restored, re-evaluate the parked exact-commit reviews one at a time, then promote dependencies and derive the next Core successor only when authorized.

FW-ASOC is roadmap/architecture authority only at this point. It must be implemented incrementally by reusing FW-ROOT, FW-ID, FW-MCP, FW-SOC, FW-EVID, FW-TEST, the Model Broker, Action Tickets, and Monitor → Repair → Review. Do not create a duplicate identity, policy, audit, or orchestration subsystem, and do not deploy FW-ASOC from the roadmap entry alone.
