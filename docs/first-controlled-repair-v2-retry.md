# First controlled repair — v2 retry

Result: **FAILED safely during the one authorized retry**.

All preconditions were verified before starting: swarm HEAD contained
`85682e7`, v2 was exactly at `9cf4d5933b5563fe079e17ccdd8d33b8169de2db`,
only v2 was allowlisted, deployment was disabled, the kill switch was
engaged, and the v2 repository was clean.

## Job evidence

```text
job_id: controlled-baseline-96f6cufh
baseline: 9cf4d5933b5563fe079e17ccdd8d33b8169de2db
tree scan: 2 files, 0 findings
Git blob scan: 2 blobs, 0 findings
worktree: created from exact baseline SHA
authorized defect: temporary deadline.py copy only
Codex: invoked
deterministic command attempted: python3 -m pytest -q tests/swarm_regressions/test_deadline_contract.py
deterministic result: FAILED — path not found from repository root
repair commit: not retained; temporary worktree removed
agy/Gemini: not run after deterministic failure
audit: /home/jeff/hermes-swarm-audit/audit.jsonl
```

The required repository-relative command is
`python3 -m pytest -q csv-processor/tests/swarm_regressions/test_deadline_contract.py`.
The runner has been corrected to use that exact command, but this authorization
was consumed and no further retry was performed.

## Final safety checks

- Kill switch: `ENGAGED`.
- Deployment: `DISABLED`.
- v2 baseline branch remains at
  `9cf4d5933b5563fe079e17ccdd8d33b8169de2db` and is clean.
- The old baseline was not accessed, deleted, or modified.
- `/home/jeff/n8n` remains at HEAD `dd847c7e86ea62369537f46cf887aba799a441fa`
  with its prior working state unchanged.
- Docker and production were untouched.
- Existing tests remained read-only; no baseline test was modified.
- The durable audit contains scan, worktree, kill-switch-clear,
  Codex-start, deterministic-check, kill-switch-reengagement, and failure
  records for the exact job ID.
- No repair SHA or Gemini verdict exists because deterministic checks failed.

The corrected runner is committed as a swarm implementation change. A new
explicit authorization would be required for any future execution.
