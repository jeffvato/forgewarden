# Final conditional v2 repair exercise

Result: **STOPPED at deterministic preflight**.

The preconditions were verified and the final conditional exercise was
started once. The v2 tree and Git-object scans passed. A temporary worktree
was created from the exact baseline, and the test path was constructed from
that worktree root. The unchanged baseline test did not pass because the
minimal v2 tree has no importable `app` package on pytest's default path:

```text
ModuleNotFoundError: No module named 'app'
```

The runner stopped before introducing the defect, clearing the kill switch,
or invoking Codex. No automatic correction or additional exercise was
attempted.

## Job evidence

```text
job_id: controlled-baseline-nwn7jjot
baseline: 9cf4d5933b5563fe079e17ccdd8d33b8169de2db
tree scan: 2 files, 0 findings
Git blob scan: 2 blobs, 0 findings
temporary worktree: created, then removed
test path: constructed as csv-processor/tests/swarm_regressions/test_deadline_contract.py
baseline test: FAILED during import collection
defect introduced: no
Codex: not invoked
deterministic post-repair test: not run
repair commit: none
agy/Gemini: not invoked
audit: /home/jeff/hermes-swarm-audit/audit.jsonl
```

Because the first preflight gate failed, the kill switch was never cleared;
there is no kill-switch-clear event for this job. The durable audit contains
the scan, exact baseline SHA, worktree, and failure state. The path and
working-directory audit event is now emitted before baseline execution for
future authorized runs; this failed run predates that audit-placement fix.

## Final safety state

- Kill switch: `ENGAGED`.
- Deployment: `DISABLED`.
- v2 baseline branch: unchanged at
  `9cf4d5933b5563fe079e17ccdd8d33b8169de2db`.
- Existing tests: read-only; no test was modified.
- Old baseline: not accessed, deleted, or modified.
- `/home/jeff/n8n`: unchanged at HEAD `dd847c7e…` with its prior working
  state intact.
- Docker and production: untouched.
- No Codex, networked repair, or reviewer process ran.

The runner and integration tests were committed after this stopped exercise;
another explicit authorization would be required before any further run.
