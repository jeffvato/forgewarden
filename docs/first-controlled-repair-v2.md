# First controlled repair — sanitized v2 baseline

Result: **FAILED safely during the single authorized job**.

The v2 filesystem and Git-object scans passed before the job. The runner
created a temporary worktree, introduced the deadline defect, cleared the
parallel kill switch for this one job, and invoked Codex. The deterministic
stage then failed because the committed runner still referenced the superseded
test path `tests/test_ai_watcher_deadline.py`; the minimal v2 tree correctly
contains only `tests/swarm_regressions/test_deadline_contract.py`.

The runner cleaned up the temporary worktree and re-engaged the kill switch.
No Gemini review was authorized after deterministic failure, and the v2
baseline branch was not changed.

## Evidence

```text
v2 repository: /home/jeff/swarm-repositories/n8n-csv-baseline-v2
v2 baseline: 9cf4d5933b5563fe079e17ccdd8d33b8169de2db
job: one controlled-baseline invocation
tree scan: 2 files, 0 findings
Git blob scan: 2 blobs, 0 findings
Codex: invoked; repair worktree cleaned up
deterministic result: FAILED — obsolete test path not found
agy/Gemini: not run after deterministic failure
kill switch: ENGAGED
deployment: DISABLED
audit: /home/jeff/hermes-swarm-audit/audit.jsonl
```

The durable audit contains the v2 scan, worktree, kill-switch, Codex, and
failure state records. It contains no secret values. The failed repair commit
was confined to the temporary worktree and was not merged into v2 `main`.

## Controls verified

- The old `/home/jeff/swarm-repositories/n8n-csv-baseline` was not used and
  remains undeleted and unmodified.
- `/home/jeff/n8n` remained untouched.
- Docker and production services were not accessed.
- The v2 repository has a fresh single commit, no alternates, and no old Git
  history or objects.
- The writable policy remains limited to `deadline.py` and new files under
  `tests/swarm_regressions/`; existing tests and all other files are read-only.
- The 2 GiB aggregate cgroup, `MemorySwapMax=0`, environment scrubbing, and
  network-denial policy are required for the agent/check subprocesses. The
  deterministic check failed before a successful gate/review result could be
  produced.

## Required before another authorization

The runner has been corrected in the swarm repository to use:

```text
python3 -m pytest -q tests/swarm_regressions/test_deadline_contract.py
```

Because the single authorized job was consumed by the failed attempt, no
second kill-switch clearance was performed. A new explicit authorization is
required before retrying. Deployment remains disabled.
