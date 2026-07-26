# Phase 2A preapproved Desktop jobs

Phase 2A adds one restricted execution tool to the existing local stdio MCP
bridge:

    run_preapproved_job(profile_id, issue_summary)
    submit_preapproved_job(profile_id, issue_summary)

The bridge still exposes only safe status/audit operations plus the guarded
preapproved capability. It does not expose shell commands, repository paths,
test commands, model names, environment variables, writable paths, deployment,
merge, push, or standalone kill-switch clearing.

## Threat model and profile

The committed profile is 'csv_deadline_dry_run_v1' in
config/desktop-job-profiles.yaml, validated by
schemas/desktop-job-profile.schema.json. It binds execution to the
independent repository /home/jeff/swarm-repositories/n8n-csv-baseline-v2
at baseline bad64e7cf14e3c586d395341b25467841847dec6.

Only csv-processor/app/ai/deadline.py and new files beneath
csv-processor/tests/swarm_regressions/ are eligible. Existing tests and all
other files are read-only. The exact deterministic test runs from
<worktree>/csv-processor using
tests/swarm_regressions/test_deadline_contract.py. The current local profile
binds its interpreter to the absolute path
/home/jeff/anaconda3/bin/python3. The runner never uses PATH lookup, shell
activation, /usr/bin/env, or an ambient python3. Before pytest starts it
verifies the canonical executable target, interpreter SHA-256, sys.executable,
Python version, pytest import/version, and bounded stdout/stderr. A future
public profile may replace this machine-specific binding only with a separately
reviewed absolute interpreter configuration validated by the same checks.

The runner enforces one concurrent job, one Codex attempt, the existing
Gemini schema-correction retry limit, aggregate 2 GiB memory, no swap, CPU and
wall-clock limits, patch size/line/file limits, no binaries, symlinks,
submodules, caches, or network. Codex is the only writer; the trusted
orchestrator stages and commits validated files. Gemini receives an isolated
read-only snapshot and reviews the exact commit SHA. Learned rules are
recorded as proposals only.

## State transitions

AUTONOMOUS_DRY_RUN is a one-job lease independent of deployment and the
emergency kill switch:

    DISABLED --local preflight--> ENABLED
    ENABLED + kill switch cleared --one job--> RUNNING
    RUNNING --success/failure/timeout--> DISABLED + kill switch engaged
    RUNNING --crash, next startup--> RECOVERED_ABANDONED + DISABLED + engaged

The initial and final state are DISABLED. Enabling never clears the kill
switch and never starts a job. `run_preapproved_job` remains fail-closed while
the kill switch is engaged. `submit_preapproved_job` is the only guarded
clear-and-submit path: it performs all admission checks, acquires the one-job
lock, clears the switch internally, and starts the approved worker. Every
execution path re-engages the kill switch and consumes the lease.

## Durable queue and worker

The MCP tool performs admission, atomically consumes the one-job lease, writes
QUEUED state and audit evidence, starts the local
hermes-swarm-phase2a-worker@JOB.service user unit, and returns the canonical
job ID without owning the repair lifetime. The worker performs the complete
clean-baseline -> trusted synthetic defect commit -> Codex -> deterministic
checks -> trusted repair commit -> Gemini sequence.

The unit is installed at
/home/jeff/.config/systemd/user/hermes-swarm-phase2a-worker@.service and is
not enabled or started by installation. It uses the fixed local Python,
control-group termination, MemoryMax=2 GiB, MemorySwapMax=0, and no network
for worker-owned commands. Provider communication remains confined to the
existing adapters and their controls. A bridge disconnect or restart does not
cancel a worker. Recovery requires both an expired heartbeat and the absence
of the verified worker PID/start-time identity; a new bridge never abandons a
live worker.

The trusted worker seeds and commits exactly one synthetic defect before Codex.
The required seed hash is
8546054f0e2542f77afa975b1ba8dbe3561059537d2252ae0a290e0e02966d17, and the
approved deterministic failure fingerprint is the first assertion line
matching `assert 30.x <= 30`. Codex is never invoked unless both the hash and
exit-1 fingerprint gates pass. The repair is measured against the synthetic
defect parent and must restore the complete clean baseline tree.

## Local-only commands

    hermes-swarm autonomous-dry-run-status
    hermes-swarm autonomous-dry-run-enable
    hermes-swarm autonomous-dry-run-disable
    hermes-swarm kill-switch

Worker service inspection and rollback:

    systemctl --user status 'hermes-swarm-phase2a-worker@*.service'
    systemctl --user daemon-reload
    systemctl --user disable --now hermes-swarm-phase2a-worker@JOB.service

The last command is only for an explicitly identified worker instance. To
remove the inactive template after stopping all identified instances, move
the unit file out of the user-unit directory, run daemon-reload, and verify
that no Phase 2A worker unit is active. The swarm launcher and MCP bridge
remain installed; the kill switch is the emergency stop.

Enable validates the exact profile, clean baseline, scans, user bus, cgroup
v2, deployment-disabled state, and profile/implementation hashes. To execute
one later job, Jeff enables the autonomous lease locally, then uses the Hermes
Desktop tool `mcp__coding_swarm__submit_preapproved_job` with the fixed profile
ID and a plain-text issue summary. The tool performs the guarded one-job clear
internally; no kill-switch file should be removed manually.

## Audit, replay, and recovery

Accepted and rejected requests receive immutable job IDs in the durable audit.
An atomic runtime lock blocks concurrency and replay through the single-use
lease. Audit values are redacted and no prompt, credentials, customer data,
raw model output, or unrestricted command output is returned by MCP.

The runner creates a detached disposable worktree from the exact baseline,
never writes the baseline checkout, and removes the worktree and read-only
review snapshot after evidence is durable. A RUNNING state found on the next
request engages the kill switch and disables the lease before allowing new
work.

For a terminal `RECOVERED_ABANDONED` state, the local command
`hermes-swarm phase2a-recover-terminal` performs a narrower cleanup. It
requires no verified worker, deployment disabled, the kill switch engaged, and
autonomous dry-run disabled. It removes only stale `phase2a-job.lock` and
`RUNNING` markers, preserves `phase2a-state.json` byte-for-byte, and records
the cleanup in the durable audit. Failed preconditions leave all markers
untouched; the command never submits or starts a job.

## Adding profiles safely

Adding a profile requires a new versioned YAML object and matching strict
schema constants. It must bind an independent sanitized repository, exact
baseline SHA, canonical writable paths, deterministic tests, resource limits,
and an explicit deployment-forbidden value. Add process-level fake-adapter
tests for every failure gate. Do not broaden the MCP argument contract or
allow the caller to supply paths, commands, models, or environments.

## Portability

The current paths are intentionally absolute for this local WSL installation.
For a future GitHub release, replace them with installation-root discovery
that resolves only a trusted package root, preserve exact SHA/profile binding,
use platform-specific cgroup/job-object controls, and keep the same
fail-closed policy and local-only activation boundary.
