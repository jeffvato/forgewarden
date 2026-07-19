# Final v2 controlled exercise and writer validation

Summary: the earlier v2 attempt stopped at deterministic preflight; the later
authorized exercise reached Codex and stopped at the diff gate because no
authorized change was committed. The separate Codex writer capability probe
also reached Codex but was rejected for a structured job-ID mismatch. No
deadline repair was retried.

## Corrected baseline

The human-approved correction changed only:

```text
csv-processor/tests/swarm_regressions/test_deadline_contract.py
```

It wraps the complete `product_deadline(0)` statement in
`pytest.raises(ProductDeadlineExceeded)`, verifies that the context body is
never entered, and retains the positive-duration contract assertions. The
application deadline implementation was not changed.

The exact deterministic command passed before the baseline commit:

```text
working directory: <v2>/csv-processor
argv: [/home/jeff/anaconda3/bin/python3, -m, pytest, -q, -p, no:cacheprovider, tests/swarm_regressions/test_deadline_contract.py]
environment: explicit minimal allowlist; PYTHONDONTWRITEBYTECODE=1
result: 2 passed in 0.01s
```

Corrected authoritative baseline:

```text
bad64e7cf14e3c586d395341b25467841847dec6
```

The complete tree scan found 2 files with 0 findings. The complete reachable
Git-blob scan found 3 blobs with 0 findings. The corrected test is a regular
read-only file in the clean baseline.

## Conditional exercise

Job ID: `controlled-baseline-kps4zang`

The runner verified the exact baseline SHA, scanned the tree and Git blobs,
created a temporary worktree, resolved the test path inside it, and recorded
the working directory and argument array. The first unchanged-baseline
subprocess could not start under the required aggregate systemd scope:

```text
Failed to connect to bus: No medium found
```

This is an infrastructure preflight failure, not a test result. The runner
stopped before introducing the defect. Therefore:

- Codex was not invoked.
- No repair commit SHA exists.
- agy/Gemini was not invoked; no verdict exists.
- The kill switch was never cleared.
- The temporary worktree was removed by the runner cleanup path.
- The durable audit record is `/home/jeff/hermes-swarm-audit/audit.jsonl`.

No retry was attempted; this consumed the single authorized conditional
exercise.

## Final safety state

- Kill switch: **ENGAGED**.
- Deployment: **DISABLED**.
- v2 baseline: unchanged at `bad64e7cf14e3c586d395341b25467841847dec6`.
- Original `/home/jeff/n8n`: unchanged at `dd847c7e86ea62369537f46cf887aba799a441fa`.
- Old baseline: untouched.
- Docker and production: untouched.
- No production credentials, customer data, or database data were exposed.

The runner, baseline manifest, and this evidence document were updated in the
swarm repository only. No repair authorization remains to be executed.

## Systemd user-bus diagnosis and harmless scope proof

The earlier failure was environment-related, not a missing WSL systemd
installation. In the normal WSL shell, read-only diagnostics showed:

```text
PID 1: systemd
cgroup filesystem: cgroup2fs
systemctl is-system-running: degraded
uid: 1000 (derived by id -u)
/run/user/1000: present
/run/user/1000/bus: Unix socket
XDG_RUNTIME_DIR: /run/user/1000
DBUS_SESSION_BUS_ADDRESS: unix:path=/run/user/1000/bus
systemctl --user: responsive (degraded)
```

The earlier sandbox had PID 1 `bwrap` and denied bus access; it was not a
valid normal WSL systemd context. The swarm had also omitted the two bus
variables from its child environment. The runner now derives the UID and
adds only `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` when the matching
runtime directory and bus socket exist. No other environment expansion was
added.

A real process-level integration test now runs a harmless Python probe inside
the transient scope and verifies through cgroup files:

```text
MemoryMax: 2147483648
MemorySwapMax: 0
scope process: inside the transient cgroup
scope after exit: removed cleanly
```

The same corrected launcher executed `/bin/true` successfully in the
transient scope. The complete swarm test suite passed: **29 tests passed**.
No repair job, Codex process, Gemini process, Docker command, or production
operation was run. The kill switch remains engaged and deployment remains
disabled.

## Authorized exercise result: `controlled-baseline-287uxzal`

The later explicit exercise passed every pre-agent gate:

```text
baseline: bad64e7cf14e3c586d395341b25467841847dec6
tree scan: 2 files, 0 findings
Git-blob scan: 3 blobs, 0 findings
unchanged deterministic test: PASSED
seeded defect: FAILED with expected AssertionError
MemoryMax: 2147483648
MemorySwapMax: 0
```

The kill switch was then cleared for this job and Codex was invoked. The
post-agent diff gate found no committed authorized change:

```text
controlled exercise changed unexpected authorized files: []
```

The runner re-engaged the kill switch on this failure path. No repair commit
SHA exists, so agy/Gemini did not review a commit and has no verdict. The
temporary worktree was removed after the failure was recorded in the durable
audit at `/home/jeff/hermes-swarm-audit/audit.jsonl`.

No retry or automatic correction was performed.
