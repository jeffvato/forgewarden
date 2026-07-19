# Final v2 controlled exercise

Result: **STOPPED safely at deterministic preflight.**

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
