# Gemini reviewer contract validation

The reviewer adapter now creates a per-job schema with:

- exact `job_id.const`;
- exact `reviewed_commit.const`;
- all nine required fields;
- `additionalProperties: false`.

The accepted field is `tests_missing`. The alias `missing_tests` is invalid and
is never normalized. `APPROVE` is rejected if `blocking_findings` or
`tests_missing` is non-empty.

`agy 1.1.17` exposes JSON-schema output. The adapter binds the dynamic schema
to the exact job and commit in both the CLI request and local validation. The
prompt also includes the exact required JSON structure as defense in depth. One
formatting-only retry is permitted; it receives only the validation error and
the same required structure, while retaining the same job, commit, and review
evidence. A second invalid response fails closed.

The adapter defaults to network isolation. A remote review can run only when
the trusted caller explicitly constructs it with `allow_external_review=True`;
that opt-in retains the read-only plan/sandbox mode, cgroup resource limits,
exact-SHA schema binding, and local validation. It does not authorize any
mutation, deployment, credential access, or other network action.

## Retained review recovery

The durable audit identifies the retained repair as:

```text
job: controlled-baseline-wnegqza6
repair: 535bb244d1cc79e65c07c029285255495531e6db
synthetic parent: 97b4edde003ef14e4469c02b58c5013a0d9aa8a5
clean baseline: bad64e7cf14e3c586d395341b25467841847dec6
```

The repair exists, its parent is the recorded synthetic defect, its diff is
only `csv-processor/app/ai/deadline.py`, and its complete tree equals the clean
baseline tree. The exact deterministic test is checked by the recovery command
before agy is permitted to review.

Jeff may run the review-only recovery from a normal WSL shell with:

```bash
cd /home/jeff/hermes-swarm-phase1
PYTHONPATH=. python3 -m swarm.cli gemini-review-recovery \
  --repository /home/jeff/swarm-repositories/n8n-csv-baseline-v2 \
  --job-id controlled-baseline-wnegqza6 \
  --repair-commit 535bb244d1cc79e65c07c029285255495531e6db \
  --runtime-root /home/jeff/hermes-swarm-runtime \
  --audit-dir /home/jeff/hermes-swarm-audit
```

This command does not invoke Codex, create defects, modify the baseline,
create commits, merge, push, deploy, or clear the kill switch. It uses a
temporary archive snapshot, records sanitized original-invalid and corrected
review evidence in the durable audit, and re-engages the kill switch on every
exit path. The command itself has not been executed during this validation.
