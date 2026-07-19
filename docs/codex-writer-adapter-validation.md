# Codex writer adapter validation

Result: **adapter contract corrected; fake process test passed; real
capability probe stopped on structured-result validation.**

No baseline, `/home/jeff/n8n`, Docker, or production repository was accessed.
Deployment remained disabled, and the kill switch remained engaged.

## Installed CLI

```text
executable: /home/jeff/.local/bin/codex
version: codex-cli 0.144.6
```

The installed CLI accepted the corrected ordering:

```text
/home/jeff/.local/bin/codex --ask-for-approval never exec --help
```

The global approval option is before the `exec` subcommand, as required by
this CLI. The exec sandbox is explicitly selected; no default is relied on.

## Sanitized invocation contract

For worktree `<WORKTREE>`, the adapter invokes the following argument array
(the optional `--add-dir` pair is included only when Git metadata is supplied):

```text
[
  "/home/jeff/.local/bin/codex",
  "--ask-for-approval", "never",
  "exec", "--ephemeral",
  "--sandbox", "workspace-write",
  "--skip-git-repo-check",
  "--cd", "<WORKTREE>",
  "--output-schema", "<WORKTREE>/.swarm/codex-result.schema.json",
  "--output-last-message", "<temporary-json-file>",
  "--color", "never", "--json",
  "<PROMPT-AS-FINAL-POSITIONAL-ARGUMENT>"
]
```

The subprocess working directory is `<WORKTREE>`, and `--cd` points to the
same directory. The prompt is delivered as the final positional argument;
stdin is empty. Codex runs in its own transient systemd scope with the
aggregate 2 GiB memory limit, `MemorySwapMax=0`, blocked network policy,
CPU/timeout limits, and log cap.

Only these environment names may be passed to Codex, when present or derived:

```text
PATH HOME LANG LC_ALL TERM CODEX_HOME OPENAI_API_KEY OPENAI_BASE_URL
XDG_RUNTIME_DIR DBUS_SESSION_BUS_ADDRESS SWARM_ROLE SWARM_DRY_RUN
SWARM_NETWORK_BLOCKED
```

Credential values are never logged. Proxy variables are removed. The two
systemd bus values are derived from `id -u` and included only when the runtime
directory and bus socket exist.

Nonzero exit codes produce a sanitized failure. The adapter records the exit
code, working directory, argument shape, environment names, and redacted
stdout/stderr. It requires a non-empty `--output-last-message` file, parses it
as JSON, validates the Codex contract, and requires the response `job_id` to
match the requested job. The structured final response is retained only in
sanitized form.

## Tests

The fake-CLI process integration test verifies the exact approval/sandbox
argument ordering, working directory, prompt, environment-name contract,
authorized fixture edit, and diff detection. The real systemd scope test also
verifies the cgroup controls and clean scope termination.

Targeted validation passed: **16 tests passed**. The fake CLI edited only its
fixture's authorized `value.py`; no agent or baseline was involved.

## Real disposable Codex capability probe

A new disposable Git repository contained `value.py` returning 1 and a
read-only test requiring `value() == 2`.

```text
unchanged test: failed as required (exit code 2)
Codex process: reached and returned a structured response
Codex exit: 0 (the adapter reached post-exit structured validation)
response validation: rejected
reason: expected job_id codex-writer-probe, received writer-probe
probe commit: not accepted by the adapter
post-repair test: not run after validation failure
```

The probe was run under the 2 GiB aggregate systemd cgroup, swap disabled,
blocked network policy, timeout, and log cap. Its temporary repository was
removed in a `finally` path, and the kill switch was re-engaged. Sanitized
probe evidence is preserved at:

```text
/home/jeff/hermes-swarm-audit/codex-writer-adapter-validation.jsonl
```

No retry or automatic correction was performed. The probe failure means real
Codex writer capability is not yet validated end-to-end; a separate explicit
authorization is required for any future probe or repair.

The failed pre-canonical probe’s sanitized evidence did not include a file
diff, so it cannot establish whether `value.py` changed before its response
was rejected. Its temporary repository no longer exists, and no change could
escape that disposable directory.

## Canonical-ID retry result

The one authorized retry generated this single job ID:

```text
codex-writer-a6d6b322889e422099c23046ad260973
```

That exact value was used for the audit record, prompt, dynamic output-schema
`const`, response validation, result filenames, and state evidence. The
structured Codex response was accepted for the exact ID. Codex changed only
`value.py`; no test or other source file was changed.

The probe nevertheless failed its required completion gates. The disposable
test repository was created incorrectly with literal backslash-n characters in
`test_value.py`, so the required unchanged and post-write pytest command
failed collection with exit code 2. The probe Git metadata was also not
writable to the Codex subprocess, so the permitted `value.py` change was not
committed. Consequently there is no valid probe commit and the diff/green-test
requirements were not satisfied.

The sanitized evidence records the generated ID, Codex exit code 0, exact
structured response summary, changed path, test exit code, cgroup controls,
and final kill-switch state at:

```text
/home/jeff/hermes-swarm-audit/codex-writer-adapter-validation.jsonl
```

The disposable repository was removed after evidence persistence. No retry,
deadline repair, Gemini review, baseline access, or production operation was
performed.

## Trusted-orchestrator writer-probe retry

The corrected checked-in fixture templates passed integrity, compilation,
collection, and seeded-assertion checks. The trusted orchestrator moved Git
metadata out of the Codex-visible worktree, and the process-level tests passed
for metadata isolation, authorized edits, unauthorized edits, claimed/actual
mismatches, hook suppression, explicit staging, and exact committed diffs.

The one authorized real retry used this newly generated canonical ID:

```text
codex-writer-56c6f44114774f6bbdcd31fa1d91be1d
```

Evidence:

```text
seeded test: FAILED_ASSERTION (exit 1)
Codex exit: 0
schema validation: PASSED; exact job ID matched
Codex claimed changed files: value.py
actual changed files: value.py plus two generated __pycache__ files
deterministic post-edit test: not reached
orchestrator commit: none
```

The orchestrator blocked the commit because the Codex subprocess generated
bytecode files while running its own test command. It captured before/after
hashes and changed paths, recorded the failure before cleanup, and kept the
kill switch engaged. The Codex environment is now corrected to set
`PYTHONDONTWRITEBYTECODE=1` and `PYTHONNOUSERSITE=1` for future probes; this
probe was not retried.

The disposable repository and its external Git metadata were removed only
after the sanitized evidence was written to the durable audit file. No
deadline repair or Gemini review was invoked.

## Final workspace-hygiene retry result

After the fixture-integrity and hygiene tests passed, the one authorized real
writer probe succeeded with canonical job ID:

```text
codex-writer-5992160844164b28823c55db4e4d0af3
```

Evidence:

```text
baseline commit: 507d8e4cdb19d236d81334f82aea0c22c7512189
preflight test: FAILED_ASSERTION (exit 1)
preflight hashes: unchanged
Codex exit: 0
schema validation: PASSED
claimed changed files: value.py
actual changed files: value.py
post-edit deterministic test: PASSED (exit 0)
staged files: value.py
committed diff: value.py
probe commit: 00dcc9de36023cb98bb3d4e4e8f65c3512450c90
secret scan: 4 files, 0 findings
external cache cleanup: PASSED
hook executed: no
```

The Codex subprocess inherited `PYTHONDONTWRITEBYTECODE=1`, a job-specific
`PYTHONPYCACHEPREFIX` beneath the disposable swarm runtime, and
`PYTEST_ADDOPTS=-p no:cacheprovider`. No cache or generated artifact appeared
inside the worktree. The orchestrator restored Git metadata only after Codex
returned, staged `value.py` explicitly, disabled hooks and signing, and
created the commit with the fixed Hermes Swarm identity.

The durable evidence is preserved in
`/home/jeff/hermes-swarm-audit/codex-writer-adapter-validation.jsonl`. The
kill switch is engaged, deployment remains disabled, and no deadline repair,
Gemini review, baseline, n8n, Docker, or production operation was performed.

## Final safety state

- Deployment: **DISABLED**.
- Kill switch: **ENGAGED**.
- Active Hermes: untouched.
- Both baselines: untouched.
- `/home/jeff/n8n`, Docker, and production: untouched.
