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

Targeted validation passed: **13 tests passed**. The fake CLI edited only its
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

## Final safety state

- Deployment: **DISABLED**.
- Kill switch: **ENGAGED**.
- Active Hermes: untouched.
- Both baselines: untouched.
- `/home/jeff/n8n`, Docker, and production: untouched.
