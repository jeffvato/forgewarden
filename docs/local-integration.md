# Local CLI integration record

Discovered executable paths:

| CLI | Path | observed result |
| --- | --- | --- |
| Hermes | `/home/jeff/.local/bin/hermes` | local wrapper; `--print-prompt` succeeds |
| Codex | `/home/jeff/.local/bin/codex` | `codex-cli 0.144.6`; authenticated; `exec` probe succeeds |
| Gemini-compatible reviewer | `/home/jeff/.local/bin/agy` | `1.1.4`; Antigravity CLI, `--print --mode plan --sandbox` succeeds |

The integration command is:

```bash
cd ~/hermes-swarm-phase1
PYTHONPATH=. python3 -m swarm.cli dry-run
```

Hermes is invoked through its non-mutating `--print-prompt` interface, so the
existing `/home/jeff/hermes-sandbox/review/task.md` is not changed. Codex is
invoked as `codex exec` with workspace-write, an isolated fixture worktree,
`--skip-git-repo-check`, and a Codex-compatible projection of the supplied
schema. The returned JSON is then validated against the full supplied schema.
The Gemini-compatible reviewer is invoked as `agy --print --mode plan --sandbox`, and its
separate read-only snapshot tied to the exact full commit SHA.

The combined exact-commit review runner is:

```bash
PYTHONPATH=. python3 -m swarm.cli review-cycle \
  --repository /path/to/repository \
  --candidate-commit <full-commit-sha> \
  --job-id phase2a-abcdefghijklmnopqrstuvwx \
  --context-file /path/to/sanitized-review-context.txt \
  --allow-external-review
```

It creates two independent disposable Git archives from the same exact commit,
invokes Claude and `agy` concurrently, validates both responses against the exact
job ID and commit, and returns
`APPROVED` only when both are low-risk approvals with no blocking findings or
missing tests. Provider failures are returned as `UNAVAILABLE`; they never
become approval evidence. The external-review flag is explicit because the
Gemini-compatible reviewer needs provider network access.

## Verification result

The initially discovered `gemini` command returned an unsupported-account error,
so the adapter correctly uses the installed `agy` command instead. `agy` was
verified with a read-only probe and then in the complete fixture run.

```text
Error authenticating: IneligibleTierError: This client is no longer supported for Gemini Code Assist for individuals. To continue using Gemini, please migrate to the Antigravity suite of products: https://antigravity.google
```

The earlier `gemini` invocation also reported:

```text
RangeError: WebAssembly.instantiate(): Out of memory: Cannot allocate Wasm memory for new instance
```

The final `agy` run succeeded. It reviewed exact commit
`d01beac00d48aef1c286d1f5a9069cb18dbacb69`, returned `APPROVE` / `LOW`, and
produced a valid schema-conforming review. No learned rule was proposed or
activated. The final audit record is retained under the ignored
`.integration-runtime/` directory. No production deployment is authorized by
this state.
