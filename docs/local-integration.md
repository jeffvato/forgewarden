# Local CLI integration record

Discovered executable paths:

| CLI | Path | observed result |
| --- | --- | --- |
| Hermes | `/home/jeff/.local/bin/hermes` | local wrapper; `--print-prompt` succeeds |
| Codex | `/home/jeff/.local/bin/codex` | `codex-cli 0.144.6`; authenticated; `exec` probe succeeds |
| Gemini | `/home/jeff/.nvm/versions/node/v24.11.1/bin/gemini` | `0.50.0`; invocation reaches CLI but authentication is rejected |

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
Gemini is invoked with `--approval-mode plan`, `--sandbox`, JSON output, and a
separate read-only snapshot tied to the exact full commit SHA.

## Current blocker

The real Gemini command was reached but returned this authentication error:

```text
Error authenticating: IneligibleTierError: This client is no longer supported for Gemini Code Assist for individuals. To continue using Gemini, please migrate to the Antigravity suite of products: https://antigravity.google
```

The same invocation also reported:

```text
RangeError: WebAssembly.instantiate(): Out of memory: Cannot allocate Wasm memory for new instance
```

The process was run with a measured resource cap and exited nonzero. No review
was accepted and no learned rule was activated. The end-to-end acceptance test
therefore remains incomplete until Jeff provides a supported local Gemini
authentication/account configuration or installs a supported local Gemini CLI
client. No production deployment is authorized by this state.
