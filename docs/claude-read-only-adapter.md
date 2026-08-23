# Regular Claude read-only reviewer

The swarm has an explicit, opt-in reviewer for the installed Claude Code CLI.
It is separate from the Fable credit adapter and is not connected to Phase 2A,
the MCP bridge, job submission, recovery, or deployment.

The accepted aliases are bound to these exact full model strings:

```text
sonnet -> claude-sonnet-4-6
opus   -> claude-opus-4-5
haiku  -> claude-haiku-4-5-20251001
```

The adapter validates the alias and binds the same full model string into both
the CLI request and the structured-output schema, so a provider response from
a different model is rejected. Sonnet 5 is not configured because the
installed CLI did not expose it.

The adapter sends only the caller-provided context after local redaction and a
24,000-byte bound. It does not read repository files, audit logs, credentials,
production data, or `/home/jeff/n8n`. The child receives only the normal Claude
Code authentication environment, fixed locale/path settings, and no copied
credential values.

The exact-commit verifier runs from a disposable archived snapshot and permits
only Claude's read-only file tool so it can inspect the candidate files it was
given. Shell, Git, edit, MCP, network, and Chrome access remain disabled. The
general advisory adapter runs from a fresh temporary directory with no tools.

The exact-commit verifier is bounded to twenty-four turns and 180 seconds, while
the general advisory adapter remains bounded to three turns. Both use plan mode,
disables tools, disables session persistence, and requires strict structured
JSON bound to the job ID and selected model. Results remain in memory; the
adapter writes no provider evidence and cannot authorize mutations.

The fake-CLI tests verify the exact read-only argv, sanitized payload, model
allowlist, schema binding, timeout/process failure behavior, and absence of
durable provider output. No real Claude invocation is part of repository CI.

The packaged explicit entry point is:

```bash
packaging/hermes-swarm claude-review \
  --job-id claude-000000000000000000000000 \
  --model sonnet \
  --context-file /path/to/sanitized-review-context.txt
```

The command requires the caller to name the context file; it does not inspect
the current repository or automatically send project files. It is not exposed
through the MCP bridge and cannot start a Phase 2A job.
