# Regular Claude read-only reviewer

The swarm has an explicit, opt-in reviewer for the installed Claude Code CLI.
It is separate from the Fable credit adapter and is not connected to Phase 2A,
the MCP bridge, job submission, recovery, or deployment.

The default model is the official Claude CLI `sonnet` alias. `opus` and `haiku`
are the only other accepted choices. The alias is intentional: it lets the
installed Claude CLI select the account’s current Sonnet release without the
swarm hard-coding an unverified future model ID such as “Sonnet 4.6” or
“Sonnet 5”.

The adapter sends only the caller-provided context after local redaction and a
24,000-byte bound. It does not read repository files, audit logs, credentials,
production data, or `/home/jeff/n8n`. The child receives only the normal Claude
Code authentication environment, fixed locale/path settings, and no copied
credential values.

The process runs from the fixed empty-purpose `/tmp` working directory rather
than any repository checkout, so Claude Code cannot infer a project from the
swarm’s caller working directory.

Each invocation is bounded to three turns and 180 seconds, uses plan mode,
disables tools, disables session persistence, and requires strict structured
JSON bound to the job ID and selected model. Results remain in memory; the
adapter writes no provider evidence and cannot authorize mutations.

The fake-CLI tests verify the exact read-only argv, sanitized payload, model
allowlist, schema binding, timeout/process failure behavior, and absence of
durable provider output. No real Claude invocation is part of repository CI.
