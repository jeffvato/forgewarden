# Hermes Desktop coding-swarm bridge

The Desktop backend now loads a local stdio MCP server named
`coding_swarm`. The bridge is intentionally limited to four tools:

```text
status
job_status
recent_audit
engage_kill_switch
```

No repair, deployment, merge, push, shell, Git, filesystem, prompt,
resource, or sampling tool is registered. MCP protocol traffic is written only
to stdout; diagnostics use stderr.

## Fixed runtime contract

The launcher is:

```text
/home/jeff/.local/bin/hermes-swarm-mcp
```

It accepts no arguments, changes to `/home/jeff/hermes-swarm-phase1`, sets the
swarm repository as `PYTHONPATH`, and execs the official Hermes Python. Bridge
subprocesses use fixed argv arrays, `shell=False`, a minimal environment, and
10-second timeouts. Audit access is read-only. Kill-switch engagement invokes
only the fixed `hermes-swarm kill-switch` command and verifies the resulting
status.

Audit output is restricted to timestamp, job ID, state, event, verdict, risk,
repair commit, and categorized errors. Corrupt JSONL fails closed; prompts,
model output, environment values, credentials, and secret-shaped data are not
returned.

## Hermes configuration

The Desktop configuration contains the additive `mcp_servers.coding_swarm`
entry with four selected tools, resources disabled, prompts disabled, and
sampling disabled. A timestamped pre-change backup was created at:

```text
/home/jeff/hermes-swarm-desktop-home/config.yaml.backup-20260720T020723Z
```

## MCP and package validation

Installed Hermes metadata for `hermes-agent==0.18.2` declares
`mcp==1.26.0` for its MCP extras. Only that exact version was installed in the
official Desktop virtual environment. `hermes-agent` remained `0.18.2`.

```text
pip check: No broken requirements found
import mcp: passed (1.26.0)
MCP_SERVER_AVAILABLE: True
YAML parse: valid
hermes mcp test coding_swarm: connected; 4 tools discovered
complete swarm suite: 64 tests passed
```

The Desktop service was restarted only after these validations. Its backend
continues to bind to `127.0.0.1:9120` and use the dedicated Desktop Hermes
home.

## Safety state

```text
mode: DRY_RUN
deployment: DISABLED
kill switch: ENGAGED
```

No `/home/jeff/n8n`, Docker, production service, Codex writer, Gemini
reviewer, or repair job was accessed or invoked.
