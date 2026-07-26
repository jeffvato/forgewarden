# Hermes Desktop coding-swarm bridge

The Desktop backend now loads a local stdio MCP server named
`coding_swarm`. The bridge is intentionally limited to seven tools:

```text
status
job_status
recent_audit
engage_kill_switch
run_preapproved_job
submit_preapproved_job
workflow_status
```

No repair, deployment, merge, push, shell, Git, filesystem, prompt,
resource, or sampling tool is registered. MCP protocol traffic is written only
to stdout; diagnostics use stderr.

The bridge uses FastMCP's persistent `stdio` transport. It remains alive for
the lifetime of its client session, handles repeated tool calls on that same
session, and converts tool exceptions into MCP `isError` results. A normal
client close, cancellation, or EOF is handled as session shutdown without a
traceback or protocol corruption. Each Desktop stdio connection has its own
bridge process, so closing one connection cannot terminate an independent
connection.

## ClosedResourceError / WSL pipe validation

The initial failure was a transport-level stall during initialization rather
than a repair-tool failure. In this WSL environment, the pinned MCP 1.26.0
server helper did not reliably consume the child stdin pipe through its
`anyio.wrap_file(TextIOWrapper)` reader. The bridge therefore uses a small
fd-based reader/writer shim around the official MCP memory streams. It keeps
newline-delimited JSON-RPC framing unchanged, reads only fd 0, writes only
protocol frames to fd 1, and leaves diagnostics on stderr.

The bridge's MCP server handler remains the official FastMCP handler. Its
exception path returns structured MCP `CallToolResult` responses with
`isError=true`; malformed audit data and invalid arguments therefore do not
terminate the session. A client cancellation is isolated to that stdio child.
The Desktop service and any other independent MCP child are unaffected.

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
entry with seven selected tools, resources disabled, prompts disabled, and
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
hermes mcp test coding_swarm: connected; 7 tools discovered
complete swarm suite: 108 tests passed, 1 skipped
```

The lifecycle regression additionally verifies three repeated `status` calls,
an invalid `job_status` call returning `isError=true`, continued operation
after that error, and survival of a separate stdio session after the first
session closes.

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
