# Hermes MCP keepalive and reconnect validation

## Evidence

The local stdio bridge was exercised with the installed MCP SDK: initialize,
tools/list, status, repeated ping/status calls, malformed tool arguments, and
clean session closure all completed without stdout protocol corruption. The
bridge transport uses persistent fd-backed streams; protocol frames stay on
stdout and diagnostics stay on stderr.

An accelerated `MCPServerTask` run with `keepalive_interval=5` remained alive
through three keepalive windows and subsequent ping/status calls. The earlier
`hermes mcp test coding_swarm` probe has a 20-second CLI probe budget while
this local WSL process takes longer to complete its first stdio lifecycle
startup; the opt-in process-level lifecycle test uses a 55-second bound and records
the full accelerated run.

The post-patch direct command was re-run. The bridge itself passed the direct
SDK session (five tools and three ping/status calls), but
`hermes mcp test coding_swarm` still timed out at its fixed 20-second probe
budget (`MCP call timed out after 20.0s`). This is an explicit remaining
validation limitation, not reported as a pass.

## Root causes

1. The bridge needed explicit lifecycle coverage for MCP base-protocol ping
   and clean cancellation/EOF. Its fd transport was retained and hardened
   so closed peers are contained by the transport task rather than written to
   stdout or terminating unrelated sessions.
2. Hermes’ reconnect readiness was boolean-only. `_ready` remains set for the
   original connection unless carefully cleared, so a session-expired call
   could retry before a strictly newer initialized session existed. The
   compatibility patch adds monotonically increasing connection and ready
   generations and requires `ready_generation > old_generation` before the
   one-time retry.

## Installed compatibility patch

- Hermes: `hermes-agent==0.18.2`
- Target: `/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/lib/python3.12/site-packages/tools/mcp_tool.py`
- Generation patch pre-SHA256: `1adb71a97786260fe8c258bf9c348ee3b5ea484de0150aad9469147ed2ec42de`
- Generation patch post-SHA256: `a4aa9a701de75fa0970180e94c7ac326c39b862b31bc5e3bbacef4346f48d1f0`
- Backup: `/home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T172305Z-generation`

Apply or verify:

```bash
/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_generation_patch.py apply
```

Rollback:

```bash
/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_generation_patch.py rollback \
  --backup /home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T172305Z-generation
systemctl --user restart hermes-swarm-desktop.service
```

The patch does not change retry count, deploy behavior, swarm activation,
the kill switch, or any repository. No Phase 2A job, Codex, or Gemini call was
run during this validation.
