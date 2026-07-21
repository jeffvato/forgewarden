# Hermes MCP keepalive and reconnect validation

## Evidence

The local stdio bridge was exercised with the installed MCP SDK: initialize,
tools/list, status, repeated ping/status calls, malformed tool arguments, and
clean session closure all completed without stdout protocol corruption. The
bridge transport uses persistent fd-backed streams; protocol frames stay on
stdout and diagnostics stay on stderr.

Independent timing of the real launcher under Hermes' filtered environment
showed spawn in under 1 ms, first protocol response in 418--509 ms,
`initialize` completion in the same interval, `initialized` notification
delivery immediately afterward, `tools/list` in 419--510 ms, and clean EOF in
512--603 ms. Three repeated runs had no stderr output and no child leaks.

The official probe now completes successfully in 1.33 s wall time:

```
✓ Connected (654ms)
✓ Tools discovered: 5
```

The acceptance test uses the official Hermes executable and dedicated
`HERMES_HOME`; it asserts five-tool discovery under five seconds. The direct
MCP session also passes repeated ping/status calls. The long-running
`MCPServerTask` diagnostic remains opt-in because Hermes' own process-group
reaper can terminate the invoking test group during teardown; the acceptance
path isolates that subprocess with a new session and retains the historical
three accelerated keepalive evidence.

## Root causes

1. Hermes performed a network-bound OSV malware preflight before starting a
   fixed absolute local bridge executable. In the filtered WSL environment the
   preflight timed out at 12 seconds and the remaining startup/teardown work
   exceeded Hermes' fixed 20-second probe budget. The compatibility patch skips
   that package lookup only for an existing absolute local executable; package
   resolving commands retain the existing OSV check.
2. Hermes created the asyncio selector loop in one thread and ran it in
   another. In WSL, `call_soon_threadsafe()` callbacks could remain queued
   while the selector slept indefinitely. The patch creates the loop in its
   owner thread and bounds selector sleep with a 50 ms wakeup timer.
3. Hermes’ reconnect readiness was boolean-only. `_ready` remains set for the
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
- Local-startup patch post-SHA256: `b7b5c60e79409f009256c0705c8dbb974b374e468ae9373416550d31315f9d65`
- Loop-owner patch post-SHA256: `1764639bca5249d9cc01fd0c0525b5d732f7623626b28b3c33dded31fef7ec10`
- Loop-wakeup patch post-SHA256: `bc13c3ab73ecfe3a2e2f4ca486ec0b773d4c76de089f219e4e0db5547cf17d51`
- Latest target SHA-256: `bc13c3ab73ecfe3a2e2f4ca486ec0b773d4c76de089f219e4e0db5547cf17d51`
- Timestamped backups for the latter patches are retained under
  `/home/jeff/hermes-swarm-desktop-backend-backups/`.

Apply or verify:

```bash
/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_generation_patch.py apply
```

The reproducible follow-on patches are applied in order:

```bash
.../python scripts/hermes_mcp_local_startup_patch.py apply
.../python scripts/hermes_mcp_loop_owner_patch.py apply
.../python scripts/hermes_mcp_loop_wakeup_patch.py apply
```

Rollback:

```bash
/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_generation_patch.py rollback \
  --backup /home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T172305Z-generation
systemctl --user restart hermes-swarm-desktop.service
```

Each follow-on script has a fixed pre/post hash, refuses unknown source, is
idempotent, creates a mode-0600 timestamped backup, and provides a guarded
rollback command. Roll back in reverse order using the corresponding backup
path, then restart `hermes-swarm-desktop.service`.

The patches do not change retry count, deploy behavior, swarm activation, the
kill switch, or any repository. No Phase 2A job, Codex, or Gemini call was run
during this validation.
