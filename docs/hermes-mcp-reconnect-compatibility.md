# Hermes MCP reconnect compatibility patch

Hermes Desktop 0.18.2 includes `closedresourceerror` in its session-expiry
markers, but `_is_session_expired_error()` used `str(exc).lower()`. A bare
`anyio.ClosedResourceError()` has an empty string representation, while the
installed helper `_exc_str()` correctly returns `ClosedResourceError()`.
Consequently, the existing one-time reconnect path was not entered for the
Desktop error.

The compatibility patch changes only the session-expiry classifier to use
`_exc_str(exc).lower()`. It does not alter retry limits, transport handling,
the swarm bridge, or any agent execution.

## Guarded commands

From the swarm repository:

```bash
python3 scripts/hermes_mcp_compat_patch.py apply
python3 scripts/hermes_mcp_compat_patch.py rollback \
  --backup /home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-YYYYMMDDTHHMMSSZ
```

The utility requires `hermes-agent==0.18.2`, targets only the official Desktop
virtual environment, verifies exact pre/post SHA-256 values, refuses unknown
source, creates a mode-600 timestamped backup, is idempotent, and disables
rollback from an unexpected source hash.

The swarm bridge remains unchanged. Deployment is disabled and the swarm kill
switch remains engaged.

## Applied validation record

- Hermes package: `hermes-agent==0.18.2`
- Target: `/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/lib/python3.12/site-packages/tools/mcp_tool.py`
- Pre-patch SHA-256: `5781bd02572b40b7e5132235bbc4755f6ca5685f8a1b8772e7b47ed02925b129`
- Post-patch SHA-256: `1adb71a97786260fe8c258bf9c348ee3b5ea484de0150aad9469147ed2ec42de`
- Applied backup: `/home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T025000Z`
- Backup mode: `0600`
- Original diagnostic backup: `/home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T024758Z`

Validation completed:

- focused compatibility tests: 4 passed;
- complete swarm suite: 70 passed, 7 skipped;
- `pip check`: no broken requirements;
- `hermes mcp test coding_swarm`: connected and discovered all 4 tools;
- direct MCP session: 3 status calls passed with structured responses;
- patch apply is idempotent and reports `already applied` on the second run.

The package contains no separate Hermes MCP test files. The final UI-specific
check must be performed from a new Hermes Desktop session: invoke
`mcp_coding_swarm_status` and confirm the structured response contains
`mode=DRY_RUN`, `deployment=DISABLED`, and `kill_switch=ENGAGED`. The headless
`hermes serve` API has no standalone HTTP endpoint for invoking an MCP tool,
so this step is intentionally not simulated.

Rollback:

```bash
python3 scripts/hermes_mcp_compat_patch.py rollback \
  --backup /home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T025000Z
systemctl --user restart hermes-swarm-desktop.service
```
