# Disposable MCPServerTask fixture postmortem

## Finding

The failing fixture did not match the working Desktop initialization path. It
used a plain `FastMCP(...).run(transport="stdio")` server and called
`MCPServerTask.run()` directly. Under Hermes' filtered WSL environment that
fixture never reached readiness: the task advanced to connection generation 1,
but `_ready_generation` remained 0 and the retry log reported an unhandled MCP
TaskGroup error. The disposable server's stderr contained no application
exception.

The production bridge instead uses the project's persistent fd stdio transport,
and its launcher supplies `PYTHONPATH` and the dedicated `HERMES_HOME`. The
fixture also omitted the production environment's `HOME`, locale, and
`PYTHONNOUSERSITE` entries. A direct JSON-RPC probe against the corrected
fixture received `initialize` in under one second, proving the fixture server
itself was valid.

## Correction

The acceptance fixture now:

- imports and uses `_persistent_stdio_server`, the same transport as the
  production bridge;
- uses the public `MCPServerTask.start()` entrypoint;
- runs with the filtered `PATH`, `HOME`, locale, `PYTHONNOUSERSITE`,
  `PYTHONPATH`, and dedicated `HERMES_HOME` values;
- closes the active MCP session task group to force transport closure;
- verifies a strictly newer connection/readiness generation;
- performs three accelerated ping/status keepalive cycles;
- performs a fake-only idempotent Phase 2A admission/replay check;
- verifies terminal fake-worker state, consumed lease, no orphan processes,
  engaged kill switch, disabled autonomous mode, and disabled deployment.

## Acceptance evidence

The corrected process-level test completed in approximately 4.1 seconds. It
verified generation `1` followed by a strictly newer generation `2`, successful
status after reconnect, the same fake job ID on replay, terminal `SUCCEEDED`
state, and `CONSUMED` lease state.

No real Codex, Gemini, repair job, baseline, Docker, production repository, or
production service was accessed. The official Hermes discovery probe remained
separately validated at five tools under five seconds.

This correction changes only the disposable test harness and documentation;
it does not change Hermes or swarm production behavior.
