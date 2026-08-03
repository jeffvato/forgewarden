# Fable 5 MCP-lifecycle analysis

## Result

The bounded Fable 5 adapter was exercised against the recorded MCP-lifecycle
task with the emergency kill switch engaged, autonomous dry-run disabled, and
deployment disabled. The successful invocation returned structured,
model-derived findings for the disposable harness only. It did not access
tools, files, shell, Git, MCP mutation, or deployment.

Model identifier: `claude-fable-5`.

## Invocation evidence

The corrected diagnostic invocation was:

- job ID: `fable-a74b730a3d9240d582908b12`
- task cap: `$35.00`
- result: `SUCCEEDED`
- reported provider cost: `$0.90`
- tools: none
- edits, shell, Git, MCP mutation, deployment: denied/not exposed

Sanitized evidence is retained at:

`/home/jeff/hermes-swarm-audit/fable-evidence/fable-a74b730a3d9240d582908b12.json`

The first implementation attempt was interrupted before it could persist a
canonical job ID. The adapter was corrected to settle reservations and persist
failure evidence on interruption, and the reservation was released with no
reported cost. This telemetry defect is recorded as
`fable-interrupted-unrecorded` in the local ledger and must not be treated as a
successful Fable invocation.

The earlier interrupted attempts remain recorded as failures and did not
consume budget. Ledger state after the successful invocation:

- hard ceiling: `$95.93`
- spent: `$0.92` (including a prior `$0.02` successful invocation)
- reserved: `$0.00`

## Findings and bounded follow-up

Fable identified evidence drift between the postmortem and the lifecycle
fixture, a possible module-shadowing risk, reliance on private SDK teardown
internals, a timer race in the replay assertion, incomplete teardown coverage,
and an environment-inheritance ambiguity. The first follow-up patch is
limited to the disposable acceptance harness: it verifies the imported
`tools.mcp_tool` path, accepts the documented `QUEUED`/`SUCCEEDED` timing
window, and returns through normal async teardown instead of `os._exit(0)`.
Runtime behavior, production access, and deployment remain unchanged.

## Safety result

No Codex, Gemini, worker, repair, deployment, baseline mutation, Docker access,
production access, or `/home/jeff/n8n` access occurred. No safety gate was
cleared.

## Local verification note

The focused lifecycle module passed (3 tests), the full suite passed (215
tests, 1 skipped), and portable validation passed (141 tests). A private Azure
ACR validation image from the previous green cycle remains available as
`forgewarden/validation:20260803-cycle2`; a later rebuild was not published
because its disposable source archive encountered an unreadable `.save`
backup artifact. No Hermes package or compatibility patch was changed.
