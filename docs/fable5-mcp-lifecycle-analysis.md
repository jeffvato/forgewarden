# Fable 5 MCP-lifecycle analysis

## Result

The bounded Fable 5 adapter was implemented and exercised against the
recorded MCP-lifecycle task with the emergency kill switch engaged,
autonomous dry-run disabled, and deployment disabled. Fable did not return a
structured analysis before the adapter timeout, so this document contains no
model-derived findings.

Model identifier: `claude-fable-5`.

## Invocation evidence

The corrected diagnostic invocation was:

- job ID: `fable-e8c12174a2344306a56fdc4f`
- task cap: `$35.00`
- timeout: 120 seconds for this diagnostic attempt
- result: `TIMEOUT`
- provider exit code: unavailable because the child was terminated by the
  adapter timeout
- structured result: absent
- reported provider cost: `$0.00`
- tools: none
- edits, shell, Git, MCP mutation, deployment: denied/not exposed

Sanitized evidence is retained at:

`/home/jeff/hermes-swarm-audit/fable-evidence/fable-e8c12174a2344306a56fdc4f.json`

The first implementation attempt was interrupted before it could persist a
canonical job ID. The adapter was corrected to settle reservations and persist
failure evidence on interruption, and the reservation was released with no
reported cost. This telemetry defect is recorded as
`fable-interrupted-unrecorded` in the local ledger and must not be treated as a
successful Fable invocation.

Ledger state after both attempts:

- hard ceiling: `$100.00`
- spent: `$0.00`
- reserved: `$0.00`

## Safety result

No Codex, Gemini, worker, repair, deployment, baseline mutation, Docker access,
production access, or `/home/jeff/n8n` access occurred. No safety gate was
cleared.

## Local verification note

The new adapter tests passed. A subsequent full-suite run exposed unrelated
pre-existing Hermes compatibility/environment drift: the installed client did
not match the recorded compatibility-patch hash, the bare
`ClosedResourceError` regression failed, the generation helper signature
differed, and the official probe exceeded its test timeout. No Hermes package
or compatibility patch was changed during this task. Those failures remain a
separate project blocker and are reported without guessing or repairing them.
