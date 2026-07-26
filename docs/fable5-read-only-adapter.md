# Fable 5 read-only adapter

The swarm now has a bounded advisory adapter for the recorded Fable 5 credit
program. It is not part of Phase 2A execution and cannot invoke Codex, Gemini,
workers, deployment, Git, shell tools, or MCP mutation.

## Contract

- CLI: `/home/jeff/.local/bin/claude`
- Model: `claude-fable-5`
- Permission mode: `plan`
- Claude tools: empty allowlist
- Output: JSON with a dynamic job-ID schema
- Timeout: 300 seconds
- Per-analysis cap: the program-defined target (the MCP lifecycle task is $35)
- Aggregate hard ceiling: $100
- Authentication: Claude Code's existing user-supported mechanism; no token is
  copied into the child environment or recorded
- Input: fixed sanitized swarm context only; no audit log, credentials,
  protected repository, production source, customer data, or `/home/jeff/n8n`

The adapter reserves the configured cap before invoking the provider and
settles the ledger from the provider's structured `total_cost_usd`. It refuses
to start if the cap exceeds the remaining budget. Malformed output, missing
cost, wrong model, wrong job ID, schema failure, timeout, and CLI failure are
recorded as failed/invalid evidence and fail closed.

Ledger and evidence are local, mode-restricted files:

- `/home/jeff/hermes-swarm-audit/fable-budget.json`
- `/home/jeff/hermes-swarm-audit/fable-evidence/<job-id>.json`

Fable findings are advisory evidence only. They cannot activate rules, alter
the kill switch, enable autonomous dry-run, authorize a repair, or change the
Phase 2A gate.

## Fake-CLI acceptance

The adapter is covered first by real process-level fake-CLI tests. They verify
the exact argv, working directory, minimal environment names, dynamic schema
const binding, exact `claude-fable-5` identity, plan/no-tools restrictions,
sanitized prompt delivery, malformed identity rejection, and
`total_cost_usd` settlement without contacting the provider.
