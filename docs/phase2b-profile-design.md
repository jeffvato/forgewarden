# Phase 2B profile design

Phase 2B expands the local dry-run harness with additional preapproved repair
profiles. It does not authorize deployment, production access, remote control,
a real provider call, or a second real Phase 2A job.

## Product boundary

Every profile remains an immutable contract owned by the trusted orchestrator.
The caller may provide only a bounded issue summary. The caller must not choose
a repository, commit, path, command, interpreter, model, environment, or risk
classification.

Each profile must bind:

- an independently sanitized repository and exact baseline SHA;
- a canonical writable path allowlist;
- one deterministic regression test and failure fingerprint;
- fixed resource, patch, file-count, and concurrency limits;
- Codex as the only writer and Gemini as an exact-commit reviewer;
- deployment forbidden and the same engaged-kill-switch final state.

## Candidate profiles

### `csv_deadline_dry_run_v1` — retained baseline

The existing deadline-contract profile remains the reference implementation.
It must not be changed while new profiles are evaluated.

### `console_asset_safety_dry_run_v1` — candidate A

Purpose: repair a narrowly seeded local management-console asset validation
defect, such as accepting a symlinked static asset.

Scope: a disposable fixture repository containing only the console asset
loader, one seeded regression, and a new regression-test directory. No network,
browser session, production site, or real Forgewarden installation is allowed.

Acceptance: the clean baseline passes, the seeded defect fails with an exact
fingerprint, the repair changes only the allowlisted loader and new regression
test, and Gemini approves the exact repair commit.

### `audit_review_dry_run_v1` — candidate B

Purpose: repair a narrowly seeded audit-review parsing defect, such as accepting
a malformed completion event as valid.

Scope: a disposable fixture repository containing only the audit consumer,
synthetic JSONL fixtures, and new regression tests. Audit contents must be
synthetic and secret-free.

Acceptance: malformed, symlinked, and replayed evidence remains fail-closed;
the deterministic test passes after the smallest repair; and no audit file,
runtime marker, or provider adapter is writable by the agent.

## Admission gates

A candidate is not a profile until it has all of the following:

1. a clean-baseline test and seeded-defect test;
2. a strict profile/schema validation test;
3. fake Codex and Gemini process tests;
4. path, symlink, secret, diff, resource, timeout, and cleanup tests;
5. a dry-run integration fixture proving exact commit binding;
6. a full and portable validator run;
7. a written threat-model review and rollback note.

Any missing evidence keeps the candidate design-only and out of the MCP
profile registry.

## Sequencing decision

Implement candidate A first because it exercises the new management-console
surface without touching the protected repository or the existing Phase 2A
profile. Candidate B follows only after candidate A has a green complete gate.

Claude/Fable may review sanitized evidence from these candidates, but it cannot
write source, change admission, approve a commit, or become a required gate.
