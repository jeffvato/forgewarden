# Candidate B audit-review design

Profile: `audit_review_dry_run_v1`

Status: registered fixture-only. Candidate B is not connected to the active
runner, and deployment remains disabled.

## Purpose and boundary

Candidate B will evaluate a disposable, synthetic audit consumer that must
reject malformed completion events. It may use only synthetic JSONL fixtures;
it must not read live audit files, runtime markers, provider output, customer
data, credentials, or production repositories.

The only proposed writable paths are `swarm/audit_consumer.py` and
`tests/swarm_regressions/`. The deterministic contract must cover malformed,
symlinked, replayed, and correctly formed events, with fail-closed behavior for
every invalid case.

## Threat model and controls

- Malformed event acceptance: require a strict event schema, required terminal
  fields, and explicit rejection of unknown or contradictory states.
- Replay acceptance: bind event identity and sequence to the synthetic job and
  reject duplicate terminal events.
- Symlink or path escape: keep all JSONL fixtures inside the disposable
  fixture, reject symlinked inputs, and validate canonical paths before reads.
- Secret leakage: use synthetic values only; scan fixture, patch, evidence, and
  reviewer output for secret-like assignments and customer identifiers.
- Scope expansion: compare claimed and actual Git changes against the two-path
  allowlist and reject binaries, submodules, caches, or unexpected files.
- Resource abuse: retain Candidate A limits: one job, one Codex attempt, two
  Gemini attempts, 2 GiB memory, zero swap, 45 CPU seconds, 180 seconds wall
  time, and 256 KiB logs.
- Reviewer confusion: Gemini must review a read-only snapshot and approve the
  exact repair commit SHA; no approval may be inferred from a branch or message.

## Admission checklist

Candidate B remains design-only until it has:

- a disposable repository with an exact baseline and seeded failure;
- deterministic tests for malformed, replayed, symlinked, and valid events;
- fake Codex/Gemini exact-commit binding;
- secret, scope, resource, timeout, cleanup, and rollback checks;
- sanitized persisted evidence and schema validation;
- portable and full validation runs; and
- human review of this design and evidence bundle.

## Rollback

If this admission is withdrawn, remove only Candidate B’s exact Phase 2B
registry entry and dedicated fixture artifacts, then rerun the portable and
full validators. No runtime marker, systemd unit, provider adapter, live audit
file, or protected repository may be changed by Candidate B.
