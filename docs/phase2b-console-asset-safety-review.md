# Candidate A threat model and rollback note

Profile: `console_asset_safety_dry_run_v1`

Status: registered fixture-only. This note does not activate the profile.

## Threat model

The seeded defect is a static-asset loader that follows a symlink. The safety
objective is to ensure an asset request cannot escape the disposable fixture or
serve a path outside the approved asset tree.

Threats and controls:

- Symlink escape: the fixture contains a relative symlink and the repaired
  loader rejects `Path.is_symlink()` before reading. Snapshot validation also
  rejects external or broken links.
- Scope expansion: the fake writer is allowed only
  `swarm/console_asset_loader.py`; the orchestrator compares the claimed file
  list with the actual Git diff and rejects unexpected files.
- Reviewer confusion: the fake reviewer receives a read-only snapshot and its
  schema binds both job ID and exact repair commit SHA.
- Secret leakage: the fixture contains only synthetic text, no credentials,
  customer data, provider output, or live audit content. Agent environments use
  the existing sanitized environment policy.
- Replay or mutation: the fixture runs through the existing disposable
  worktree, mailbox, audit, quality-gate, and exact-commit paths. It never
  touches the protected repository or the active MCP registry.
- Resource abuse: the contract fixes one concurrent job, one Codex attempt,
  two Gemini attempts, 45 CPU seconds, 180 seconds wall time, 2 GiB memory,
  256 KiB logs, a two-file change limit, and no network except controlled
  adapters.

## Acceptance evidence

Proven locally:

- seeded symlink defect fails before repair;
- fake Codex changes only the loader and creates an exact repair commit;
- fake Gemini approves the exact commit in a read-only snapshot;
- dry-run reaches `SUCCEEDED`;
- Candidate A contract and symlink/mutation tests pass;
- full suite passes with the lifecycle gate enabled.

Still required before registry admission:

- persist a sanitized evidence artifact containing baseline, defect, repair,
  changed-file, and cleanup facts;
- add candidate-specific secret, resource, timeout, and rollback assertions;
- run portable validation with the Candidate A evidence test included;
- obtain a human review of this threat model and evidence bundle.

## Rollback

Candidate A has a dedicated Phase 2B admission entry and no production deployment path.
Rollback before admission is therefore deletion or archival of the design-only
contract, fixture test, schema, and this note. No runtime marker, protected
repository, systemd unit, or provider adapter is changed by Candidate A.

If this admission is later withdrawn, remove only the exact Phase 2B profile
registry entry and its dedicated fixture artifacts, run the full and portable
validators, verify the existing `csv_deadline_dry_run_v1` profile is
unchanged, and confirm `workflow-status` still reports dry-run, deployment
disabled, kill switch engaged, no lock, and no running marker.
