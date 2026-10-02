# ForgeWarden Repository Consolidation Record

Date: 2026-10-01

## Canonical repository

- Repository: `jeffvato/forgewarden`
- Canonical branch: `main`
- Pre-rename consolidation checkpoint: `dfa7fb8d4ebece6c0661d0bd49e67ecf49e4ed8d`
- The repository was renamed from `jeffvato/forgewarden-swarm` to
  `jeffvato/forgewarden` after that checkpoint. The checkpoint is historical;
  determine the current canonical `main` commit from GitHub rather than treating
  this record as a moving status file.

## Hermes lineage

The historical `jeffvato/hermes-coding-swarm` repository is an ancestor of the
ForgeWarden repository, not a separate current product tree.

The latest preserved Hermes `main` commit at consolidation time was:

`595557ce15048e11f8aa8a7e94ee201c8772f668`

That exact commit exists in the ForgeWarden history. Comparing it to the
ForgeWarden pre-rename consolidation checkpoint shows ForgeWarden is 1,073
commits ahead and 0 commits behind. Therefore no Hermes changes need to be
merged into ForgeWarden to preserve current work.

## Preservation points

No repositories, branches, files, or commits were deleted during consolidation.

Preservation branches were created before cleanup. On 2026-10-02, read-only
remote ref checks in the repository owner's authenticated Git context confirmed
both exact bindings below; no credential material was displayed or recorded:

- `jeffvato/forgewarden:preservation/pre-consolidation-2026-10-01`
  -> `dfa7fb8d4ebece6c0661d0bd49e67ecf49e4ed8d`
- `jeffvato/hermes-coding-swarm:preservation/pre-consolidation-2026-10-01`
  -> `595557ce15048e11f8aa8a7e94ee201c8772f668`

## Repository roles going forward

### ForgeWarden

The ForgeWarden repository is the authoritative product repository. It includes
the security platform, product code, roadmap, evidence, tests, console, release
infrastructure, and the AI development harness.

### Hermes coding swarm

The Hermes repository is retained as historical provenance for the earlier
development harness. New ForgeWarden product development should not be committed
there.

Hermes remains a subsystem concept inside ForgeWarden's development harness;
it is not a competing source of truth for ForgeWarden.

## Branch policy

- `main`: authoritative tested ForgeWarden code.
- `feature/*`: temporary feature work.
- `fix/*`: temporary repair work.
- `fwq/*`: queue/work-item branches.
- `preservation/*`: historical rollback points; do not rewrite.

Future repository renames, default-branch changes, or archival actions must
preserve Git history and should occur only after verifying references and
integrations.
