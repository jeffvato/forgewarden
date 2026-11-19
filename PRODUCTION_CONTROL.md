# ForgeWarden Production Control

Effective: 2026-11-18  
Canonical repository: `jeffvato/forgewarden`  
Canonical base: `main`

## Operating mode

ForgeWarden is now managed as one production-engineering track. Parallel experimental, architecture, and feature tracks are parked unless Jeff / Customer Root explicitly reopens them.

This is a development-control decision, not a production deployment authorization. Existing safety posture remains unchanged:

- `DRY_RUN` remains enforced.
- Deployment remains `DISABLED`.
- The kill switch remains engaged where configured.
- AI workers do not gain Git, merge, policy, credential, deployment, or authority-expansion rights.
- Trusted deterministic controls remain above model-generated instructions.

## Parked tracks

The following pull requests were closed without merge on 2026-11-18 and are historical evidence only:

- PR #9: FWQ-0115 Sentinel prerequisite hardening
- PR #11: open-core trust boundary

Their branches and commits may be consulted for future recovery or reimplementation, but neither is canonical production work.

The branch `feature/daybreak-blue-verification` is also non-canonical. Its API-oriented access assumptions do not match the current approved Daybreak Blue access path and it must not be merged as-is.

## Active production workflow

1. Start from current canonical `main`.
2. Select one bounded production task.
3. Codex is the sole application-code writer for that task.
4. Run deterministic tests, invariants, architecture checks, Product Integrity, and applicable Golden Paths.
5. Produce one exact candidate commit.
6. Verify that exact commit using Daybreak Blue through the user's approved ChatGPT/Codex plan/session.
7. If Blue is unavailable, fail closed. Do not substitute a legacy reviewer automatically.
8. Repair findings through Codex, rerun deterministic validation, and create a new exact candidate if needed.
9. Merge only an accepted candidate to `main`.
10. Begin the next task only after the previous task is merged or explicitly abandoned.

## Billing and external infrastructure

- Do not require an OpenAI API key for the current Daybreak Blue verification path.
- Do not add paid API fallback.
- Azure is retired for the current ForgeWarden path and must not be reconnected without explicit Customer Root approval.
- The GitHub-native cloud build is the active desktop-independent validation layer.

## Immediate production objective

Reconcile the stale reviewer and queue assumptions on `main`, then select the smallest bounded implementation needed to move ForgeWarden toward a production-capable Sentinel/runtime path without enabling live deployment or endpoint response authority.
