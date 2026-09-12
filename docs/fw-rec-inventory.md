# FW-REC ownership inventory and checkpoint contract

FW-REC-001 coordinates existing owners without replacing them.

| Recovery fact | Canonical owner |
|---|---|
| Task state, dependencies, retry and budget | harness_task, harness_controller |
| Stage persistence | utonomous_loop |
| Atomic work checkpoint | work_checkpoint |
| Git/worktree and accepted commit | trusted Git controller and acceptance gate |
| Lifecycle Evidence | vidence, harness_evidence |
| Monitoring, inert repair request and review | harness_recovery |
| Domain recovery proposals | existing domain recovery modules |
| Operator authority | policy, Action Tickets, leases and Customer Root |

RecoveryCheckpoint binds tenant, task, requirement, stage, starting/current
commits, changed-file digest, validation/review, authority freshness, budgets,
retries, Evidence tail, interruption, timestamp and safe resume decision. Its
exact schema rejects execution claims. It has no restore, rollback, restart,
delete, repair, containment, deployment, Git, filesystem or process mutation
method. It remains DRY_RUN metadata with deployment disabled and grants no authority.


## FW-REC-002 durable persistence

The canonical store writes one bounded, versioned, SHA-256-bound checkpoint by
private temporary file, file and directory fsync, and atomic replacement.
Reconstruction uses no resume side effect: it revalidates the entire contract
and exact caller-provided tenant, Git HEAD, Evidence tail, and consumed
checkpoint IDs. Unsafe paths, public permissions, corruption, truncation,
oversize input, replay, and stale bindings deny before state is returned.

## FW-REC-003 resume admission

`ResumeAdmission` is immutable decision metadata. It binds the exact checkpoint
digest, tenant, task, Git commit, Evidence tail, interruption class, remaining
budgets and retries, reason, and timestamp. The deterministic classifier emits
only `RESUME`, `BLOCK`, or `ROLLBACK_PROPOSAL`; it requires an engaged kill
switch and current authority, and it writes Evidence before returning a result.
It has no method or authority to execute any decision.

## FW-REC-004 integrated proof

The local lifecycle proof composes checkpoint creation, private atomic
persistence, restart reconstruction, exact resume admission, canonical Evidence
durability, restart Evidence reconstruction, safe retry after Evidence failure,
and replay/tamper/stale/cross-tenant denial. Product Integrity reports FW-REC as
Proven only for this metadata-only DRY_RUN coordination boundary. Restore,
rollback, restart, repair, deletion, containment, deployment, filesystem,
process, credential, network, and response execution remain outside FW-REC's
accepted implementation.
