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
