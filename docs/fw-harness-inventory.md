# FW-HARNESS Phase H1 architecture inventory

Date: 2026-09-09  
Inventory requirement: FW-HARNESS-001  
Repository checkpoint inspected: `09442959fe64c3c33e01e23d1e60c2e32df13ba8`

## Scope and conclusion

ForgeWarden already contains the foundation of the permanent governed engineering harness. The existing trusted Python orchestration path must remain canonical. FW-HARNESS formalizes and incrementally consolidates it; it does not authorize a second controller, a second evidence system, production deployment, or broader model authority.

FW-HARNESS permanently lives inside ForgeWarden Core. It also governs ForgeWarden's own coding work from its activation forward, replacing repeated manual continuation with persisted, policy-controlled development. This is self-hosting through the same trusted controller, not a parallel development project. During incremental implementation, existing harness components remain the active governed path until each canonical FW-HARNESS interface replaces its legacy representation with validated compatibility.

The current implementation can persist a bounded queue, recover interrupted leases, select dependency-complete work, dispatch a scoped Codex worker, inspect and commit bounded changes through trusted Git code, run deterministic tests, obtain exact-commit Claude review, create bounded repair successors, checkpoint progress, and continue. The largest gap is not absence of orchestration. It is fragmentation between three task/state representations and incomplete coverage of the permanent schema, budgets, context evidence, approval classes, worktree lifecycle, and Mission Control status.

## Existing canonical components

| Concern | Existing owner | Current behavior | H2+ gap |
|---|---|---|---|
| Persistent control files | `swarm.supervisor_state` | Safely reads and validates the repository control documents and resume checkpoint. | Keep as operator-facing control evidence; map it to one canonical task record. |
| Requirement/task selection | `swarm.task_selection`, `swarm.control_manifest` | Parses `WORK_QUEUE.md`, validates dependencies/cycles, and deterministically chooses eligible Core work. | Parser supports only `FWQ-####` execution IDs and a legacy state vocabulary. Requirement IDs need a separate stable field and richer lifecycle mapping. |
| Durable task engine | `swarm.autonomous_loop.AutonomousOrchestrator` | Atomically persists queue/runtime state, worker leases, retries, tests, review and acceptance; recovers stale/orphaned work and continues bounded runs. | `TaskSpec`, queue records, and required FW-HARNESS fields need one versioned schema and validated transition table. |
| Checkpoints/resume | `swarm.work_checkpoint`, `swarm.continuation` | Integrity-hashed atomic checkpoints, Git reconciliation, exact-once continuation admission, bounded repair/replay. | Checkpoint is work-unit evidence rather than the complete task record; legacy `gemini_review` remains for compatibility. Stage-level resume evidence needs explicit integration. |
| Safety/stop policy | `swarm.policy_gate`, `swarm.stop_conditions`, `AGENTS.md` | Enforces DRY_RUN, disabled deployment, engaged kill switch, authorization and stop conditions outside model output. | Approval classes and budget/security stop reasons need canonical machine-readable representation. |
| Worker mediation | `swarm.autonomous_adapters.CodexWorkerAdapter`, `WorkerLease` | Codex receives an approved task and relative allowed paths; returned changes are checked against scope. | Define a generic registered-worker protocol, explicit output schema, capability references, and resource accounting without granting shell/Git authority to models. |
| Deterministic validation | `run_deterministic_tests`, repository tests, `swarm.integrity` | Harness runs configured tests and the standing integrity gate; model claims do not establish success. | Represent validation requirements/results as structured lifecycle evidence and support bounded check classes. |
| Read-only review | `swarm.review_runner`, `swarm.claude_verifier`, `swarm.review_handoff` | Creates isolated exact-commit snapshots, validates job/SHA/schema binding, and requires Claude APPROVE/LOW under D-020. | Store normalized reviewer identity/configuration and advisory findings in the canonical task lifecycle. |
| Git authority | `swarm.autonomous_loop.GitCheckpointController`, `swarm.core` | Trusted code checks scope, computes diffs, creates commits, records exact hashes, and rejects unsafe state. | Add an explicit isolated-worktree lifecycle and protected-branch/rollback policy interface before concurrency. |
| Audit/evidence | `swarm.accepted_work_evidence`, `swarm.review_evidence`, `swarm.audit_integrity`, autonomous JSONL log | Binds accepted commits, validation and reviews; writes durable execution events. | Route lifecycle events through FW-EVID interfaces and add prompt/context hash, denied actions, budgets and checkpoint references without creating another evidence store. |
| Capabilities/Action Tickets | `swarm.asoc`, `swarm.action_ticket`, FW-ROOT/FW-ID/FW-KEYS | Provides tenant-bound identities, leases/budgets and signed single-use authorization primitives. | Consume these interfaces in advanced governance; do not duplicate issuance or signature ownership in FW-HARNESS. |
| Model policy | `swarm.model_broker`, review adapters, D-020/D-021 | Separates writer/reviewer roles and prevents required-review substitution. | Bind workers to the Approved Model Registry with role, data, tool and budget constraints. |
| Mission Control | `swarm.console`, `console/` | Local plan-only console exposes bounded job/evidence views. | Add a sanitized harness snapshot containing task, queue, dependencies, commits, gates, retry/budget use, next action and kill-switch state. |
| Monitoring/recovery | autonomous lease recovery, audit/integrity checks | Detects stale/orphaned work, review outages and invalid durable state; bounded recovery is logged. | Consolidate anomaly categories and Monitor -> Repair -> Review outcomes under explicit limits. |

## Existing execution path

The implemented path is already aligned with the required architecture:

1. Hermes/user supplies approved work through persistent control evidence.
2. The trusted controller validates safety and durable state.
3. Queue and dependency code selects one eligible task.
4. A bounded lease scopes the Codex worker.
5. Trusted adapters inspect changed paths, run deterministic validation, and create an exact candidate commit.
6. Claude reviews an isolated snapshot of that exact commit with read-only access.
7. The controller validates review binding and disposition, accepts, repairs within limits, or blocks.
8. Checkpoint, Git hash, and audit evidence are persisted before continuation.

Model output enters this path only as untrusted worker or reviewer input. It does not own state transitions, policy, validation, Git, deployment, credentials, or the kill switch.

## Consolidation order

1. **FW-HARNESS-002:** introduce one versioned canonical task record and deterministic transition contract, with adapters for the existing queue and autonomous state. Preserve existing evidence compatibility.
2. **FW-HARNESS-003:** add auditable targeted context packets and hashes, plus per-task/session call, token, retry and elapsed-time budgets.
3. **FW-HARNESS-004:** expose the canonical read-only harness snapshot in Mission Control.
4. **FW-HARNESS-005:** add explicit worktree lifecycle and stage-level crash reconciliation around the existing trusted Git controller.
5. **FW-HARNESS-006:** integrate existing FW-ID/FW-ROOT leases, Action Tickets, FW-EVID, FW-KEYS and Approved Model Registry interfaces after their contracts are stable.

The worker interface must cover two governed transports: registered local CLIs and approved APIs. API credentials are FW-KEYS-managed secret references resolved only inside trusted adapter code and are never task/context/audit payloads. Provider activation, credential classes, and network routes remain approval-gated. Swarm hardening is a standing requirement across every milestone, with adversarial proof for replay, crash recovery, stale leases, path escape, identity substitution, malformed model output, resource exhaustion, and fail-closed interruption.

Each item is a bounded milestone. None enables production deployment or grants models authority.
