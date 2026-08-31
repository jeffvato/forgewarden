# ForgeWarden Swarm Status

## Current state

- Active phase: ForgeWarden Core
- Current focus: FW-ASOC-02 — model-token budget containment
- Current task: enforce a requested per-work model-token budget at canonical work admission.
- Queue source: `WORK_QUEUE.md`
- Repository safety mode: DRY_RUN
- Deployment: disabled
- Kill-switch policy: remains engaged where configured
- Codex role: sole application-code writer
- Claude role: architecture/requirements/adversarial reviewer
- Gemini role: independent read-only exact-commit reviewer

## Resume protocol

On every restart or continuation:

1. Read `AGENTS.md`, `ROADMAP.md`, `WORK_QUEUE.md`, `SWARM_STATUS.md`, `DECISIONS.md`, `BLOCKERS.md`, and relevant specs.
2. Inspect Git status, HEAD, recent commits, and repository tests.
3. Reconcile this status file with actual repository evidence.
4. If a task was interrupted, resume from the last provably valid checkpoint rather than restarting the project.
5. Otherwise claim the highest-priority READY task whose dependencies are complete.
6. Run the full Codex → deterministic validation → Claude review → Gemini exact-commit review → Codex repair/revalidation cycle.
7. After acceptance, checkpoint and immediately continue to the next READY task.

## Work-unit checkpoint

- Task ID: FW-ASOC-02 — model-token budget containment, per-work admission
- Starting commit: `b54113e`
- Product checkpoint: `ccbb3cd` (recovery release proof)
- Accepted handoff commit: `fc81f90` (records the proven tenant-wide slice)
- Canonical owner: `CapabilityAuthorizer.admit_work` is the canonical work-admission boundary; it composes signed `CapabilityLease` limits, `DeterministicPolicy` scope ceilings, the existing work admission ledger, and the canonical audit sink. Model execution remains a future extension at the existing Model Broker boundary, not a new execution system.
- Acceptance criteria: model-bound work declares a non-negative request; a positive request is required for policy-bound model work; policy carries a positive token ceiling; admission denies a request above the smaller signed lease and policy ceilings; admission Evidence records all three values; no authorization, model, audit, or execution subsystem is duplicated.
- Negative paths: negative, boolean, fractional, and text requested counts; omitted/zero request for model-bound policy work; missing policy ceiling; request above policy or lease ceiling; later aggregate tenant splitting, recovery, expiry, and audit-failure paths remain required before this control is fully proven.
- Proof plan: focused ASOC/policy tests cover malformed input, required limits, policy and lease cap denials, and admission evidence. The next unit will atomically reserve aggregate model tokens through the existing work ledger and prove release, recovery, expiry, concurrency, and tenant-splitting denials before broader validation.
- Exact first change: add `requested_model_tokens` to `AuthorizationRequest`; at `admit_work`, require and bound it for model-bound policy work, and include the lease/policy/requested token values in canonical admission Evidence.
- First product checkpoint: `cc70943acb9d4b0fd9ad58bc28963b53d5930d77` (`Bind ASOC leases to model token limits`).
- Files changed: in progress — `swarm/asoc.py`, `tests/test_asoc.py`, `SWARM_STATUS.md`.
- Deterministic validation: focused ASOC/policy admission tests passed (`102 passed` in the Linux repository runtime); `git diff --check` passed. Prior tenant-wide capacity evidence remains `84` focused tests, `473 passed, 1 skipped` full suite, and a passing integrity gate at `ccbb3cd`.
- Review: pending for this new meaningful commit; the external exact-review adapter returned no structured payload for the prior schema commit, so no independent approval is claimed.
- Health: YELLOW only for the pre-existing `pip check` dependency finding and unimplemented roadmap ownership for identity, normalized events, SOC incidents, and compliance.
- Blocker: none.
- Next action: commit and review per-work admission enforcement, then atomically reserve aggregate model-token capacity through the existing `WorkBudgetLedger`.

## Execution log

- 2026-08-30: Re-evaluated the FW-ASOC-01 canonical-integration gap. `ROADMAP.md`, `DECISIONS.md`, `swarm/integrity.py`, and the functionality map consistently identify Action Tickets, Model Broker, MCP Gateway, and full Z3 as canonical owners, but no concrete adapters are present in this checkout. No replacement subsystem was added: absent canonical validation continues to deny authorization. Next safe work remains bounded hardening and proof at the existing fail-closed boundary.
- 2026-08-30: Corrected AI kill-switch scope. It now revokes only model-bound AI identities and their leases, preserving unbound human deterministic-administration identities as required. Focused ASOC security tests passed (31 passed).
- 2026-08-30: Reviewer recovery check: the installed Claude CLI completed a bounded read-only invocation successfully. The prior exact-review attempt returned no validated payload and was therefore correctly rejected as evidence; no approval was inferred from the recovery check.
- 2026-08-30: Full Product Integrity Gate completed for `85eac87525b3691817c35bbdb074f585c3813ea9`: build, configuration, startup, repository, tests, and ASOC Golden Path passed; 552 tests passed with 1 host-dependent skip, and the Golden Path passed 31 tests. Health remains YELLOW only for the pre-existing local `tzdata` dependency warning and roadmap owners not yet implemented in this checkout.
- 2026-08-30: Clean-build recovery validation: a new isolated Python environment installed the pinned `requirements-test.txt` dependencies, passed `pip check`, and completed the full suite with 552 passed and 1 host-dependent skip. The OS-managed interpreter warning is no longer a reproducibility concern; roadmap ownership gaps remain the YELLOW integrity finding.
- 2026-08-30: Exact read-only Claude review of `5970dc9` returned CHANGES_REQUESTED/MEDIUM and identified a fail-closed gap for unknown action classes. Repaired by restricting leases to supported action classes and retaining the authorization fallback regardless of kill-switch state. Added negative-path regression coverage; focused ASOC validation passed (33 passed).
- 2026-08-30: Delegation groundwork hardening: non-delegable leases now require zero delegation depth, preventing contradictory future-delegation state. Added regression coverage; focused ASOC validation passed (34 passed).
- 2026-08-30: Canonical Action Ticket integration: added signed, tenant/agent/lease/action/policy-bound, short-lived, single-use tickets and connected them to mutating ASOC authorization. Direct and integrated negative-path validation passed (39 passed).
- 2026-08-30: FW-ASOC-01 canonical integration now includes deterministic policy, Action Tickets, Model Broker, MCP Gateway, durable evidence, atomic ticket consumption, and tenant/agent/role/deployment/kill-switch recovery revocation. The runnable Golden Path proves authorized operation plus replay, kill-switch, recovery, and cross-tenant denials.
- 2026-08-30: FW-ASOC-01 proof checkpoint: the exact commit `b4880fb` passed the full repository suite (578 passed, 1 skipped) and its read-only exact-snapshot quality review. The ASOC-specific audit-sink findings were verified as intentional fail-closed handling; no ASOC repair was required. The functionality map now records FW-ASOC-01 as Proven, while external adapters and full Z3 remain future roadmap work.
- 2026-08-31: FW-ASOC-02 aggregate blast-radius checkpoint: deterministic policy rules can now carry an exact tenant/capability/resource/action limit. Authorization atomically reserves configured aggregate radius through lease expiry, denies cross-agent splitting attempts, records the requested radius in evidence, and releases reservations during recovery revocation. Focused ASOC, policy, and integrity validation passed (66 passed).
- 2026-08-31: FW-ASOC-02 resource-budget checkpoint: lease-bound concurrent-work limits are validated and signed, enforced through the canonical CapabilityAuthorizer and deterministic policy, audited on admission/denial/completion, isolated under concurrency, released on expiry and recovery, and bounded across delegation. Exact review found no new slice finding; the full suite passed (473 passed, 1 skipped) and the integrity gate passed all checks at `2dc0b59`, remaining YELLOW only for the pre-existing dependency and roadmap-ownership gaps.
- 2026-08-31: FW-ASOC-02 tenant-wide capacity checkpoint: deterministic policy now requires a positive tenant limit as well as the per-lease limit, and the shared ledger atomically prevents cross-agent work splitting. Recovery releases only the revoked agent's allocation. Exact review of `ccbb3cd` found no new slice defect; the full suite passed (473 passed, 1 skipped) and the integrity gate passed all checks, remaining YELLOW only for the pre-existing dependency and roadmap-ownership gaps.

## Stop conditions

Do not stop merely because a task or review cycle finished. Stop only under the explicit conditions in `AGENTS.md`, and record the exact reason and first resume action here.

## Current stop condition

- Reason: NONE
- Exact condition: no external or human blocker is known.
- First resume action: derive and begin the next bounded FW-ASOC-02 control from the current handoff checkpoint.
