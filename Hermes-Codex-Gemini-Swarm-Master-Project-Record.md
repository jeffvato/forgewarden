# Hermes–Codex–Gemini Swarm: Master Project Record

Last updated: July 25, 2026 (through commit `7a582369eebdb18cf76acf01b7adcb101e161542`, the successful disposable lifecycle/reconnect/replay fixture, the phone/Android decisions, Claude CLI availability, and the Fable 5 credit directive)
Owner: Jeff Brown  
Primary machine: `FuzzyHoldings1`  
Platform: Windows 11 with Ubuntu under WSL2

## Why this file exists

This is the durable continuation record for the entire Hermes–Codex–Gemini coding-swarm project. A future ChatGPT, Codex, Hermes, Gemini, or human operator should be able to use this file to understand:

- what Jeff is building;
- why the system is structured this way;
- what has already been implemented and proven;
- what remains incomplete;
- what must never be weakened;
- where the important repositories, runtime state, audit records, launchers, and documentation live;
- how to resume without repeating the long diagnostic history;
- what evidence is required before advancing to deployment.

This document is a project record and implementation guide. It is not authorization to run a repair, clear a kill switch, deploy, publish, delete data, modify production, or broaden an allowlist.

## Executive summary

Jeff is building a local, reproducible coding swarm in WSL2 with strict separation of duties:

- **Hermes** is the user-facing orchestrator and gateway.
- **Codex** is the only agent allowed to write code.
- **Gemini**, accessed through the installed `agy` reviewer, is a read-only reviewer of one exact commit.
- **Claude CLI** is available for optional read-only diagnosis, planning, and test-gap analysis. It is not yet part of the active Phase 2A execution path.
- **The trusted Python orchestrator** owns policy, paths, hashes, tests, Git staging and commits, resource limits, audit evidence, cleanup, state transitions, and eventual deployment/rollback operations.
- **Jeff** controls activation, protected categories, repository onboarding, production eligibility, and expansion of authority.

The project currently operates only in `DRY_RUN`. Deployment is disabled. The emergency kill switch is engaged. A restricted Hermes Desktop MCP bridge is installed and can expose status, audit, emergency-stop, and a preapproved job-submission interface.

Phase 2A—the single-use, preapproved, dry-run job path—is implemented and has completed one real synthetic job. Commit `7a582369…` resolved the disposable `MCPServerTask` fixture blocker; commit `b119b4f…` added guarded submission and terminal recovery. Job `phase2a-1ab6c00f50704fd782e06e8d` completed with deterministic validation passed, Gemini verdict `APPROVE`, low risk, repair commit `3d3b9d8…`, and the final safety state restored to deployment disabled, autonomous dry run disabled, and kill switch engaged. The current swarm suite passes 108 tests with 1 skip.

## 2026-07-30 validation update

The disposable production-equivalent `MCPServerTask` acceptance gate was rerun locally with the explicit lifecycle diagnostic enabled. All three lifecycle cases passed: official discovery, strict newer-generation readiness, and the real disposable fixture covering readiness, three accelerated keepalives, forced reconnect, post-reconnect status, replay-safe fake enqueue, fake worker completion, and child cleanup. The full local suite passed 157 tests with no skips under that gate. The final workflow state remains `DRY_RUN`, deployment `DISABLED`, autonomous dry-run `DISABLED`, kill switch `ENGAGED`, lock absent, and no running or stale markers.

This validates the disposable lifecycle gate only. No additional systemd worker exercise, provider repair, deployment, remote host, credential, or `/home/jeff/n8n` operation was performed in this validation. Phase 2B remains unregistered and held.

Fable 5 accounting is now: hard ceiling `$95.93`, spent `$0.02`, remaining `$95.91`.

## Mission and design position

The system exists to repair well-defined, low-risk software issues while Jeff is away from his desk, without giving any model broad or production-level authority.

AI output is treated as untrusted evidence. Deterministic checks and trusted code—not model confidence—decide whether a job advances.

The intended mature workflow is:

```text
trusted trigger
  -> Hermes validates an immutable job profile
  -> trusted admission and deduplication
  -> disposable worktree
  -> trusted reproducer proves the defect
  -> Codex proposes a narrowly scoped repair
  -> trusted diff, hash, secret, and test gates
  -> trusted orchestrator creates the exact commit
  -> Gemini reviews that exact commit read-only
  -> result is audited
  -> dry-run stops OR a separately authorized deployment executor acts
  -> health checks
  -> rollback on failure
  -> Jeff receives a fixed completion summary
```

## Phone and Android decisions: unattended and remote operation

The discussions Jeff had from his phone are part of the project requirements, not informal side notes.

### One front door

Hermes must be Jeff's single operational front door. Jeff should not have to copy messages between Hermes, Codex, Gemini, or ChatGPT.

The intended unattended communication path is:

```text
Jeff gives Hermes an approved objective
  -> Hermes validates and durably queues it
  -> a persistent supervised worker invokes Codex
  -> trusted deterministic checks validate the result
  -> Gemini reviews the exact retained commit read-only
  -> Hermes reports the audited outcome to Jeff
```

ChatGPT may help plan, diagnose, document, and review the system, but the ChatGPT phone or desktop application is not the unattended runtime worker. Codex and Gemini must be invoked programmatically by the trusted swarm.

### Remote access from Jeff's phone

Jeff uses Tailscale while away from the computer. Tailscale provides a private network path, but it does not by itself create a safe control interface for Hermes or Codex.

Any future phone-accessible control path must be deliberately installed and must:

- expose a narrow authenticated API or durable queue, not an arbitrary remote shell;
- accept only committed, preapproved job profiles;
- use outbound encrypted connections where practical;
- bind requests to an immutable job ID, policy version, repository, scope, and expiry;
- prevent replay and duplicate admission;
- preserve sanitized append-only audit evidence;
- support an immediate kill switch;
- allow only one active job during the early phases;
- leave deployment disabled unless a separate deployment phase is explicitly authorized.

Codex CLI must not be exposed directly to the phone or the network. Remote access must terminate at Hermes or a trusted admission service that applies all swarm policy before a worker can run.

### Notifications

Jeff wants notifications only when action or a meaningful result exists:

- approval is required;
- the job is blocked or ambiguous;
- Codex cannot produce a valid scoped change;
- deterministic verification repeatedly fails;
- Gemini returns `HUMAN_REQUIRED`, rejects the change, or repeatedly fails review;
- an authorized deployment starts, completes, fails, or rolls back;
- a security or resource threshold is crossed;
- the job completes.

A completion message should include the job ID, service or profile, trigger, risk, root cause, repair summary, changed files, exact commit, deterministic checks, Gemini verdict, deployment and health result when applicable, rollback point, and any manual follow-up.

### Separate future managed platform

The phone discussions also defined a possible separate product: a server-hosted managed platform in which customers install a small licensed local agent that makes an outbound encrypted connection to the service for approved settings and work.

That concept may later become the Forgewarden / Hermes Managed Security Platform. It is not part of the current swarm's authority and must not silently broaden this repository, its allowlists, or its deployment permissions. It should have its own threat model, repository boundary, authentication and licensing design, tenant isolation, update and rollback process, and customer-data rules.

Even in that future platform, unattended changes to firewall, SSH, identity, sudo, operating-system policy, DNS, payments, databases, pricing, orders, secrets, or customer data remain prohibited until separately designed, tested, and explicitly authorized.

### Optional local model assistance

An Ollama-hosted coding model may later assist with classification, planning, or review. It must not replace deterministic checks, acquire broader write authority, or become an unrecorded decision-maker. Its outputs are untrusted evidence under the same policy as other model output.

## Separation of duties

### Hermes

Hermes may:

- present status and sanitized audit results;
- accept only enumerated, committed job profiles;
- enqueue one preapproved dry-run job after a local one-job activation lease exists;
- report job state;
- engage the emergency kill switch.

Hermes may not:

- accept arbitrary shell commands, paths, repositories, tests, models, environment variables, or deployment options;
- clear the emergency kill switch;
- enable autonomous dry-run mode;
- edit code directly;
- modify policy;
- merge, push, or deploy;
- expose secrets or raw model output.

### Codex

Codex is the only code-writing agent. It may write only inside the disposable worktree and only to paths authorized by the committed job profile.

Codex does not own:

- Git metadata;
- staging or commits;
- test selection;
- repository selection;
- deployment;
- policy changes;
- approval decisions.

The trusted orchestrator hides Git metadata from Codex, validates Codex’s structured output, independently measures changes, stages explicit paths, and creates commits with hooks and signing disabled.

### Gemini / agy

Gemini is read-only and reviews one exact retained commit. It must return the enforced structured schema with exact job-ID and commit binding.

Gemini may propose short rules, but proposed rules remain pending audit evidence. They are never activated automatically.

Gemini approval alone never authorizes deployment.

### Claude CLI

Claude CLI is available as an optional read-only swarm specialist. Its best initial uses are:

- diagnosing a failure before Codex is invoked;
- converting an issue report into a narrow hypothesis and proposed reproducer;
- identifying edge cases and missing deterministic tests;
- independently reviewing sanitized failure evidence when Codex or Gemini is blocked;
- proposing concise candidate rules for human review.

Claude must not:

- edit the worktree or any protected repository;
- replace Codex as the only code writer;
- replace Gemini's exact-commit review gate;
- stage, commit, merge, push, deploy, or roll back;
- clear the kill switch, enable a lease, change policy, or broaden scope;
- see credentials, production environment values, raw secrets, or unrestricted logs;
- turn its own recommendation into an activated rule.

Claude output is untrusted advisory evidence. The trusted orchestrator must invoke it with a minimal environment, read-only filesystem access, bounded resources, sanitized inputs and outputs, a structured schema, an immutable job ID, and a recorded model/version. Deterministic checks remain authoritative.

The `MCPServerTask` lifecycle, reconnect, and replay acceptance tests now pass. Claude may therefore begin the separately bounded read-only Fable work program, but it is not yet part of the live Phase 2A critical path. Its adapter must first use a fake CLI and a disposable synthetic fixture and must demonstrate that Claude failure or unavailability cannot block the established fail-closed safety state.

#### Fable 5 credit directive

Jeff has authorized using up to **$100 of available Claude Fable 5 credits** for this project. The credits should be consumed on high-value analysis rather than artificial token generation.

Fable 5 is initially assigned this read-only work program:

1. **$35 target — MCP lifecycle validation and postmortem:** independently review the resolved production-equivalent `MCPServerTask` startup/readiness path, asyncio loop ownership, keepalive timing, generation-bound reconnect, and post-reconnect replay behavior. Look for residual failure modes and propose discriminating regression tests without altering the accepted implementation.
2. **$25 target — Phase 2A adversarial audit:** inspect sanitized implementation and fake-fixture evidence for queue admission, one-job leases, duplicate/replay rejection, heartbeat recovery, PID/start-time binding, cancellation, control-group cleanup, and fail-closed behavior.
3. **$20 target — deterministic test design:** produce missing process-level and fault-injection tests, including bridge death, worker death, response loss after durable enqueue, stale heartbeat, PID reuse, systemd user-bus loss, timeout, malformed model output, and audit-write failure.
4. **$15 target — reproducibility and public-release audit:** identify Jeff- or machine-specific assumptions, installer gaps, dependency pinning needs, clean-WSL validation steps, secret-removal requirements, and documentation needed before a GitHub release.
5. **$5 target — synthesis:** consolidate confirmed findings into a short prioritized implementation handoff and propose concise rules. Rules remain pending human review and are never activated automatically.

The trusted adapter must record `total_cost_usd` from Claude's structured JSON result and maintain an aggregate Fable budget ledger. The hard ceiling is **$100**; no invocation may begin if its configured maximum could cross the remaining budget. A target spend of $95–$100 is acceptable, but crossing $100, buying additional credits, or enabling automatic billing requires new approval.

Use non-interactive structured output, an immutable job ID, the exact Fable model identifier resolved by the installed CLI, bounded turns and time, plan/read-only permissions, and explicit denial of edit, write, shell, commit, network expansion, MCP mutation, and deployment tools. Cache stable sanitized context when supported so the budget is spent on reasoning rather than repeatedly transmitting the same project record.

Fable 5 requires 30-day data retention. Do not send it secrets, credentials, API keys, customer data, production environment values, protected raw logs, unrestricted audit records, or proprietary data that Jeff has not separately approved for that retention policy. Inputs must be minimized and sanitized before invocation.

Fable findings do not clear the current Phase 2A gate. The existing deterministic acceptance evidence remains required before another real repair job.

### Trusted orchestrator

The trusted orchestrator owns:

- immutable job IDs and one-job leases;
- allowlists and job-profile hashes;
- normalized path and diff gates;
- secret scans;
- deterministic commands and working directories;
- interpreter selection and verification;
- systemd cgroups and timeouts;
- Git staging and commits;
- reviewer schema enforcement;
- append-only audit records;
- crash recovery and verified cleanup;
- future fixed deployment and rollback adapters.

## Non-negotiable safety rules

1. Never give Gemini write access.
2. Never deploy because Gemini approves alone.
3. Never expose credentials, secrets, environment values, raw prompts, or unrestricted logs.
4. Never accept arbitrary commands or paths from Hermes or a model.
5. Never use `shell=True` in trusted execution paths.
6. Never use `git add -A`; stage only explicitly authorized paths.
7. Never modify the protected working repository directly.
8. Never perform unattended database, payment, order, pricing, authentication, authorization, secrets, firewall, backup-policy, destructive, or security-incident changes.
9. Never automatically activate a learned rule.
10. Never allow more than one active repair job for the initial profile.
11. Never infer success from a model claim; verify paths, hashes, diffs, tests, tree identity, job ID, and commit ID independently.
12. Fail closed on ambiguity, missing evidence, unexpected output, schema failure, timeout, resource-limit failure, user-bus failure, secret finding, cleanup failure, or state mismatch.
13. Preserve sanitized append-only evidence before cleanup.
14. Completion, failure, rejection, timeout, cancellation, or crash consumes the one-job lease, disables autonomous dry run, and engages the kill switch.
15. Use explicit `ABSTAIN` and `INSUFFICIENT_EVIDENCE` outcomes rather than guessing.
16. Never allow Claude, Gemini, or an optional local model to acquire write, commit, approval, policy, or deployment authority.

## Current machine layout

### Swarm implementation

- Repository: `/home/jeff/hermes-swarm-phase1`
- Launcher: `/home/jeff/.local/bin/hermes-swarm`
- Runtime: `/home/jeff/hermes-swarm-runtime`
- Durable audit directory: `/home/jeff/hermes-swarm-audit`
- Audit file: `/home/jeff/hermes-swarm-audit/audit.jsonl`

Expected permissions:

- audit directory: `0700`
- audit file: `0600`

### Hermes Desktop backend

- Backend virtual environment: `/home/jeff/.local/share/hermes-swarm-desktop-backend/venv`
- Hermes executable: `/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/hermes`
- Hermes version: `0.18.2`
- MCP SDK: `mcp==1.26.0`
- Dedicated Hermes home: `/home/jeff/hermes-swarm-desktop-home`
- Config: `/home/jeff/hermes-swarm-desktop-home/config.yaml`
- Environment file: `/home/jeff/hermes-swarm-desktop-home/.env`
- Desktop backend service: `hermes-swarm-desktop.service`
- Bind address: `127.0.0.1:9120`
- Windows connection: `http://localhost:9120`

### Desktop MCP bridge

- Launcher: `/home/jeff/.local/bin/hermes-swarm-mcp`
- MCP server name: `coding_swarm`
- Current configured tools:
  - `status`
  - `job_status`
  - `recent_audit`
  - `engage_kill_switch`
  - `run_preapproved_job`
- Hermes-prefixed names use the form `mcp__coding_swarm__status`.

### Phase 2A worker

- Template: `hermes-swarm-phase2a-worker@.service`
- Instance form: `hermes-swarm-phase2a-worker@JOB_ID.service`
- Template is installed but normally disabled and inactive.
- A verified admitted job starts one instance.
- Memory limit: `MemoryMax=2147483648`
- Swap: `MemorySwapMax=0`
- Worker uses control-group termination.

### Protected repository

Never access or modify during swarm development or synthetic exercises:

`/home/jeff/n8n`

This repository has had a large pre-existing dirty working state. Its status must be preserved. It is not the Phase 2A allowlisted repository.

### Independent initial baseline

- Repository: `/home/jeff/swarm-repositories/n8n-csv-baseline-v2`
- Clean baseline commit: `bad64e7cf14e3c586d395341b25467841847dec6`
- Clean tree: `c4b0ef66a712e18eb72ea7c7164ce412e351ed11`
- Synthetic defect commit: `97b4edde003ef14e4469c02b58c5013a0d9aa8a5`
- Known repair commit: `535bb244d1cc79e65c07c029285255495531e6db`
- Known seeded target hash: `8546054f0e2542f77afa975b1ba8dbe3561059537d2252ae0a290e0e02966d17`
- Known clean target hash: `3961d556ef730a9e7bb5cd1ec3a253ddef1deb885d010ee25c46448be2a2dbea`

The baseline checkout must remain clean and unchanged. Work occurs only in disposable worktrees.

## Initial Phase 2A job profile

Profile ID:

`csv_deadline_dry_run_v1`

Authorized existing writable file:

`csv-processor/app/ai/deadline.py`

Authorized new-file prefix:

`csv-processor/tests/swarm_regressions/`

Everything else, including every existing test, is read-only.

Deterministic test runs from the disposable worktree’s `csv-processor` directory:

```text
/home/jeff/anaconda3/bin/python3
-m pytest
-q
-p no:cacheprovider
tests/swarm_regressions/test_deadline_contract.py
```

Verified deterministic interpreter:

- configured path: `/home/jeff/anaconda3/bin/python3`
- canonical target: `/home/jeff/anaconda3/bin/python3.11`
- interpreter SHA-256: `61d223947169eefba0eb03a744ad74c25b6243d20866d3c32864d40ba4a285ce`
- Python: `3.11.7`
- pytest: `8.3.5`

The trusted synthetic exercise must:

1. Verify the clean baseline test passes.
2. Seed the fixed defect only in the disposable worktree.
3. Require the seeded target hash to equal `8546054f…66d17`.
4. Require pytest exit code `1` and the approved `assert 30.x <= 30` fingerprint.
5. Run Codex only after that evidence exists.
6. Measure the repair relative to the synthetic defect commit.
7. Require the repaired tree to equal the clean baseline tree.
8. Run deterministic tests.
9. Commit through the trusted orchestrator.
10. Have Gemini review the exact commit.
11. Audit and clean up without altering the baseline.

## Resource and execution controls

Current controls include:

- one concurrent job;
- 2 GiB aggregate memory limit;
- swap disabled;
- bounded CPU and wall-clock time;
- bounded captured logs;
- minimal environment;
- production and credential variables removed;
- network blocked through systemd policy except the controlled model-adapter requirements;
- normalized path checks;
- secret scans over selected files and Git blobs;
- no binary files, symlinks, submodules, nested repositories, generated caches, or unauthorized paths;
- hooks and commit signing disabled for orchestrator-owned synthetic commits.

## Desktop activation model

Phase 2A uses three separate states:

- deployment state;
- emergency kill switch;
- one-job autonomous dry-run lease.

The MCP model cannot enable the lease or clear the kill switch.

Local-only commands are intended to include:

```text
hermes-swarm autonomous-dry-run-status
hermes-swarm autonomous-dry-run-enable
hermes-swarm autonomous-dry-run-disable
```

The earlier controlled sequence was:

```bash
/home/jeff/.local/bin/hermes-swarm kill-switch
/home/jeff/.local/bin/hermes-swarm autonomous-dry-run-enable
/home/jeff/.local/bin/hermes-swarm autonomous-dry-run-status
/home/jeff/.local/bin/hermes-swarm enable-dry-run
/home/jeff/.local/bin/hermes-swarm status
```

Do not run this sequence while the current MCP blocker remains unresolved.

## Current safety state

The required and last reported state is:

```text
mode=DRY_RUN
AUTONOMOUS_DRY_RUN=DISABLED
deployment=DISABLED
kill_switch=ENGAGED
no queued or running Phase 2A job
```

Always verify rather than assume:

```bash
/home/jeff/.local/bin/hermes-swarm status
/home/jeff/.local/bin/hermes-swarm autonomous-dry-run-status
systemctl --user list-units 'hermes-swarm-phase2a-worker@*' --all --no-pager
```

## Current gate: Phase 2A post-run hardening and release preparation

### What works

- The Desktop backend is reachable from WSL and Windows on loopback.
- Hermes Desktop successfully called `mcp__coding_swarm__status` and received structured status.
- Direct MCP SDK initialization, six-tool discovery, repeated ping, and repeated status calls have passed.
- The bridge has closed-peer and `OSError` containment.
- Hermes’ local compatibility patch recognizes empty-string `ClosedResourceError` values.
- A generation-aware compatibility patch requires a strictly newer connection before reconnect readiness.
- Commit `989ed97d93bde8a6847b51c2043e9bc92d10ae03` removed the fixed-local-bridge OSV delay and corrected asyncio loop ownership/wakeup behavior under WSL.
- Commit `7a582369eebdb18cf76acf01b7adcb101e161542` corrected the disposable fixture to use the production persistent fd transport, public `MCPServerTask.start()`, and the production-style filtered environment.
- The official MCP probe now passes in 1.31 seconds, connects in 656 ms, and discovers six tools.
- The production-equivalent lifecycle fixture passes in 6.3 seconds, including three accelerated keepalives, forced closure, newer-generation reconnect, post-reconnect status, replay-safe fake enqueue, and a fake worker reaching `SUCCEEDED`.
- The full swarm suite reports 108 passed and 1 skipped; the bridge suite reports 12 passed; `pip check` passed.

### Resolved root causes

The latest reported implementation commit is:

`7a582369eebdb18cf76acf01b7adcb101e161542`

The prior official-client timeout had three causes:

1. Hermes ran a 12-second OSV network preflight against the fixed local bridge executable.
2. Hermes created the asyncio selector loop in one thread and ran it in another, producing WSL wakeup stalls.
3. Reconnection needed generation-bound readiness so a stale boolean event could not authorize an early retry.

The official command now passes:

```bash
HERMES_HOME=/home/jeff/hermes-swarm-desktop-home \
/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/hermes \
mcp test coding_swarm
```

Reported timing is 1.31 seconds total and 656 ms to connect.

Historical logs showed the first Hermes keepalive failing approximately every 200 seconds, followed by reconnection attempts. A prior retry happened before the replacement connection was ready. Commit `7a582369…` now demonstrates the production-equivalent keepalive/reconnect acceptance sequence in the disposable fixture.

The disposable acceptance fixture originally failed because it used plain FastMCP stdio, called `MCPServerTask.run()` directly, and omitted `HOME`, locale, `PYTHONNOUSERSITE`, and a dedicated `HERMES_HOME`. It stalled at generation 1 with `_ready_generation=0`. Commit `7a582369…` aligned the fixture with production and proved the lifecycle sequence.

### Completed Phase 2A evidence

Proven through commit `7a582369…`:

- official discovery passed three of three runs;
- each run discovered six tools;
- connection times were 0.6–0.9 seconds and total runtimes were 1.2–1.6 seconds;
- no MCP children leaked;
- a real Hermes Desktop status call succeeded after the normal keepalive boundary;
- the fake Phase 2A suite passed 13 of 13 tests;
- the full suite passed 93 tests with 8 skipped;
- `pip check` passed;
- the disposable production-equivalent `MCPServerTask` fixture reached ready;
- three accelerated keepalive cycles passed;
- status passed after the cycles;
- forced transport closure reconnected to a strictly newer generation;
- fake enqueue/replay returned the same job ID without duplication;
- the fake worker reached `SUCCEEDED`;
- the fake lease finished `CONSUMED`;
- the final kill switch was engaged, autonomous dry run disabled, and deployment disabled;
- no orphan MCP processes remained;
- one real synthetic job ran through Codex, deterministic validation, trusted commit creation, and Gemini exact-commit review;
- job `phase2a-1ab6c00f50704fd782e06e8d` received Gemini verdict `APPROVE` with low risk;
- repair commit `3d3b9d8fd1071bf3c4196c19d5a547d355d13795` was produced in the isolated baseline worktree;
- the baseline repository remained unchanged.

Next gates:

1. Keep the swarm repository separate from application repositories and publish only swarm source, tests, and documentation.
2. Add reproducible clean-machine installation and verification instructions.
3. Add bounded fault-injection coverage for worker, bridge, audit, and reviewer failures.
4. Design—but do not enable—additional Phase 2B profiles.
5. Keep deployment disabled and require separate authorization before any production-capable phase.

## Compatibility patches and backups

### ClosedResourceError compatibility

The Hermes client originally checked `str(exc).lower()`. Because `str(anyio.ClosedResourceError())` is empty, the existing session-expiry marker was not detected. The compatibility correction uses `_exc_str(exc).lower()`.

Backup reported for the earlier correction:

`/home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T025000Z`

### Generation-aware reconnect patch

- Active reported `mcp_tool.py` SHA-256: `a4aa9a701de75fa0970180e94c7ac326c39b862b31bc5e3bbacef4346f48d1f0`
- Backup: `/home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T172305Z-generation`

Reported rollback:

```bash
cd /home/jeff/hermes-swarm-phase1

/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_generation_patch.py rollback \
  --backup /home/jeff/hermes-swarm-desktop-backend-backups/mcp_tool.py.backup-20260720T172305Z-generation

systemctl --user restart hermes-swarm-desktop.service
```

### Local startup and asyncio loop patch chain

Commit `989ed97d93bde8a6847b51c2043e9bc92d10ae03` added a three-part, version/hash-guarded compatibility chain:

- local fixed-executable startup/preflight patch: reported hash prefix `b7b5c60e…`
- event-loop ownership patch: reported hash prefix `1764639b…`
- event-loop wakeup/current patch: reported hash prefix `bc13c3ab…`

Backups are retained under:

`/home/jeff/hermes-swarm-desktop-backend-backups/`

Rollback must occur in reverse order using the exact backup paths recorded by the implementation:

```bash
cd /home/jeff/hermes-swarm-phase1

/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_loop_wakeup_patch.py rollback --backup <wakeup-backup>

/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_loop_owner_patch.py rollback --backup <owner-backup>

/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/python \
  scripts/hermes_mcp_local_startup_patch.py rollback --backup <startup-backup>

systemctl --user restart hermes-swarm-desktop.service
```

Never apply or roll back a compatibility patch without verifying the expected Hermes version and source hash. Hermes upgrades may overwrite local patches. Test upgrades in a disposable environment first.

## Important diagnostic conclusions

### Docker inspection limitation

Early inventory could not inspect `/var/run/docker.sock` from the enclosing sandbox. Docker and production were intentionally left untouched.

### Dirty production repository

The original `/home/jeff/n8n` working tree was dirty throughout onboarding. That condition was preserved. Independent clones/baselines were created specifically to avoid damaging or confusing that state.

### Baseline contract

`product_deadline(0)` means immediate expiration. The exception occurs during context entry. An earlier regression test caught it too late; the baseline test was corrected and now passes.

### Systemd user bus

WSL has systemd as PID 1 and a user bus. Earlier cgroup failures were caused by subprocess environments omitting:

- `XDG_RUNTIME_DIR`
- `DBUS_SESSION_BUS_ADDRESS`

The runner now derives and includes those only when the corresponding user-bus socket exists.

### Memory control

An earlier virtual-address limit was replaced by transient systemd user cgroups covering the complete Codex/Gemini process tree:

- `MemoryMax=2147483648`
- `MemorySwapMax=0`

### Deterministic interpreter

Ambient `python3` under systemd resolved to `/usr/bin/python3`, which lacked pytest. The trusted runner now requires an absolute validated interpreter and records its canonical path, hash, versions, argv, working directory, bounded output, exit code, and timeout.

### Gemini contract

Gemini initially returned a plausible approval payload missing mandatory fields. The reviewer contract now requires, among other fields:

- exact `job_id`;
- exact `reviewed_commit`;
- `verdict`;
- `risk`;
- `blocking_findings`;
- `non_blocking_notes`;
- `tests_missing`;
- `reasoning_summary`;
- `proposed_rules`.

Malformed, shortened, case-changed, whitespace-altered, or other-job IDs fail closed.

### MCP job ownership

A long repair initially ran synchronously inside the MCP request. When the connection closed, a replacement bridge marked it abandoned. Phase 2A was changed to durable queueing with a dedicated systemd worker. The MCP call should return a canonical queued job ID promptly; `job_status` reads durable state.

Only worker-side recovery may mark a job abandoned, and only after an expired heartbeat plus proof that no verified worker PID/start-time match exists.

## Selected milestone and commit history

This list records the most important reported milestones. Use Git history and documentation for exact diffs.

- `66bc89b5…`, `f28303f8…`: initial swarm repository and dry-run integration.
- `958cd85`: final pre-activation validation report.
- `23bbd4b`: SHA and aggregate-memory blockers resolved.
- `7607848…`: disposable Hermes activation proof.
- `899d0b7`: parallel dry-run activation, rollback, and reinstall proof.
- `f4782fc`, `cf35b23`: real-repository onboarding and learned-rule audit decisions.
- `553bfe1`: protected independent CSV baseline.
- `85682e7`, `01026d7`, `11ac28c`, `16c3de7`: controlled-exercise runner/path/environment corrections.
- `dba0ffe`: corrected clean baseline and documentation.
- `a58a4d1`: WSL user-bus environment correction.
- `441722e`: fail-closed no-change exercise report.
- `1be2a35`, `ede2a96`, `d3f27ef`, `d09f65e`: Codex writer adapter, canonical job binding, trusted commit orchestration, and successful writer probe.
- `5ff7920`, `491559e`, `0a8ad758…`: shared deadline writer wiring and reporting.
- `c1a5038…`: Codex diagnostic evidence.
- `2386d11`, `d1fc3b3`: synthetic two-commit model.
- `cf81792`: Gemini contract enforcement and recovery command.
- `988ff72`: initial restricted Desktop MCP bridge.
- `760d33e`: WSL-safe persistent bridge transport.
- `9d7538a`: empty-string `ClosedResourceError` compatibility handling.
- `bdd51b98…`: initial Phase 2A implementation.
- `8d340747…`: deterministic interpreter correction.
- `9ee70eac…`, `d9eab3ee…`: trusted defect seeding, durable queue, worker ownership, recovery, and single-job cancellation.
- `7d157ce…`: bridge closed-peer containment and generation-bound reconnect readiness; official Hermes 20-second probe remains unresolved.
- `989ed97d…`: fixed-local startup, OSV-preflight bypass for the trusted local executable, correct asyncio loop ownership/wakeup under WSL, and official MCP discovery restored to 1.31 seconds.
- `7a582369…`: production-equivalent disposable lifecycle fixture, accelerated keepalives, forced newer-generation reconnect, replay-safe fake enqueue, terminal fake worker, and clean final safety state.

## Existing project documentation

Important reported files in `/home/jeff/hermes-swarm-phase1/docs` include:

- `pre-activation-report.md`
- `n8n-onboarding-report.md`
- `csv-baseline-manifest.md`
- `first-controlled-repair.md`
- `first-controlled-repair-v2.md`
- `first-controlled-repair-v2-retry.md`
- `first-controlled-repair-v2-final.md`
- `deadline-contract-analysis.md`
- `codex-writer-adapter-validation.md`
- `deadline-writer-wiring-validation.md`
- `controlled-baseline-0rtmvv09-postmortem.md`
- `deadline-codex-diagnostic.md`
- `desktop-mcp-bridge.md`
- `hermes-mcp-reconnect-compatibility.md`
- `phase2a-preapproved-desktop-jobs.md`

There is an existing untracked postmortem that has repeatedly been preserved intentionally. Do not stage, overwrite, delete, or commit it unless Jeff explicitly requests that action.

Additional planning artifacts saved through ChatGPT include:

- `Hermes-Codex-Gemini-Unattended-Repair-Plan.md`
- `Hermes-Codex-Gemini-Design-Review-2026-07-20.md`
- `Hermes-Swarm-Phase2A-Codex-Handoff.md`
- this master project record.

## Rollout roadmap

### Phase 0 — Observation

Status: substantially complete.

- Inventory installation and repositories.
- Confirm dirty/protected state.
- Establish durable audits.
- Verify CLIs and model providers.
- No repairs or deployment.

### Phase 1 — Synthetic dry-run repair

Status: completed with multiple fail-closed corrections.

- Independent baseline.
- Disposable worktree.
- Trusted seeded defect.
- Codex repair.
- Deterministic test.
- Trusted commit.
- Gemini exact-commit review.
- Resource controls and cleanup.

### Phase 2A — Hermes Desktop single-use dry-run

Status: lifecycle, fake-worker acceptance, and one real synthetic dry-run completed. Deployment remains disabled.

Required completion evidence:

- official `hermes mcp test coding_swarm` passes repeatedly under five seconds (three of three reported at 1.2–1.6 seconds total);
- three accelerated keepalive cycles pass (proven);
- status succeeds afterward (proven);
- forced transport closure reconnects to a strictly newer generation (proven);
- fake enqueue succeeds after reconnect without duplication (proven);
- one real synthetic job queued promptly and completed through the worker (proven: `phase2a-1ab6c00f50704fd782e06e8d`);
- final lease disabled, kill switch engaged, deployment disabled, worker inactive, baseline unchanged.

### Phase 2B — Additional preapproved repair profiles

Status: Candidate A and Candidate B are admitted as fixture-only profiles; deployment remains disabled.

For each new profile:

- independent clean repository/baseline;
- exact scope and tests;
- trusted reproducer;
- protected-category classification;
- resource budgets;
- secret scans;
- fake-agent tests;
- one human-authorized dry-run exercise;
- no production access.

Claude CLI may be introduced during this phase as an optional read-only diagnostic step, but only after a separate adapter contract is committed and proven with fake and synthetic fixtures. Claude failure must degrade to the existing path or fail closed; it must never silently change the result of an admission, deterministic, Gemini, or deployment gate.

The Fable 5 credit work program may begin before Phase 2B only as isolated read-only analysis of sanitized material. It may not enqueue a repair job or alter the Phase 2A implementation directly.

### Phase 3 — Human-approved deployment

Status: design-only controls started; deployment remains disabled and no executor is wired.

Required design:

- explicitly named low-risk service;
- exact approved commit;
- fixed deployment adapter;
- backup and proven restore;
- staging or canary validation;
- health checks;
- automatic rollback;
- human approval for each deployment;
- notification to Jeff.

### Phase 4 — Low-risk unattended deployment

Status: future work only.

Limited to explicitly named services with sufficient successful dry-run and human-approved deployment evidence. High-risk categories remain excluded.

Before unattended operation, the remaining Phase 2A connection and replay checks must pass and a persistent, supervised worker must be proven. Remote phone control must use the narrow Hermes admission path described above; Tailscale or network reachability alone is not authorization.

### Phase 5 — Public GitHub release

Status: planning only.

Before publication:

- remove Jeff-specific paths, usernames, audits, source-repository state, credentials, and machine fingerprints;
- provide configuration templates and safe local bindings;
- pin and lock dependencies;
- provide installer, validator, update, rollback, and uninstall workflows;
- add CI for the declared environment;
- provide fake Codex/Gemini adapters and reproducible fixtures;
- document architecture, threat model, permissions, support boundaries, incident response, and responsible disclosure;
- add license and contribution guidelines;
- test from a clean Ubuntu/WSL installation;
- never publish retained secrets or historical dirty repository contents.

The intended initial public support scope is deliberately narrow:

- Ubuntu Linux and WSL2;
- Docker Compose;
- GitHub;
- Nginx;
- PostgreSQL;
- generic webhook or email notifications;
- OpenAI-compatible model APIs.

## Future deterministic deployment executor

The eventual executor should expose only fixed operations such as:

- `deploy`
- `restart`
- `health_check`
- `rollback`

It must not accept arbitrary shell commands. Every operation must bind to an explicitly approved service profile, exact commit, fixed command implementation, timeout, audit schema, health check, and rollback plan.

## Operator runbook

### Read-only health checks

```bash
/home/jeff/.local/bin/hermes-swarm status
/home/jeff/.local/bin/hermes-swarm autonomous-dry-run-status

curl -sS http://127.0.0.1:9120/api/status

systemctl --user status hermes-swarm-desktop.service --no-pager
systemctl --user list-units 'hermes-swarm-phase2a-worker@*' --all --no-pager
```

### MCP discovery check

```bash
HERMES_HOME=/home/jeff/hermes-swarm-desktop-home \
/home/jeff/.local/share/hermes-swarm-desktop-backend/venv/bin/hermes \
mcp test coding_swarm
```

Current expectation: this is the unresolved blocker and may time out at 20 seconds. Do not reinterpret a timeout as acceptance.

### Emergency stop

```bash
/home/jeff/.local/bin/hermes-swarm kill-switch
/home/jeff/.local/bin/hermes-swarm autonomous-dry-run-disable
```

Then verify status and worker units. Do not use broad `pkill`, `killall`, or destructive cleanup commands.

### Audit inspection

```bash
tail -n 50 /home/jeff/hermes-swarm-audit/audit.jsonl
```

Audit output is intended to be sanitized, but still handle it as sensitive operational data and do not publish it.

### Backend logs

```bash
tail -n 200 /home/jeff/hermes-swarm-desktop-home/logs/mcp-stderr.log

rg -n -i \
  'closedresource|connection closed|coding_swarm|keepalive|reconnect|traceback' \
  /home/jeff/hermes-swarm-desktop-home/logs/errors.log \
  /home/jeff/hermes-swarm-desktop-home/logs/agent.log \
  | tail -n 200
```

### Repository preservation

Before any implementation work:

```bash
cd /home/jeff/hermes-swarm-phase1
git status --short
```

Preserve unrelated changes and the known untracked postmortem. Never use `git reset --hard`, broad checkout/revert operations, or destructive cleanup.

## Resume instructions for a future Codex session

Use this prompt with this entire file attached or available:

```text
Resume the Hermes–Codex–Gemini swarm from the Master Project Record.

First perform read-only verification only:
- inspect the swarm Git status and latest commits;
- preserve the existing untracked postmortem;
- verify DRY_RUN, autonomous lease disabled, deployment disabled, and kill switch engaged;
- verify no Phase 2A worker is queued or running;
- verify the baseline remains clean at bad64e7cf14e3c586d395341b25467841847dec6;
- verify Hermes 0.18.2 and the recorded compatibility-patch hash;
- verify the official `hermes mcp test coding_swarm` result remains under five seconds;
- verify the local startup and asyncio loop compatibility-chain hashes/backups.

Do not activate a job, invoke Codex/Gemini, access /home/jeff/n8n, Docker, or production, or modify anything until the current state matches the record.

The lifecycle blocker and first real synthetic exercise are resolved. The immediate task is now post-run hardening: keep the swarm repository self-contained, improve reproducibility and fault-injection coverage, and preserve the fail-closed safety state. Do not start another Phase 2A job without separate authorization.

Preserve the phone/Android decisions in this record: Hermes is the single front door; unattended work uses the durable supervised queue; notifications are limited to approval, blocker, security/resource events, and completion; Tailscale is transport rather than authorization; and the future managed customer platform remains a separate project boundary.

Claude CLI is available. The lifecycle blocker is resolved, so the isolated read-only Fable work program may begin under a structured, audited, resource-bounded adapter. Do not add Claude to the active Phase 2A critical path until its fake-CLI and disposable-adapter contracts pass. Codex remains the sole writer, Gemini remains the exact-commit reviewer, and deterministic checks remain authoritative.

Jeff has authorized up to $100 of Fable 5 credits under the recorded budget program. Verify the installed Claude CLI version, authentication, exact resolved Fable model identifier, structured `total_cost_usd` reporting, and 30-day-retention warning before the first call. Use only sanitized inputs and enforce the aggregate $100 ceiling.
```

## Evidence required before any next real job

Do not run another controlled Phase 2A exercise until one report proves all of the following:

- official Hermes MCP test passes repeatedly (proven 3/3);
- startup is under five seconds (proven);
- exactly six tools are discovered (proven);
- real Desktop status works after the normal keepalive boundary (proven);
- the disposable `MCPServerTask` fixture reaches ready through the production-equivalent loop/ownership path (proven);
- three accelerated keepalive cycles pass through that task (proven);
- status works after the accelerated cycles (proven);
- forced disconnect reconnects to a newer generation (proven);
- fake queue admission after reconnect returns promptly (proven);
- duplicate/replayed admission returns the same job ID without duplication (proven);
- no orphaned bridge or worker processes remain after the fake exercise (proven);
- all swarm tests and `pip check` pass (108 tests passed, 1 skipped in the current environment);
- compatibility patch hashes and backups are recorded;
- baseline and protected repositories are unchanged;
- autonomous dry run is disabled;
- deployment is disabled;
- kill switch is engaged;
- no queued or running worker exists.

After the above evidence is reconfirmed, any additional real synthetic Phase 2A job still requires explicit authorization. This record does not authorize execution.

## Definition of project success

The project is successful when Jeff can safely leave his desk and a trusted, narrowly scoped issue can flow through Hermes, Codex, deterministic validation, Gemini review, and—only in a separately mature phase—controlled deployment and rollback, while every unexpected condition fails closed and produces useful evidence.

Convenience is not success if it weakens scope, reproducibility, auditability, rollback, or human control over high-risk changes.

## 2026-07-30 scope update

Jeff authorized resuming broader local dry-run development. Candidate A and Candidate B completed their bounded Phase 2B evidence gates and are admitted only to the dedicated fixture-only registry. The protected Phase 2A registry, deployment path, runtime markers, and kill switch state remain unchanged.

## 2026-07-30 Candidate A evidence update

Candidate A has a persisted schema-valid sanitized evidence artifact. Its latest approved run bound repair and reviewer commit `3f49790077186f789fd3274ce990830a46510af1`, passed the Candidate A checks, and admitted the profile to the dedicated fixture-only registry. The active Phase 2A registry remains unchanged.

## 2026-07-30 Candidate B fixture and admission update

Candidate B (`audit_review_dry_run_v1`) now has a disposable synthetic audit fixture covering malformed, replayed, symlinked, and valid completion events. The approved run bound repair and reviewer commit `06a22f1c431867cede1265bae7edf706e5a5ae04`, passed the Candidate B checks, and persisted a sanitized evidence artifact. Candidate B is admitted only to the dedicated fixture-only registry; deployment, autonomous execution, live audit access, and production access remain disabled. Portable validation now passes 108 tests.

## 2026-07-30 Phase 3 design update

Jeff authorized continuing through Phase 3. The first bounded deliverable is
design-only: `forgewarden_synthetic_service_deployment_v1` targets only the
disposable staging fixture `forgewarden-synthetic-fixture-v1` and requires an
exact-commit, one-time human approval, protected backup, fixed health check,
automatic rollback, durable audit, and fail-closed preconditions. No deployment
adapter is wired, no service is started, and deployment remains disabled.
The portable suite now passes 111 tests.

## 2026-07-30 Phase 3 fake adapter update

The disposable-only `swarm/phase3_fake_deployment.py` simulator now covers
exact approval binding, one-time replay rejection, backup creation, health
failure and timeout rollback, audit-failure rollback, identifier validation,
service/commit mismatch rejection, and symlink rejection. Focused checks pass
11/11 and the portable suite passes 119 tests. It never
starts a service, runs an external command, opens a network connection, or
enables deployment. A real deployment executor remains unwired.

## 2026-07-30 Phase 3 staging evidence update

The approved disposable staging exercise now has a schema-validated evidence
bundle bound to commit `06a22f1c431867cede1265bae7edf706e5a5ae04`. It records a
non-mutating preflight, simulated success, audited health-failure rollback, and
deployment disabled state. Portable validation passes 125 tests. No service,
external command, network, or unattended deployment was enabled.
