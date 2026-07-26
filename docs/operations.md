# Operations and handoff

All commands are local WSL commands. Phase 1 is dry-run only.

```bash
cd ~/hermes-swarm-phase1
python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 -m swarm.cli status
PYTHONPATH=. python3 -m swarm.cli start
PYTHONPATH=. python3 -m swarm.cli dry-run
PYTHONPATH=. python3 -m swarm.cli stop --state-dir .swarm-state
PYTHONPATH=. python3 -m swarm.cli quality-review \
  --repository /path/to/isolated-worktree \
  --output /tmp/hermes-quality-review.json
# Equivalent packaged launcher form:
packaging/hermes-swarm quality-review \
  --repository /path/to/isolated-worktree \
  --output /tmp/hermes-quality-review.json
```

`stop` writes a local kill-switch marker. It does not stop Hermes, n8n, Docker,
or any production service. The global deployment kill switch is represented by
the absence of any deployment implementation plus `DeploymentController`,
which unconditionally rejects deployment.

`status` measures local resources and reports discovered CLI paths and versions.
`workflow-status` is the read-only Phase 2A state check: it reports state,
lock ownership, running markers, replay blocking, and stale-marker recovery
guidance without changing runtime files. Use the separate guarded recovery
command only after reviewing its output and safety prerequisites.
All Phase 2A runtime roots and marker/state files must be local regular paths;
symlinked roots or markers are rejected before reads, writes, lock acquisition,
or recovery. Runtime state is kept separate from the repository and is not
checked into Git.
`start` only marks the dry-run controller as started; it launches no daemon.
`dry-run` creates a disposable fixture, invokes the real local adapters, and
records audit state under ignored runtime directories.
`quality-review` reads source files and emits a structured report without
editing the repository, invoking an external model, or enabling auto-apply.
Use an isolated worktree or disposable checkout as its input.
The packaged launcher exposes the same command and does not require runtime
activation or kill-switch changes.

Python checks are syntax-aware. JavaScript and TypeScript receive conservative
language-aware text detectors for wrappers, naming rot, nested ternaries,
silent failures, suspected N+1 calls, and blocking work in async code. Other
supported source extensions receive only language-neutral checks until a
detector is added and covered by fixtures.
The structured report includes this coverage declaration for downstream
reviewers.

`quality-apply-safe` is deliberately narrower than the report: it accepts only
explicit `unused_import` SAFE findings, requires a clean linked Git worktree
whose report repository matches exactly, and rejects repository roots,
symlinks, dirty trees, ambiguous imports, and all CAREFUL/RISKY findings. It
changes files in that isolated worktree only; it does not commit, push, deploy,
or restart anything. A deterministic test run and human review remain required
before any later application step.
Before its first write, it must consume a matching, unexpired,
replay-protected independent approval bound to the combined evidence hash.
The command requires a shell-free verification command, records its exit
status, and restores the original bytes and modes if verification fails. Its
structured result is defined by
`schemas/quality-application-result.schema.json`.
It also requires a job ID and durable audit path. The audit is mode `0600` and
records only hashes, finding IDs, changed-file names, status, and verification
outcome; it excludes command text, command output, and source contents.

`quality-audit` is the read-only human/Gemini handoff for that evidence. It
validates the audit mode and JSON records, selects only the requested job, and
returns a schema-validated summary with `review_required: true` and
`mutation_allowed: false`. It verifies state/verification/rollback consistency
and hash formats, and returns a hash of the specific reviewed event. It never
returns the underlying audit records.

Durable audit logs and their lock files are opened with no-follow semantics and
must be regular files beneath non-symlinked directories. A symlinked audit or
lock path fails closed before any record is written.

`review-evidence` combines the quality report, application plan, and audit
summary by hash. It requires versioned read-only inputs, emits only counts,
statuses, and hashes, and always returns `HUMAN_REVIEW_REQUIRED` with
`mutation_allowed: false`. Its output contract is
`schemas/combined-review-evidence.schema.json`; no model is invoked by this
command. File output uses the same no-symlink, mode-`0600` writer as quality
reports.

`approval-create` binds an explicit reviewer decision to the combined evidence
file hash and writes a mode-`0600` record under a mode-`0700` directory.
`approval-verify --consume` checks the job ID, evidence hash, expiry, and
non-authorizing flags, then atomically creates a consumption marker. A second
consumption attempt is rejected as replay; approval records do not enable
mutation or deployment.
`approval-reconcile` additionally confirms that the consumed approval ID and
evidence hash appear in the durable SAFE-application audit event for the same
job.

The application plan is validated by `schemas/quality-application-plan.schema.json`.
For CAREFUL findings, the orchestrator compares Codex's
`tests_added_or_changed` list against its verified changed-file list; a test
name that is not actually changed cannot satisfy the gate.

During an orchestrated dry-run, the report is also supplied to Gemini as
read-only evidence. The final application gate is mechanical: any RISKY
finding produces `AWAITING_JEFF`, while CAREFUL findings require at least one
Codex-listed test change before the candidate can complete the dry-run. A
Gemini `APPROVE` verdict cannot bypass either condition; only SAFE findings, or
test-backed CAREFUL findings, may proceed.

Structured Codex and Gemini mailbox files are created exclusively with mode
`0600` and are never replaced through a symlink. Mailbox directories and
structured results must be regular local paths. Before Gemini starts, the
disposable snapshot is checked for symlinks that resolve outside that snapshot;
such a snapshot fails closed. This protects review evidence from stale or
model-created path redirection.

The implementation does not alter Hermes configuration. Before a later phase
changes an existing Hermes configuration, take a timestamped copy, display the
proposed diff, and obtain Jeff's approval. No OS package, network, remote host,
Docker socket, credential, or live n8n access is required here.

Before human-approved deployment can be considered, Jeff must separately:

1. approve a named service and repository/base revision;
2. verify clean-repository policy, rollback artifacts, health checks, and resource limits;
3. prove Codex and Gemini isolation, gateway authentication, and secret redaction;
4. review dry-run audit evidence and the risk matrix;
5. approve any protected behavior changes and any generated rule;
6. authorize a distinct deployment phase with a tested targeted rollback.

Rollback of this phase is simply to stop invoking the new directory and remove
it only after preserving its audit evidence. Existing `~/n8n` files and Hermes
configuration are not touched by this implementation.
