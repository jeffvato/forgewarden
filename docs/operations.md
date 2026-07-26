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
`start` only marks the dry-run controller as started; it launches no daemon.
`dry-run` creates a disposable fixture, invokes the real local adapters, and
records audit state under ignored runtime directories.
`quality-review` reads source files and emits a structured report without
editing the repository, invoking an external model, or enabling auto-apply.
Use an isolated worktree or disposable checkout as its input.
The packaged launcher exposes the same command and does not require runtime
activation or kill-switch changes.

During an orchestrated dry-run, the report is also supplied to Gemini as
read-only evidence. The final application gate is mechanical: any RISKY
finding produces `AWAITING_JEFF`, while CAREFUL findings require at least one
Codex-listed test change before the candidate can complete the dry-run. A
Gemini `APPROVE` verdict cannot bypass either condition; only SAFE findings, or
test-backed CAREFUL findings, may proceed.

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
