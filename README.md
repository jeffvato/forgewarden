# Hermes + Codex + Gemini coding swarm (Phase 1)

This is a local-only, dry-run implementation of the setup-kit specification.
It is intentionally independent of `~/n8n` and never edits, deploys, pushes,
restarts, or contacts remote infrastructure.

## Quick start

```bash
cd ~/hermes-swarm-phase1
python3 -m unittest discover -s tests -v
python3 -m swarm.cli --help
```

The tests create a disposable Git repository, seed a low-risk defect, run a
fake Codex writer and fake Gemini reviewer, and exercise rejection paths.
No live repository is used.

Every push and pull request runs the portable deterministic fixture suite on
Python 3.11 and 3.12 through GitHub Actions. The workflow also validates both
shell launchers. Machine-specific Hermes/Desktop lifecycle tests remain a
separate local validation gate because they require the pinned WSL runtime.

The same checks are available locally through `bash scripts/validate-swarm.sh
--portable`; use `--full` for the complete local suite.

The advisory code-quality review is read-only and produces structured,
risk-tiered findings. Run it against an isolated worktree or disposable
checkout:

```bash
PYTHONPATH=. python3 -m swarm.cli quality-review \
  --repository /path/to/isolated-worktree \
  --output /tmp/hermes-quality-review.json
```

It currently reports heuristic SAFE, CAREFUL, and RISKY findings, removes
duplicate findings deterministically, and exposes the proposed review order;
every finding has `auto_apply: false`. It does not edit, commit, deploy, or
invoke an external model.

## Boundaries

- Hermes owns job state and orchestration; it never edits application files.
- Codex is the only writer and is confined to a temporary Git worktree.
- Gemini reviews a separate read-only snapshot tied to the exact commit SHA.
- Deterministic checks and policy gates override model opinions.
- Learned rules are proposed separately and remain inactive in dry-run mode.
- `DeploymentController` always raises in dry-run mode; there is no deployment
  command in this phase.

See `docs/operations.md` for commands, rollback/kill-switch procedures, and
the prerequisites for any future human-approved deployment phase.

Launcher templates are under `packaging/`. The MCP launcher validates that it
is running from a complete swarm checkout and uses `python3` by default; set
`HERMES_SWARM_PYTHON` explicitly when MCP is installed in a dedicated Python
environment. Installing these templates does not enable autonomous work, start
a worker, or change the kill switch.

The shell launcher accepts absolute-path overrides for isolated installations:

```bash
HERMES_SWARM_RUNTIME_ROOT=/srv/hermes/runtime \
HERMES_SWARM_AUDIT_ROOT=/srv/hermes/audit \
HERMES_SWARM_BASELINE_REPOSITORY=/srv/hermes/baseline \
  packaging/hermes-swarm status
```

Relative overrides are rejected. These settings relocate local state only; they
do not change the deployment-disabled boundary or authorize a job.
