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
