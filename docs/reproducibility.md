# Reproducibility and portability boundary

The published repository is the source for the Hermes + Codex + Gemini coding
swarm. It is not yet a portable installer. The current Phase 2A implementation
is intentionally bound to Jeff's validated WSL installation and must not be
activated from an unverified checkout.

## Validated local environment

- WSL2 on the primary development machine
- Python 3.11.7 at `/home/jeff/anaconda3/bin/python3`
- Hermes Agent 0.18.2
- MCP 1.26.0 in the Hermes environment
- Codex and `agy`/Gemini adapters installed at their recorded local paths
- Baseline repository: `/home/jeff/swarm-repositories/n8n-csv-baseline-v2`
- Runtime state: `/home/jeff/hermes-swarm-runtime`
- Durable audit: `/home/jeff/hermes-swarm-audit`

## Verification from this repository

Run the deterministic repository suite from the project root:

```bash
python3 -m unittest discover -s tests -v
```

The current validated result is 108 tests passed and 1 skipped. The skipped
test is the explicit real WSL `MCPServerTask` diagnostic. A fresh checkout
without the validated Hermes environment is expected to fail closed rather
than silently substitute a different interpreter, MCP version, CLI, profile,
or repository.

## Portability work still required

Before a public installer or another machine may activate Phase 2A, a separate
review must:

1. replace machine-specific absolute paths with trusted installation-root
   discovery;
2. provide pinned dependency installation and version/hash verification;
3. define platform-specific process isolation and resource controls;
4. bind profiles to a newly scanned baseline and canonical interpreter;
5. add a clean-machine acceptance run covering MCP discovery, reconnect,
   replay, worker cleanup, audit durability, and fail-closed recovery.

Repository-relative launcher templates are available now, but the active
Desktop integration still requires explicit installation of the launcher, the
Hermes-compatible Python environment, and local configuration. The shell
launcher accepts absolute `HERMES_SWARM_RUNTIME_ROOT`,
`HERMES_SWARM_AUDIT_ROOT`, and `HERMES_SWARM_BASELINE_REPOSITORY` overrides;
relative values are rejected. These overrides improve local installation
portability but do not make the Phase 2A profile portable or change its safety
gates. The templates do not modify the active installation automatically.

Until those checks pass, keep autonomous dry-run disabled, deployment disabled,
and the kill switch engaged. Do not copy the local profile or runtime state to
another machine.
