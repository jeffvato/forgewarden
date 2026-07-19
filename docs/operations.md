# Operations and handoff

All commands are local WSL commands. Phase 1 is dry-run only.

```bash
cd ~/hermes-swarm-phase1
python3 -m unittest discover -s tests -v
PYTHONPATH=. python3 -m swarm.cli status
PYTHONPATH=. python3 -m swarm.cli start
PYTHONPATH=. python3 -m swarm.cli dry-run
PYTHONPATH=. python3 -m swarm.cli stop --state-dir .swarm-state
```

`stop` writes a local kill-switch marker. It does not stop Hermes, n8n, Docker,
or any production service. The global deployment kill switch is represented by
the absence of any deployment implementation plus `DeploymentController`,
which unconditionally rejects deployment.

`status` measures local resources and reports discovered CLI paths and versions.
`start` only marks the dry-run controller as started; it launches no daemon.
`dry-run` creates a disposable fixture, invokes the real local adapters, and
records audit state under ignored runtime directories.

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
