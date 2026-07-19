# First controlled baseline repair

Result: **BLOCKED before repair execution**.

The exercise was invoked once through the parallel launcher while the kill
switch was engaged. The complete sanitized baseline scan ran first and found
credential-like material, so the runner refused to clear the kill switch.
No temporary worktree was created and no Codex, deterministic test, or
agy/Gemini process ran.

## Evidence

```text
job_id: controlled-baseline-x_wvrqiy
baseline: 1815f77634a81adfdb0383139f37cd663a951393
files scanned: 420
secret-scan findings: 5
audit: /home/jeff/hermes-swarm-audit/audit.jsonl
kill switch after attempt: ENGAGED
deployment: DISABLED
```

The scan reported filenames and classifications only:

```text
docker-compose.yml                  SECRET_OR_PRIVATE_MATERIAL
test_wc_api.py                      SECRET_OR_PRIVATE_MATERIAL
project_context.md                  SECRET_OR_PRIVATE_MATERIAL
vps/docker-compose.vps.yml          SECRET_OR_PRIVATE_MATERIAL
csv-processor/app/templates/content_pipeline.html  SECRET_OR_PRIVATE_MATERIAL
```

No secret values were displayed. The durable audit contains the scan record;
the launcher returned the blocked result before the runner's later failure
transition hook, so no repair commit or reviewer record was created.

## Control plane prepared

Writable paths were narrowed to:

```text
csv-processor/app/ai/deadline.py
new files only beneath csv-processor/tests/swarm_regressions/
```

Existing tests, all other source/configuration, and all protected integration
categories are read-only. The mechanical gate rejects existing-test changes,
deletions, out-of-scope changes, escaping renames, symlinks, traversal,
skip/xfail, unconditional success, and assertion removal.

The runner is configured to strip credential/production-like environment
variables, use only the narrow deadline test command, and require systemd
`MemoryMax=2 GiB`, `MemorySwapMax=0`, and `IPAddressDeny=any` for agent/test
subprocesses. Deployment remains mechanically disabled.

## Post-attempt checks

- Kill switch: `ENGAGED`.
- Deployment: `DISABLED`.
- Baseline repository HEAD remains `1815f77634a81adfdb0383139f37cd663a951393`.
- `/home/jeff/n8n` remained untouched; its HEAD remains
  `dd847c7e86ea62369537f46cf887aba799a441fa`.
- Docker and production services were not accessed.
- Network-isolated agent processes were never started because the scan blocked
  before that stage.
- No repair file changed and existing tests remain byte-identical.

## Required next decision

Jeff must review and remove or otherwise remediate the five filename-only
findings in the independent baseline, without changing `/home/jeff/n8n`.
The baseline commit used by the controlled runner must then be re-established
and rescanned with zero findings. Until that happens, the runner must continue
to block before kill-switch clearance.
