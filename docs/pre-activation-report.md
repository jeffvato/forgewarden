# Redacted pre-activation validation report

Status: DRY-RUN ONLY. Hermes configuration was not applied.

## Provider and model proof

The successful review of commit `d01beac00d48aef2c286d1f5a9069cb18dbacb69`
was executed by `/home/jeff/.local/bin/agy` version `1.1.4`.

The matching agy log was:

```text
/home/jeff/.gemini/antigravity-cli/log/cli-20260719_132813.log
workspaceDirs=[.../.integration-runtime/run-oxlms3ra/state/review-real-local-e2cv8uqr-g59hqx6n]
product=antigravity
label="Gemini 3.5 Flash (Medium)"
URL: https://daily-cloudcode-pa.googleapis.com/v1internal:streamGenerateContent
```

Therefore the reviewer was Gemini through the Antigravity `agy` CLI, using
Google Gemini 3.5 Flash (Medium). Credentials, tokens, trace IDs, and response
IDs are intentionally omitted.

## Acceptance results

All 13 local negative/guard tests passed:

| Acceptance case | Result | Evidence |
| --- | --- | --- |
| agy rejects deliberately incorrect patch | PASS | Real agy returned `REJECT` with a blocking finding |
| stale approval for older commit rejected | PASS | `test_schema_rejects_invalid_json_and_stale_review` |
| invalid reviewer JSON rejected | PASS | `test_schema_rejects_invalid_json_and_stale_review` |
| failing deterministic test overrides approval | PASS | `test_bad_deterministic_check_blocks_model_approval` |
| forbidden-file change blocked | PASS | `test_forbidden_file_change_is_blocked` |
| duplicate job blocked | PASS | `test_duplicate_job_is_blocked` |
| fourth review cycle blocked | PASS | `test_three_review_cycle_limit` |
| kill switch prevents new jobs | PASS | `test_kill_switch_prevents_new_jobs` |
| learned rule cannot self-activate | PASS | `test_learned_rule_cannot_activate_itself_and_protected_rule_requires_jeff` |
| security rule requires Jeff | PASS | same rule-policy test; returns `HUMAN_REQUIRED` |
| full fixture regression suite | PASS | `13 tests passed` |

The successful positive fixture also produced a non-empty Codex commit,
deterministic pass, exact-SHA agy approval, and a final audit record.

## Resource measurement and final limits

Successful fixture measurement:

- WSL memory total: `16,771,153,920` bytes (`15.62 GiB`)
- WSL memory available before run: `13,864,165,376` bytes (`12.91 GiB`)
- Peak child RSS: `231,296 KiB` (`226 MiB`)
- CPUs visible: `8`
- Final per-agent virtual-memory limit: `10,398,124,032` bytes (`9.69 GiB`)

The limit is 75% of measured available memory, capped at 10 GiB, leaving at
least 25% available for n8n, PostgreSQL, Docker, and the CSV processor. The
observed RSS was only about 226 MiB; the larger virtual-address ceiling is
required by the Node/WebAssembly runtime used by agy. Jobs remain serialized,
with 45 CPU seconds, 180 seconds wall time, and 256 KiB captured logs.

## Proposed dedicated Hermes profile

Reviewable file: `config/hermes-profile.yaml`. It specifies local-only
dry-run mode, Hermes orchestration, Codex as sole writer, agy/Gemini as
read-only reviewer, one concurrent job, three review cycles, and a kill switch.

## Exact Hermes configuration diff (NOT APPLIED)

The current installed Hermes wrapper has no dedicated profile-file switch. The
following is the exact proposed future addition; it is shown for review only:

```diff
--- /dev/null
+++ b/home/jeff/hermes-sandbox/config/profiles/hermes-coding-swarm-phase1.yaml
@@
+profile: hermes-coding-swarm-phase1
+mode: DRY_RUN
+local_only: true
+automatic_deployment: false
+repository_roots:
+  - /home/jeff/hermes-swarm-phase1
+roles:
+  orchestrator: hermes
+  application_writer: codex
+  reviewer: agy-gemini-read-only
+limits:
+  max_concurrent_jobs: 1
+  max_review_cycles: 3
+  command_timeout_seconds: 180
+  max_memory_bytes: 10398124032
+  max_log_bytes: 256000
+kill_switch: /home/jeff/hermes-swarm-phase1/.swarm-state/KILL_SWITCH
+deployment:
+  enabled: false
+notifications:
+  enabled: false
```

No file at that target path was created or modified.

## Commands

```bash
cd ~/hermes-swarm-phase1
PYTHONPATH=. python3 -m swarm.cli start
PYTHONPATH=. python3 -m swarm.cli status
PYTHONPATH=. python3 -m swarm.cli dry-run
PYTHONPATH=. python3 -m swarm.cli stop
PYTHONPATH=. python3 -m swarm.cli kill-switch
```

`stop` and `kill-switch` only write local swarm state. They do not stop Hermes,
n8n, Docker, or any production service.

## Hermes configuration rollback

Because the proposed Hermes configuration was not applied, rollback is no-op:
do not create the proposed profile file. If a future approved change creates
it, first copy it to a timestamped backup, stop new swarm jobs, enable the
swarm kill switch, remove only that dedicated profile file, restore the backup
if required, and verify `hermes --print-prompt` plus the existing Hermes
configuration diff. Do not alter unrelated Hermes files.
