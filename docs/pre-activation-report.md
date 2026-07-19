# Redacted pre-activation validation report

Status: DRY-RUN ONLY. Hermes configuration was not applied.

## Provider and model proof

The successful review of commit `d01beac00d48aef1c286d1f5a9069cb18dbacb69`
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

SHA reconciliation for that historical fixture run:

- Fixture Git repository `HEAD`: `d01beac00d48aef1c286d1f5a9069cb18dbacb69`
- Audit record `commit`: `d01beac00d48aef1c286d1f5a9069cb18dbacb69`
- Audit record `gemini.reviewed_commit`: `d01beac00d48aef1c286d1f5a9069cb18dbacb69`
- One-character mismatch regression: PASS; `require_exact_commit` rejects the altered SHA.

The alternate value ending `...aef2c...` was a report typo and is not authoritative.

## Acceptance results

All 14 local negative/guard tests passed:

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
| one-character SHA mismatch blocks approval | PASS | `test_one_character_commit_mismatch_blocks_approval` |
| full fixture regression suite | PASS | `14 tests passed` |

The successful positive fixture also produced a non-empty Codex commit,
deterministic pass, exact-SHA agy approval, and a final audit record.

## Resource measurement and final limits

Successful fixture measurement:

- WSL memory total: `16,771,153,920` bytes (`15.62 GiB`)
- WSL memory available before repeated run: `13,777,154,048` bytes (`12.83 GiB`)
- Peak child RSS in repeated run: `229,504 KiB` (`224 MiB`)
- CPUs visible: `8`
- Final aggregate process-tree limit: `2,147,483,648` bytes (`2 GiB`)

The limit is enforced by a transient `systemd-run --user --scope` cgroup over
the complete Codex/agy process tree with `MemoryMax=2147483648` and
`MemorySwapMax=0`. The 2 GiB limit succeeded despite Node/WebAssembly runtime
behavior, so the former 9.69 GiB virtual-address cap was removed. Jobs remain
serialized, with 45 CPU seconds, 180 seconds wall time, and 256 KiB captured
logs. The observed RSS was about 224 MiB, leaving substantial headroom inside
the 2 GiB job cap and reserving the rest of WSL for n8n, PostgreSQL, Docker,
and the CSV processor.

Repeated validation run: PASS. New fixture commit
`8cfb33b2e42412a52169199d86f70950e72fda68` matched its audit and reviewer
records exactly; deterministic tests passed and agy returned `APPROVE` / `LOW`.

## Proposed dedicated Hermes profile

Reviewable file: `config/hermes-profile.yaml`. It specifies local-only
dry-run mode, Hermes orchestration, Codex as sole writer, agy/Gemini as
read-only reviewer, one concurrent job, three review cycles, and a kill switch.

## Hermes activation proof

Installed Hermes resolves to `/home/jeff/.local/bin/hermes` with SHA-256
`8e364441fc54fff4f2ae5037a643faef632e61307a8612e806893fd289b40b76`.
The wrapper hard-codes `ROOT=/home/jeff/hermes-sandbox` and reads:

```text
/home/jeff/hermes-sandbox/agents/hermes.md
/home/jeff/hermes-sandbox/config/policy.yaml
/home/jeff/hermes-sandbox/review/task.md
```

`hermes --help` exposes no `profile` or `config` subcommand. The attempted
`hermes profile --help` and `hermes config --help` invocations fell through to
the interactive launcher and refused to start because the validation shell had
`TERM=dumb` and no TTY. The wrapper exposes `HERMES_MODEL`, but no profile-home
or config-file selector. Therefore this installed Hermes has no officially
supported dedicated-profile command or YAML location; the proposed YAML is a
swarm-side review artifact, not an applied Hermes configuration.

Disposable proof passed in `tests/test_hermes_profile.py`: a temporary copy of
the actual wrapper selected a disposable root, rendered the unique marker
`HERMES-SWARM-DISPOSABLE-MARKER-7F4C`, rendered `SWARM_POLICY_LOADED`, and
rendered the disposable task. Removing the disposable root removed the marker.
The active wrapper SHA was identical before and after. The active Hermes files
were not changed.

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
+  max_memory_bytes: 2147483648
+  memory_control: systemd-user-cgroup
+  max_log_bytes: 256000
+kill_switch: /home/jeff/hermes-swarm-phase1/.swarm-state/KILL_SWITCH
+deployment:
+  enabled: false
+notifications:
+  enabled: false
```

No file at that target path was created or modified.

## Exact future activation procedure (NOT EXECUTED)

Because this wrapper has no profile selector, future activation must use a
separate wrapper and separate Hermes root; it must not replace the active
wrapper. After Jeff approves, the exact procedure is:

```bash
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
ACTIVE_WRAPPER=/home/jeff/.local/bin/hermes
ACTIVE_ROOT=/home/jeff/hermes-sandbox
DEDICATED_WRAPPER=/home/jeff/.local/bin/hermes-coding-swarm-phase1
DEDICATED_ROOT=/home/jeff/hermes-sandbox-coding-swarm-phase1

cp -a "$ACTIVE_WRAPPER" "$ACTIVE_WRAPPER.backup.$STAMP"
cp -a "$ACTIVE_ROOT" "$DEDICATED_ROOT"
cp "$ACTIVE_WRAPPER" "$DEDICATED_WRAPPER"
# In the copied wrapper only, change ROOT to "$DEDICATED_ROOT".
# Install the reviewed profile files under the copied root's existing
# agents/, config/, and review/ paths. Do not create a YAML profile path.
chmod 700 "$DEDICATED_WRAPPER"
"$DEDICATED_WRAPPER" --print-prompt > /tmp/hermes-swarm-profile-$STAMP.txt
rg -F 'HERMES-SWARM-DISPOSABLE-MARKER-7F4C' /tmp/hermes-swarm-profile-$STAMP.txt
```

The verification command is the final `--print-prompt` command plus the
marker search. Activation must be rejected if the marker, policy, or dry-run
mode is absent.

Rollback commands for that future dedicated activation are:

```bash
rm -f /home/jeff/.local/bin/hermes-coding-swarm-phase1
rm -rf /home/jeff/hermes-sandbox-coding-swarm-phase1
mv /home/jeff/.local/bin/hermes.backup.$STAMP /home/jeff/.local/bin/hermes
/home/jeff/.local/bin/hermes --print-prompt > /tmp/hermes-rollback-$STAMP.txt
```

Rollback must be limited to the timestamped dedicated wrapper/root and must
not reset or clean unrelated files.

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

## Parallel DRY-RUN activation evidence

The separate launcher was installed at `/home/jeff/.local/bin/hermes-swarm`
with runtime/configuration root `/home/jeff/hermes-swarm-runtime`. Its only
installed instruction surfaces were `agents/hermes.md`, `config/policy.yaml`,
and `review/task.md`.

The launcher starts in `DRY_RUN`, with deployment disabled and the kill switch
engaged. Before the successful fixture run, `hermes-swarm dry-run` returned
exit code 1 with `blocked: dry-run kill switch engaged`. The separate
`hermes-swarm enable-dry-run` command cleared only that dry-run kill switch;
it could not enable deployment.

The complete disposable fixture run produced:

```text
Codex commit: f8b26dd0fb9a72c75936c3d5e49da722755d59af
Deterministic checks: passed (exit 0)
agy/Gemini review: APPROVE LOW
Reviewed commit: f8b26dd0fb9a72c75936c3d5e49da722755d59af
Audit: /home/jeff/hermes-swarm-runtime/run-_vaqc76g/state/audit.jsonl
MemoryMax: 2147483648 bytes (2 GiB)
MemorySwapMax: 0
Peak child RSS: 227968 KiB
Deployment: disabled
```

The audit record contained matching base, commit, and reviewer SHAs, the
deterministic test result, the agy/Gemini decision, and the enforced limits.
No credentials were copied into the repository, runtime, prompts, or logs;
the existing supported credential mechanism was used. No `~/n8n` path,
Docker command, production data, or production service was accessed.

Rollback was tested by removing only the parallel launcher and runtime. The
original `/home/jeff/.local/bin/hermes --print-prompt` then succeeded and its
SHA remained:

```text
8e364441fc54fff4f2ae5037a643faef632e61307a8612e806893fd289b40b76
```

The parallel launcher was reinstalled from committed revision
`32b9d3d359150b732fcb9701a1913f8a5126ba35`. The current post-test state is
therefore `DRY_RUN`, deployment `DISABLED`, and kill switch `ENGAGED`.
The runtime audit was intentionally removed with the runtime during rollback;
the evidence above was captured before removal.

### Parallel launcher operations

```bash
LAUNCHER=/home/jeff/.local/bin/hermes-swarm
$LAUNCHER start
$LAUNCHER status
$LAUNCHER prompt
$LAUNCHER enable-dry-run   # explicit dry-run-only enable; deployment stays disabled
$LAUNCHER dry-run
$LAUNCHER audit
$LAUNCHER stop
$LAUNCHER kill-switch      # engage before maintenance or emergency shutdown
```

Uninstall/rollback and reinstall from the committed swarm repository:

```bash
chmod -R u+rwX /home/jeff/hermes-swarm-runtime
rm -f /home/jeff/.local/bin/hermes-swarm
rm -rf /home/jeff/hermes-swarm-runtime
/home/jeff/.local/bin/hermes --print-prompt

REV=32b9d3d359150b732fcb9701a1913f8a5126ba35
git -C /home/jeff/hermes-swarm-phase1 show "$REV":packaging/hermes-swarm > /tmp/hermes-swarm-reinstall
git -C /home/jeff/hermes-swarm-phase1 show "$REV":packaging/runtime-task.md > /tmp/hermes-swarm-task-reinstall
mkdir -p /home/jeff/hermes-swarm-runtime/{agents,config,review,state}
install -m 0700 /tmp/hermes-swarm-reinstall /home/jeff/.local/bin/hermes-swarm
install -m 0644 /home/jeff/hermes-sandbox/agents/hermes.md /home/jeff/hermes-swarm-runtime/agents/hermes.md
install -m 0600 /home/jeff/hermes-sandbox/config/policy.yaml /home/jeff/hermes-swarm-runtime/config/policy.yaml
install -m 0644 /tmp/hermes-swarm-task-reinstall /home/jeff/hermes-swarm-runtime/review/task.md
touch /home/jeff/hermes-swarm-runtime/state/KILL_SWITCH
touch /home/jeff/hermes-swarm-runtime/state/RUNNING
```

The reinstall procedure uses only the existing credential mechanism and does
not copy credentials.
