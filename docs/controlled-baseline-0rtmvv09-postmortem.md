# Postmortem: `controlled-baseline-0rtmvv09`

Status: **FAILED CLOSED; evidence incomplete for the Codex turn**

This is a read-only postmortem. No code, baseline, implementation, kill
switch, or agent state was changed while producing it. The durable records
are `/home/jeff/hermes-swarm-audit/audit.jsonl` and the earlier sanitized
writer-probe record at
`/home/jeff/hermes-swarm-audit/codex-writer-adapter-validation.jsonl`.

## Job facts recorded by the durable audit

```text
job_id: controlled-baseline-0rtmvv09
base_revision: bad64e7cf14e3c586d395341b25467841847dec6
temporary Git root: /home/jeff/hermes-swarm-runtime/state/controlled-controlled-baseline-0rtmvv09-otluy15g
deterministic working directory: <temporary-worktree>/csv-processor
deterministic test: tests/swarm_regressions/test_deadline_contract.py
```

The baseline scan found 2 files and 0 findings; the reachable Git-blob scan
found 3 blobs and 0 findings. The unchanged test passed, the seeded defect
failed with the expected assertion, and the kill switch was then cleared for
this one job. It was re-engaged after the failed diff gate.

## Required Codex telemetry

The runner audit stopped recording Codex invocation telemetry on the failure
path. The following values are therefore **NOT RECORDED** for this job; they
must not be reconstructed as if they were observed.

1. **Exact sanitized Codex argv:** NOT RECORDED.
2. **Actual Codex working directory:** NOT recorded by the Codex adapter. The
   validated writer specification recorded the intended CWD as
   `<temporary-worktree>/csv-processor`.
3. **Environment variable names passed to Codex:** NOT RECORDED for this
   invocation. No environment values are present in the audit.
4. **Exact prompt text:** NOT RECORDED. A sanitized reconstruction from the
   validated specification is shown below, but it is not proof of the exact
   bytes delivered.
5. **Seeded target hash before Codex:**
   `8546054f0e2542f77afa975b1ba8dbe3561059537d2252ae0a290e0e02966d17`
6. **Codex exit code:** NOT RECORDED.
7. **JSON/schema validation result:** NOT separately recorded. The runner
   reached the diff gate after `CodexAdapter.run` returned, and no schema
   error was reported, but the successful validation event was never audited.
8. **Final-response summary:** NOT RECORDED.
9. **Codex-claimed `changed_files`:** NOT RECORDED.
10. **Target hash immediately after Codex:** NOT RECORDED.
11. **Actual normalized Git changed paths:** `[]`, as reported by the trusted
    diff gate. No normalized Codex claim was persisted.
12. **Codex command/test activity:** NOT RECORDED.
13. **Sandbox/write-denial messages:** None were recorded in the durable job
    audit. Absence of a recorded message is not proof that none occurred.

The exact durable failure was:

```text
controlled exercise changed unexpected authorized files: []
```

No repair commit was created and Gemini was not invoked.

## Shared writer specification

The validated deadline mapping was:

```text
Codex-relative writable path:    app/ai/deadline.py
Git-root-relative writable path: csv-processor/app/ai/deadline.py
Codex CWD:                       <temporary-worktree>/csv-processor
Git root:                        <temporary-worktree>
seeded target hash:              8546054f0e2542f77afa975b1ba8dbe3561059537d2252ae0a290e0e02966d17
```

The prompt was generated from that specification and had this sanitized
structure:

```text
RETURN JOB_ID EXACTLY AS SUPPLIED: <canonical-job-id>. Do not shorten, rewrite, or derive it.

Work only in Git root <temporary-worktree>. Your actual CWD is <temporary-worktree>/csv-processor.
The exact canonical job ID is <canonical-job-id>.
The only writable source path is app/ai/deadline.py relative to your CWD,
corresponding to csv-processor/app/ai/deadline.py relative to Git root.
Expected behavior: remaining_seconds() returns non-negative remaining monotonic time.
The sanitized failing assertion is: the seeded deadline contract assertion must pass after the smallest source correction.
Make the smallest source correction.
Do not modify or create tests. Do not write Git metadata, stage files, create commits, remotes, or pushes.
Run only the declared argument-array deterministic test. The trusted orchestrator commits the edit.
```

The exact job ID, temporary paths, command serialization, and prompt bytes are
not available in the failed-job audit, so the block above is explicitly a
sanitized reconstruction, not exact prompt evidence.

## Comparison with successful `value.py` writer probe

The comparison source is the successful probe record with job ID
`codex-writer-5992160844164b28823c55db4e4d0af3`, which recorded repair commit
`00dcc9de36023cb98bb3d4e4e8f65c3512450c90`.

| Field | Successful value.py probe | Deadline job `controlled-baseline-0rtmvv09` |
|---|---|---|
| Invocation flags | Recorded: `codex --ask-for-approval never exec --ephemeral --sandbox workspace-write --skip-git-repo-check --cd <probe-repo> --output-schema <repo>/.swarm/codex-result-<job>.schema.json --output-last-message <temporary-json> --color never --json <prompt-argument>` | Not recorded; the shared adapter contract intended the same flags, with `--cd <temporary-worktree>/csv-processor` |
| CWD | Recorded as a disposable probe repository | Intended and spec-validated as `<temporary-worktree>/csv-processor`; actual child CWD not recorded |
| Environment names | Recorded: `CODEX_HOME`, `DBUS_SESSION_BUS_ADDRESS`, `HOME`, `LANG`, `LC_ALL`, `PATH`, `SWARM_DRY_RUN`, `SWARM_NETWORK_BLOCKED`, `SWARM_ROLE`, `TERM`, `XDG_RUNTIME_DIR` | Not recorded for this job; no values were recorded |
| Prompt structure | Dynamic job-ID prefix plus writer-probe instructions generated through the shared spec | Same shared job-ID prefix/spec structure intended; exact bytes not recorded |
| Writable path | `value.py` relative to CWD and Git root | `app/ai/deadline.py` relative to CWD; `csv-processor/app/ai/deadline.py` relative to Git root |
| Schema | Dynamic Codex result schema with the canonical job ID bound in `job_id.const` | Same adapter behavior intended; successful validation event not audited |
| Timeout | 180 seconds | 180 seconds configured by the runner |
| Aggregate cgroup | `MemoryMax=2147483648`, `MemorySwapMax=0` | Same configured limits; job-specific cgroup properties were not persisted in the job audit |
| Network policy | `IPAddressDeny=any` | `IPAddressDeny=any` recorded by the runner policy |
| Result | Claimed and actual `value.py`; deterministic test passed; orchestrator committed | Diff gate observed no actual authorized path; no commit; Gemini not invoked |

The successful probe's full final response was preserved in its separate
sanitized audit record. The deadline job's final response was not.

## Why did value.py succeed while deadline.py did not?

The evidence does **not** support a causal explanation. It proves only that:

- the successful value probe returned a schema-valid response claiming
  `value.py`, changed that file, passed its deterministic test, and allowed
  the trusted orchestrator to commit it; and
- the deadline job passed its pre-agent checks, then reached the diff gate
  with no authorized Git change, causing a fail-closed result.

There is no evidence showing whether the deadline Codex turn made no edit,
edited and reverted the file, received a different prompt than reconstructed,
hit a write denial, timed out internally, or returned a response whose
claimed paths were empty. Guessing among those possibilities would be
unsupported.

The missing telemetry needed to answer the question is:

- sanitized argv and actual child CWD;
- environment-name list;
- exact prompt or prompt hash plus retained redacted prompt text;
- Codex exit code and stdout/stderr denial messages;
- schema-validation result and exact sanitized final response;
- claimed changed paths;
- target post-Codex hash and normalized actual paths;
- child command/test event summary.

## Final safety state

The durable audit records the kill switch re-engaged with outcome `FAILED`.
Deployment remained disabled. No repair commit or Gemini review exists. The
baseline, original n8n repository, Docker, production, and active Hermes were
not modified.
