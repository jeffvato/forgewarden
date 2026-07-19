# Deadline writer wiring validation

Status: **VALIDATED WITHOUT AGENT INVOCATION**

This change unifies writer probes and controlled deadline repairs around one
immutable `WriterInvocationSpec` and one `CodexAdapter`. No Codex or agy/Gemini
process was invoked for this validation, and no repair authorization was
consumed.

## Canonical deadline specification

For every temporary deadline worktree, the specification is:

```text
Git root:                 <temporary-worktree>
Codex CWD:                <temporary-worktree>/csv-processor
Codex-relative target:    app/ai/deadline.py
Git-root-relative target: csv-processor/app/ai/deadline.py
```

Before a writer can run, the adapter verifies the CWD, regular-file and
non-symlink properties, containment, equivalence of both target paths, and the
SHA-256 hash of the seeded defect. The deterministic failure evidence must
name the same resolved target.

The repair prompt is generated from that same specification. It includes the
canonical job ID, actual CWD, both relative paths, expected behavior, the
sanitized failing assertion, smallest-correction instruction, and explicit
instructions not to modify/create tests or write Git metadata, stage, commit,
push, or use remotes.

## Changed-path normalization

Codex reports paths relative to its CWD. The adapter rejects absolute paths,
backslashes, traversal, missing files, symlinks, duplicates, escapes, and
paths outside the declared writable scope. Valid paths are resolved and
compared as Git-root-relative paths. Thus `app/ai/deadline.py` normalizes to
`csv-processor/app/ai/deadline.py`.

## Test evidence

`tests/test_writer_wiring.py` provides a real subprocess fake-CLI test. It
checks the production-style CWD and prompt, verifies the target, edits only
`app/ai/deadline.py`, validates the dynamic job-ID schema, normalizes the
claimed path, passes the trusted diff gate, stages only the validated file,
and creates the orchestrator-owned commit with hooks and signing disabled.

The same test module rejects a Git-root CWD with the shorter target, a full
Git-root path returned from the Codex CWD, missing targets, seeded-hash
mismatches, traversal, and symlink paths. Existing adapter tests continue to
cover CLI approval/sandbox arguments, exact job IDs, minimal environment, and
external cache cleanup.

The full swarm test suite passed after these changes. The environment's user
systemd bus is unavailable to the host-cgroup-specific adapter test, so that
test remains explicitly skipped; the new fake-CLI process test uses a real
child process with the production argument, CWD, prompt, schema, and
environment-builder contract while isolating host cgroup setup.

## Future audit evidence

The controlled runner records, before cleanup, the sanitized argument vector,
actual CWD, environment variable names only, prompt hash, target path and
pre/post hashes, Codex exit code, schema-validation result, sanitized result
summary, and claimed and actual normalized changed paths. Source contents,
credentials, and secrets are not recorded.

The prior authorized job `controlled-baseline-gwxk2slx` remains a distinct
failed-closed attempt: preflights passed, Codex was invoked, the trusted diff
gate found no authorized change, no commit was created, and agy/Gemini was not
invoked. Its durable audit is
`/home/jeff/hermes-swarm-audit/audit.jsonl`.

Kill switch remains **ENGAGED** and deployment remains **DISABLED**. The v2
baseline, `/home/jeff/n8n`, Docker, active Hermes, and production were not
modified or accessed by this validation.
