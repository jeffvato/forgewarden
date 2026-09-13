# FW-INTEGRITY critical-invariant mutation resistance

## Contract

The bounded mutation proof uses eight fixed source mutations to challenge seven
critical ForgeWarden invariants: AI self-authority, tenant isolation, Evidence
immutability, independent exact review, model-assurance downgrade, MCP tool
authority, kill-switch enforcement, and deployment disablement. Each mutation
names the existing deterministic test that owns the challenged behavior.

Every mutant is applied to its own function-owned archive of one exact tracked
commit. Archive paths, file types, member sizes, mutation targets, test
selectors, execution time, and captured output are bounded. The source target
must occur exactly once. A missing or ambiguous target, changed source commit,
timeout, excessive or secret-bearing output, malformed result, or surviving
mutant fails the proof. Raw test output is not retained in the result.

The repository working tree and Git history are never mutation targets. Each
temporary checkout is removed before the next mutant runs. The report identifies
the exact commit, mutation and invariant IDs, canonical owner, source path,
existing test selector, and kill result without granting authority.

Run the proof with:

```text
bash scripts/run-mutation-resistance-proof.sh
```

## Limits

This is a selected-test effectiveness proof for eight high-value mutations. It
is not exhaustive mutation testing, formal verification, production readiness,
or permission to modify policy. It installs no mutation engine or dependency,
uses no provider or network access, starts no service or sensor, executes no
response or recovery, and cannot deploy or alter ForgeWarden authority.
