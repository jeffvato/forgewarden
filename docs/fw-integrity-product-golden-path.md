# FW-INTEGRITY executable product Golden Path

## Purpose

This proof answers whether representative accepted ForgeWarden components can
still operate together at the current exact commit. It uses their public local
DRY_RUN contracts rather than historical pass counts or documentation claims.

The path composes canonical identity registration, deterministic policy, a
signed single-use Action Ticket fixture, Harness lifecycle Evidence, endpoint
and AI attribution, AI threat classification, cross-domain SOC correlation, an
inert containment proposal, canonical Evidence recovery, recovery admission,
and Mission Control capability projection. All records use one tenant.

## Safety boundary

The proof uses caller-supplied fixtures and a temporary local Evidence ledger.
It reads the current Git hash but does not mutate Git. It opens no network
connection, resolves no credential, invokes no model, installs no sensor,
executes no response or recovery action, and grants no authority. Expected
outputs remain DRY_RUN, deployment-disabled, kill-switch-engaged,
proposal/read-only, live-disabled, and production-not-ready.

The test also proves cross-tenant identity and recovery denial, Action Ticket
replay denial, AI-event replay denial, and rejection of a live safety claim.
On success it emits a bounded JSON summary containing the exact commit,
exercised requirement families, and boolean assertions. It includes no raw
prompt, retrieved content, credential, signature material, or callback.

Run the proof with:

```text
bash scripts/run-product-golden-path.sh
```
