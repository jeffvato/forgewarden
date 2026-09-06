# FW-ENDPOINT-05 — Windows/Linux sensor adapter contract

## Status and authority

This is a design-and-test contract only. It does not install, start, or
communicate with a Windows or Linux sensor. Live sensor hooks, services,
filesystem/process monitoring, network collection, credentials, deployment,
quarantine, remediation, cleanup, repair, and response remain disabled until a
separate authorization.

## Canonical handoff

An eventual platform adapter is a producer of caller-authorized observations;
it is not an event store or policy engine. It must submit one bounded envelope
to the canonical `swarm.normalized_events.NormalizedEventStore.admit_fixture`
owner. The adapter cannot bypass normalization, tenant/device/source binding,
Evidence, deduplication, queue limits, or deterministic policy. It receives no
authority from a native record, path, process, or network destination.

Required handoff fields are `event_id`, `tenant_id`, `device_id`,
`observed_at_epoch`, `event_type`, `source`, bounded `artifact` or `process`
metadata, and `evidence_ref`. `source` is exactly `WINDOWS_SENSOR` or
`LINUX_SENSOR`; unknown values fail closed. The canonical owner fixes `mode` to
`DRY_RUN` and `action` to `DETECT_ONLY`.

## Adapter obligations

Before calling the canonical owner, a future adapter must:

1. map native data to the bounded vocabulary without carrying executable or
   authority-bearing instructions;
2. preserve the caller-supplied tenant and device identity;
3. enforce the serialized-input, metadata, ancestry, indicator, and rate caps;
4. avoid retaining raw content, secrets, paths, or credentials; and
5. surface canonical denial and retry outcomes without inventing a second queue.

The adapter must not call platform APIs, open files, inspect processes, create
network connections, invoke commands, or perform containment. Any platform
integration requires a separate implementation ticket, least-privilege design,
fixture proof, exact-commit review, and explicit authorization.

## Proof boundary

Design tests may inspect this document and caller-supplied fixtures only. They
must prove that both platform labels feed the same canonical owner, that
tenant/device identity is explicit, and that all live collection and response
capabilities remain absent. This contract grants no deployment or endpoint
authority.
