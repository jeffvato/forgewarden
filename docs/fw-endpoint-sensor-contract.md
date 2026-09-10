# FW-ENDPOINT-01 — Windows/Linux MicroSensor contract

## Purpose

This document defines the first implementation boundary for Windows and Linux
endpoint sensors. It is a design contract only. It does not install a service,
register a filesystem hook, read live endpoint state, execute a process, or
perform containment or remediation.

The sensor is a platform-native producer of bounded observations. ForgeWarden's
existing detector, canonical event/evidence path, deterministic policy, and
Action Ticket boundaries remain the owners of interpretation and response.

## Contract boundary

The future sensor adapter accepts one local observation at a time and emits a
canonical, tenant-bound event envelope. The fixture implementation must use
caller-supplied JSON objects only; it must not open paths, resolve links, call
platform APIs, contact a network endpoint, or read credentials.

Required envelope fields:

| Field | Contract |
| --- | --- |
| `event_id` | Non-empty event identifier, unique within a fixture run. |
| `tenant_id` | Explicit tenant binding; never inferred from a path or process. |
| `device_id` | Explicit device identity supplied by the caller. |
| `observed_at_epoch` | Non-negative observation time. Future observations are denied. |
| `event_type` | One of the bounded event types below. Unknown types fail closed. |
| `source` | `WINDOWS_SENSOR` or `LINUX_SENSOR`; must match the selected adapter. |
| `artifact` or `process` | Bounded metadata only; raw content is supplied separately to the detector. |
| `evidence_ref` | Reference to canonical Evidence created by the observation boundary. |
| `mode` | Always `DRY_RUN` for the first implementation. |
| `action` | Always `DETECT_ONLY`; a sensor cannot quarantine or remediate. |

No event may contain an authority-bearing command, executable payload, secret,
arbitrary filesystem operation, network request, or response instruction.

## Bounded event types

The initial cross-platform vocabulary is deliberately small:

- `FILE_LIFECYCLE`: create, modify, rename, delete, or metadata change.
- `PROCESS_START`: process identity and parent/child relationship.
- `PROCESS_EXIT`: process identity and exit metadata.
- `NETWORK_CONNECT`: destination metadata without making a connection.
- `RUNTIME_INDICATOR`: a bounded sensor observation requiring later correlation.

Platform adapters map native records into this vocabulary without changing the
tenant/device binding. Windows may later use ETW, service notifications, and
supported security telemetry. Linux may later use audit, fanotify, or other
least-privilege facilities. Those integrations are future implementation work,
not permissions granted by this contract.

## Resource and hostile-input limits

Fixture and eventual sensor adapters must enforce these limits before event
normalization:

- maximum serialized event: 64 KiB;
- maximum metadata string: 256 bytes;
- maximum process ancestry depth: 32;
- maximum related indicators per event: 64;
- maximum queued events: 1,024 per device;
- bounded backpressure with oldest low-priority observations dropped first;
- no unbounded retry, recursion, decompression, or content retention.

Malformed, oversized, future-dated, cross-tenant, unknown-type, or unavailable
Evidence inputs fail closed and produce no normalized event.

## Fixture and proof plan

The first test fixture is an in-memory JSONL stream containing explicit
`tenant_id`, `device_id`, timestamps, and event metadata. Tests must cover:

1. deterministic normalization of one Windows and one Linux fixture;
2. tenant/device mismatch and unknown event-type denial;
3. oversized, malformed, future-dated, and duplicate event denial;
4. queue/backpressure limits and deterministic ordering;
5. Evidence failure before any event is returned;
6. proof that `DRY_RUN` and `DETECT_ONLY` remain fixed;
7. proof that no path, process, network, credential, quarantine, or remediation
   operation occurs.

Live sensor APIs, installers, privileged services, on-access scanning,
quarantine, cleanup, repair, deployment, and kill-switch changes require
separate bounded authorization and review.

## FW-AID AI workload attribution

The future MicroSensor envelope extends through a versioned FW-AID reference,
not a parallel endpoint schema. Where available, endpoint observations may
carry bounded references for agent/model/session/task identity, initiating
user, capability lease, Action Ticket, tool/MCP action, process ancestry,
filesystem classification, network destination class, denial, injection
indicator, and Evidence. Raw prompts, retrieved content, commands, credentials,
tokens, and secrets are excluded by default.

Endpoint adapters remain observation producers. NormalizedEventStore remains
the canonical bounded queue; FW-AID classifies and correlates its references
with AV, identity, network, browser/email, MCP, and SOC facts. Sensors cannot
authorize containment, and the current caller-supplied DRY_RUN/DETECT_ONLY
boundary remains unchanged.
