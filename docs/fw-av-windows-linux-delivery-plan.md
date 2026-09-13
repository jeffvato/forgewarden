# FW-AV Windows/Linux delivery definition

## Product intent

FW-AV is ForgeWarden's native anti-malware and endpoint-protection capability.
The first deployable family targets managed Windows and Linux endpoints. macOS,
Android, and iOS follow as separately engineered platform releases; they are
not assumed to share endpoint privileges or response mechanisms with the first
two targets.

The product is designed for low memory use: its deterministic detector must
stream bounded data, retain only bounded metadata and performance caches, and
never require a local general-purpose AI model to protect an endpoint. AI may
help triage only through the approved Model Broker and never receives authority
to scan, quarantine, clean, or repair.

## User-approved response model

1. Every detection creates a local warning and canonical Evidence record.
2. Automatic quarantine is allowed only for a high-confidence result from
   trusted, integrity-verified detection content and only after deterministic
   policy, tenant/device identity, scope, and kill-switch checks.
3. Quarantine is containment, not deletion: the original must be recoverable,
   its digest and provenance preserved, and the action bounded and reversible.
4. Unknown, heuristic, behavioral, or AI-assisted findings warn and create
   evidence but do not automatically quarantine until their policy and proof
   are explicitly approved.
5. Clean and repair are Class 3 remediation/recovery actions. They require the
   canonical Action Ticket, stronger policy approval (normally human/dual
   control), immutable Evidence, recovery validation, and the engaged
   kill-switch boundary. They are never inferred from an AI recommendation.

This decision defines target behavior only. `DRY_RUN` remains enforced and
deployment remains disabled until a separately authorized deployment workflow.

## First release architecture

### Endpoint MicroSensor

Platform-native Windows and Linux agents collect the minimum needed endpoint
facts: file lifecycle events, process ancestry, executable identity, and
bounded runtime/network indicators. They enforce backpressure, priority, CPU
and memory limits so protection cannot starve a user workload or deterministic
security controls. A MicroSensor is not a privileged universal shell and does
not give agents arbitrary filesystem/process authority.

### Detection engine

The engine processes bounded byte streams and metadata using a staged pipeline:

1. cache lookup and exact SHA-256 trusted signatures;
2. trusted literal and later YARA-compatible content indicators;
3. archive, document, and script inspection with strict recursion, size, time,
   and decompression-ratio limits;
4. process/memory and behavior indicators correlated through FW-ENDPOINT;
5. optional sandbox escalation for non-blocking analysis, never execution on
   the protected endpoint.

Detection content must be versioned, publisher-trusted, integrity-verified,
rollback-capable, and auditable. Network reputation is an enrichment source,
not an authority source; unavailable or untrusted enrichment cannot turn a
warning into a quarantine decision.

### Decision and response path

`MicroSensor → detector → canonical event/evidence → deterministic policy →
bounded Action Ticket where required → containment/recovery workflow → review`

The existing FW-ASOC authority controls provide tenant-bound leases, bounded
delegation, aggregate limits, Model Broker checks, canonical Evidence, and
kill-switch behavior. FW-AV must reuse those boundaries rather than inventing
another policy, ticket, audit, model, gateway, or execution framework.

### Quarantine vault and recovery

The future quarantine component must preserve encrypted recoverable content or
a safe immutable reference, original metadata, digest, source path/device,
reason, rule/content version, policy decision, action ticket, timestamps, and
review state. It must resist path traversal, link attacks, replacement races,
cross-tenant access, replay, and unauthorized restore. Restore, cleanup, and
repair are recovery operations, not scanner operations.

## Required work before deployment

| Capability | Required outcome |
|---|---|
| Device and tenant identity | FW-ID device/workload identity binds every endpoint and response scope. |
| Endpoint event schema | Canonical normalized events carry detection, process, file, and containment facts. |
| Detection content trust | Publisher identity, signed/versioned bundles, anti-rollback, expiry, and safe local cache. |
| Windows/Linux agents | Privilege-minimized installer/service, safe event sources, stream scanner, scheduler, bounded caches, self-protection, and uninstall/recovery path. |
| Content inspection | Hash, trusted content/YARA-compatible rules, archive/document/script parsers with resource limits and hostile-input tests. |
| Endpoint telemetry | Process/memory/runtime/IOA correlation, compatible with FW-ENDPOINT and FW-SOC. |
| Quarantine | Reversible tenant/device-scoped containment under deterministic policy, Action Tickets, Evidence, recovery, and kill switch. |
| Clean/repair | Explicit Class 3 recovery workflows with approval/dual control, snapshots where appropriate, validation, and rollback. |
| Operations | Signed packages, update rollback, health, metrics, capacity/backpressure, fleet rollout, and incident support. |
| Proof | Unit, integration, adversarial, performance, restart/recovery, cross-tenant, kill-switch, false-positive, and pilot evidence for exact release commits. |

## Delivery sequence

1. Complete the deterministic detector core: trusted content bundles, stream
   interfaces, cache bounds, and hostile-input limits.
2. Add Windows and Linux MicroSensors in dry-run observation mode, with
   canonical identity/events/Evidence and measurable memory baselines.
3. Prove detect-and-warn operation against controlled fixtures and benign
   workloads.
4. Add high-confidence reversible quarantine behind deterministic policy and
   Action Tickets; prove recovery, kill switch, and cross-tenant denial.
5. Add controlled clean/repair workflows through FW-REC only after their
   separate high-impact approval and rollback proof.
6. Package, performance-test, and pilot on explicitly selected Windows/Linux
   hardware and fleet-management environments before any production rollout.
7. Build macOS, Android, and iOS variants using their platform-native security
   APIs and permission models; mobile platforms remain managed-device products,
   not repackaged desktop agents.

## Current implementation status

The bounded offline controls now include signed catalogs, ClamAV-compatible admission, YARA-compatible rules and evaluation, bounded content inspection, Windows/Linux caller-supplied fixtures through NormalizedEventStore recovery replay, Android fixture batches, and dry-run quarantine/recovery/release proposals with an in-memory vault. The detector also exposes an immutable multi-artifact scan report with catalog-bound digests and canonical Evidence, suitable for an offline pilot or customer assurance report. See `completion-audit-2026-09-09.md` for source and historical proof.

These are fixture/offline controls, not installed endpoint services or a deployable AV release. Live sensors, hooks, transport, actual containment/restore/cleanup/repair and deployment remain disabled and outside current authorization. Do not reimplement completed offline controls from earlier versions of this status paragraph.
