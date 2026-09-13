# FW-OPS canonical operations inventory

FW-OPS owns operational health, capacity, backpressure, workload-isolation
observations, availability/continuity metadata, and the future telemetry export
boundary. It does not own security Evidence, security policy, task authority,
recovery execution, deployment, or domain detections. This inventory records
the accepted local DRY_RUN seams before a canonical operational projection is
implemented.

## Existing components to reuse

| Concern | Canonical implementation | Reuse boundary |
| --- | --- | --- |
| Repository and product health | `swarm.integrity.run_product_integrity_gate` | Build, startup, configuration, test, Golden Path, dependency, invariant, ownership, Git-head, and GREEN/YELLOW/RED facts. It remains a validation gate rather than an operations database. |
| Endpoint pipeline capacity | `swarm.sensor_adapter.DryRunSensorPipeline.metrics` and `NormalizedEventStore` | Bounded accepted/rejected counts, peak batch size, and queued-event pressure for caller-supplied fixtures. No live sensor collection is implied. |
| Harness anomaly and recovery status | `swarm.harness_recovery` | Deterministic stuck, retry, resource, scope, Evidence, identity, and test-health decisions with bounded repair proposals. It owns no service restart or rollback execution. |
| Harness task and budget state | `swarm.harness_task`, `swarm.harness_context`, and `swarm.mission_control` | Persistent task state, bounded budget admission, and immutable operator projections. |
| Recovery continuity | `swarm.recovery` | Immutable checkpoints and fail-closed resume admission. FW-REC remains the recovery owner. |
| Loopback status | `swarm.console` and canonical Mission Control providers | Read-only local status presentation. Existing loopback HTTP is a presentation adapter, not the FW-OPS source of truth. |
| Security audit and Evidence | `swarm.core.AuditLog` and `swarm.evidence` | Security lifecycle provenance stays in FW-EVID. Operational measurements may reference Evidence but must not be written into a competing evidence chain. |
| Runtime process bounds | trusted controller/adapters and systemd/Docker packaging | Existing bounded subprocess, timeout, memory/CPU and network restrictions remain the enforcement seams. FW-OPS may report their supplied state but cannot expand them. |

## Current implemented boundary

ForgeWarden already has bounded local health and capacity facts in several
canonical owners. Product Integrity validates the repository and architecture;
the endpoint fixture pipeline exposes bounded counters; Harness monitoring
classifies failures; Recovery preserves restart metadata; Mission Control
renders read-only status. These pieces are implemented and tested in their own
families, but FW-OPS does not yet provide a single tenant-bound operational
health contract.

No current component provides production HA, active/active or active/standby
coordination, quorum, OpenTelemetry export, hot/warm retention movement,
service restart, update rollout, update rollback, or live resource collection.
Those capabilities remain planned and require separate authority, deployment,
and infrastructure decisions.

## First missing capability

FW-OPS-002 should add one immutable, caller-supplied operational health
projection. It should combine bounded component health, queue pressure,
resource-budget utilization, freshness, and current safety state; calculate a
deterministic HEALTHY/DEGRADED/UNHEALTHY result; and write privacy-minimized
canonical Evidence before returning read-only metadata.

The projection must be tenant-bound, versioned, size-limited, replay-safe, and
explicit about unavailable inputs. It must reject cross-tenant, stale,
secret-bearing, unbounded, kill-switch-cleared, or deployment-enabled input.
It must not poll hosts, start or stop processes, open listeners, export
telemetry, mutate queues, invoke recovery, perform rollback, change policy, or
grant authority.

## Safe sequence

1. FW-OPS-002 — canonical tenant-bound operational health projection.
2. FW-OPS-003 — bounded capacity/backpressure threshold assessment using
   caller-supplied canonical metrics.
3. FW-OPS-004 — local checkpoint/restart continuity proof across FW-OPS,
   FW-REC, FW-EVID, and Mission Control without executing recovery.
4. Later separately authorized work may define telemetry-export and HA/DR
   adapters after deployment, credential, network, and infrastructure
   boundaries are approved.

Throughout this sequence DRY_RUN, disabled deployment, the engaged kill switch,
tenant isolation, Evidence separation, and deterministic authority remain
mandatory.

## FW-OPS-002 implemented contract

`swarm.operations` now provides an immutable version-1 operational snapshot
and Evidence-first health projection. It accepts at most 32 caller-supplied,
tenant-bound component observations containing only enumerated state and
bounded queue/budget counters. Deterministic 80% and 100% thresholds produce
HEALTHY, DEGRADED, or UNHEALTHY metadata; explicit degraded, unavailable, and
unhealthy component states take precedence as documented in code.

The registry denies malformed, secret-bearing, duplicate, cross-tenant, stale,
expired, replayed, unsafe-runtime, excessive, over-limit, Evidence-failed, and
foreign-Evidence input. Output is fixed to DRY_RUN, deployment DISABLED,
OBSERVE_ONLY, `recovery_invoked=False`, and `authority_granted=False`.
No host polling, queue mutation, telemetry export, listener, process/service
control, recovery, rollback, credential access, or deployment is present.
