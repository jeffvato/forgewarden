# FW-INTEGRITY Product Functionality Map

The authoritative machine-readable map is `swarm.integrity.FUNCTIONALITY_MAP`.
This summary is intentionally conservative:

| Requirement | State | Responsible component | Golden Path | Main limitation |
|---|---|---|---|---|
| FW-CORE | Proven | `swarm.core`, `swarm.autonomous_loop` | Core dry-run/review path | No production deployment or live mutation |
| FW-ASOC-01 | Proven | `swarm.asoc.CapabilityAuthorizer` plus Action Tickets, Model Broker, and MCP Gateway | Canonical authorization, replay denial, kill-switch denial, recovery denial, and cross-tenant denial | In-memory single-process DRY_RUN registries; external service adapters and a full Z3 policy solver remain future work |
| FW-ASOC-02 | Proven | `swarm.asoc.AggregateBlastRadiusLedger`, `WorkBudgetLedger`, and `LeaseRegistry` | Aggregate caps, bounded delegation, and lease/tenant work budgets with recovery and concurrency denials | In-memory single-process DRY_RUN scope; broader ASOC orchestration remains future work |
| FW-ID | Proven | `swarm.identity` | Tenant-bound identity lifecycle and worker admission | In-memory metadata-only DRY_RUN; no live authentication or federation |
| FW-KEYS | Proven | `swarm.keys` | Opaque handle lifecycle and consumer invalidation | In-memory metadata only; no secret resolution, signing, or encryption |
| FW-EVID | Proven | `swarm.evidence` | Canonical tenant ledger, durable reconstruction, and tamper denial | Local unsigned DRY_RUN Evidence; no external storage or export |
| FW-REC | Proven | `swarm.recovery` | Checkpoint, reconstruction, and exact resume admission | Metadata-only DRY_RUN; no recovery execution |
| FW-COMP | Proven | `swarm.compliance` | Mapping, canonical Evidence admission, and bounded assessment lifecycle | In-memory metadata-only DRY_RUN; no certification, attestation, reporting, or control execution |
| FW-AID | Proven | `swarm.ai_agent_defense`, `swarm.normalized_events`, `swarm.mission_control` | Fixture-only Harness and endpoint attribution through detection, correlation, proposal, Evidence, and Mission Control | Caller-supplied DRY_RUN metadata only; no live sensors, enforcement, containment execution, recovery execution, or deployment |
| FW-OPS | Proven | `swarm.operations`, `swarm.operations_capacity`, `swarm.mission_control` | Health and capacity Evidence through checkpoint reconstruction, resume admission, and read-only continuity projection | Caller-supplied local DRY_RUN metadata; no live telemetry, HA/DR coordination, service/process control, retention movement, rollback execution, or deployment |
| FW-INTEGRITY | Implemented | `swarm.integrity` | Baseline Core path | Dependency lock, clean-build packaging, and broader end-to-end paths remain |

FW-AID now has a concrete canonical owner and integrated fixture-only proof. FW-SOC remains partially implemented.
Normalized events now have the partial canonical implementation
`swarm.normalized_events.NormalizedEventStore`; see the completion audit. This is not a claim that those requirements are broken;
they are not yet Proven in this checkout. Every meaningful checkpoint must add
the exact commit, unit/integration/Golden Path evidence, limitations, and
health color to this map and its machine-readable source.
