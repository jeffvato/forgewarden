# FW-INTEGRITY Product Functionality Map

The authoritative machine-readable map is `swarm.integrity.FUNCTIONALITY_MAP`.
This summary is intentionally conservative:

| Requirement | State | Responsible component | Golden Path | Main limitation |
|---|---|---|---|---|
| FW-CORE | Proven | `swarm.core`, `swarm.autonomous_loop` | Core dry-run/review path | No production deployment or live mutation |
| FW-ASOC-01 | Integrated | `swarm.asoc.CapabilityAuthorizer` plus Action Tickets, Model Broker, and MCP Gateway | Canonical authorization, replay denial, kill-switch denial, recovery denial, and cross-tenant denial | In-memory single-process registries; full external Z3 policy solver remains future work |
| FW-INTEGRITY | Implemented | `swarm.integrity` | Baseline Core path | Dependency lock, clean-build packaging, and broader end-to-end paths remain |

Defined-but-not-yet-concrete ownership includes FW-ID, normalized events,
FW-SOC, and FW-COMP. This is not a claim that those requirements are broken;
they are not yet Proven in this checkout. Every meaningful checkpoint must add
the exact commit, unit/integration/Golden Path evidence, limitations, and
health color to this map and its machine-readable source.
