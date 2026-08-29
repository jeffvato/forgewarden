# FW-INTEGRITY Product Functionality Map

The authoritative machine-readable map is `swarm.integrity.FUNCTIONALITY_MAP`.
This summary is intentionally conservative:

| Requirement | State | Responsible component | Golden Path | Main limitation |
|---|---|---|---|---|
| FW-CORE | Proven | `swarm.core`, `swarm.autonomous_loop` | Core dry-run/review path | No production deployment or live mutation |
| FW-ASOC-01 | Implemented | `swarm.asoc.CapabilityAuthorizer` | Not yet | In-memory endpoint; real canonical Model Broker/MCP/Action Ticket wiring pending |
| FW-INTEGRITY | Implemented | `swarm.integrity` | Baseline Core path | Dependency lock, clean-build packaging, and broader end-to-end paths remain |

Defined-but-not-yet-concrete ownership includes FW-ID, normalized events,
FW-SOC, and FW-COMP. This is not a claim that those requirements are broken;
they are not yet Proven in this checkout. Every meaningful checkpoint must add
the exact commit, unit/integration/Golden Path evidence, limitations, and
health color to this map and its machine-readable source.
