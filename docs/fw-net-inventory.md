# FW-NET-001 — Network security ownership inventory

## Existing canonical controls

ForgeWarden already normalizes and correlates bounded network facts in several
Core subsystems. FW-NET consumes these owners rather than creating another
endpoint store, AI detector, incident system, policy engine, or evidence log.

| Concern | Existing owner and boundary |
| --- | --- |
| Endpoint network observations | `swarm.endpoint_fixtures`, `swarm.macos_fixtures`, `swarm.sensor_adapter`, and `NormalizedEventStore`; caller-supplied `NETWORK_CONNECT` facts only |
| Ransomware lateral movement | `swarm.ransomware`; bounded same-tenant SMB propagation correlation and advisory findings |
| AI-agent egress and lateral risk | `swarm.ai_agent_defense`; exact AID egress/lateral indicators, deterministic risk, and inert proposals |
| Browser/email network-adjacent facts | `swarm.browser_email`; caller-supplied hostile-content indicators without DNS, HTTP, or mailbox access |
| Identity and authorization | FW-ID, FW-KEYS, deterministic policy, capability leases, and Action Tickets |
| Incident and evidence ownership | FW-SOC and FW-EVID; canonical incident references and Evidence chronology |
| Operator visibility | Mission Control read-only projections and explicitly labelled demo data |

These controls do not yet provide one canonical FW-NET lifecycle. The first
missing runtime boundary is a strict immutable observation for caller-supplied
network metadata that preserves tenant, device, source, destination, protocol,
port, direction, indicators, and canonical references without accepting packet
contents, credentials, commands, or a live connection.

## First missing boundary

`FW-NET-002` will add that immutable metadata contract. It will not open a
socket, capture traffic, query DNS/DHCP, inspect TLS sessions, scan hosts, read
firewall state, contact network infrastructure, or alter a route or policy.

Later milestones will classify exact supplied facts, bind canonical Endpoint,
FW-AID, FW-SOC, Identity, and FW-EVID references, create only an inert policy
and Action Ticket proposal, and prove the lifecycle through Mission Control.

## Incremental route

1. `FW-NET-002`: immutable tenant-bound caller-supplied network observation.
2. `FW-NET-003`: deterministic network anomaly and threat classification.
3. `FW-NET-004`: canonical Endpoint, FW-AID, FW-SOC, Identity, and FW-EVID reference binding.
4. `FW-NET-005`: inert policy and Action Ticket-bound containment proposal.
5. `FW-NET-006`: integrated lifecycle proof and Mission Control projection.

Each ID is a substantive gated milestone. No placeholder successor is created.

## Authority boundary

All inputs remain caller-supplied untrusted metadata. FW-NET adds no packet
capture, live sensor, listener, DNS/DHCP/TLS query, host scan, socket, firewall,
NAC, VPN, wireless, switch, router, identity-provider, or cloud-network access.
It adds no segmentation, route change, connection termination, egress denial,
isolation, credential action, containment, remediation, deployment, or response
execution. DRY_RUN, disabled deployment, the engaged kill switch, tenant
isolation, and canonical policy, Action Ticket, FW-EVID, and Git-controller
ownership remain authoritative.
