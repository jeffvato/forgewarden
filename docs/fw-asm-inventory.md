# FW-ASM-001 — External attack-surface ownership inventory

## Existing canonical controls

FW-ASM composes existing ForgeWarden owners. It does not create a second asset
inventory, vulnerability index, network detector, certificate authority,
incident system, or evidence store.

| Concern | Existing owner and boundary |
| --- | --- |
| Endpoint and asset identity | FW-ENDPOINT caller-supplied fixtures, FW-ID, and canonical asset references |
| Network exposure facts | FW-NET immutable caller-supplied observations, advisory classification, and canonical owner binding |
| SaaS and cloud application facts | FW-SAAS caller-supplied posture/threat metadata and canonical correlation references |
| Component and vulnerability facts | `swarm.vulnerability_index` plus FW-SUPPLY component/provenance lifecycle |
| Certificate and signing identity | FW-KEYS opaque handles and `TrustedSignatureCatalog`; no key material or signing authority |
| Incidents and evidence | FW-SOC and FW-EVID canonical references and chronology |
| Policy and operator visibility | Deterministic policy, Action Tickets, and Mission Control read-only projections |

The repository does not yet have one strict FW-ASM observation that represents
an externally visible asset and caller-supplied exposure facts while retaining
tenant, ownership, provenance, and Evidence bindings.

## First missing boundary

`FW-ASM-002` will add an immutable tenant-bound caller-supplied observation for
an external asset type, asset reference, exposure reference, service/protocol
metadata, ownership state, visibility state, and Evidence reference. It accepts
no response body, credential, certificate material, packet, exploit payload, or
command.

It will not discover domains, resolve DNS, scan ports, connect to an endpoint,
query cloud providers, inspect certificates, crawl websites, or access a CMDB.

## Incremental route

1. `FW-ASM-002`: immutable tenant-bound caller-supplied external-asset observation.
2. `FW-ASM-003`: deterministic exposure, ownership, and exploitability classification.
3. `FW-ASM-004`: canonical asset, network, vulnerability, certificate, FW-SOC, and FW-EVID reference binding.
4. `FW-ASM-005`: inert policy and Action Ticket-bound risk-reduction proposal.
5. `FW-ASM-006`: integrated lifecycle proof and Mission Control projection.

Each ID is a substantive gated milestone. No placeholder successor is created.

## Authority boundary

All inputs remain caller-supplied untrusted metadata. FW-ASM adds no discovery,
DNS resolution, port scan, socket, HTTP request, cloud/CMDB query, certificate
retrieval, credential use, exploit attempt, asset mutation, takedown,
containment, remediation, deployment, or response execution. DRY_RUN, disabled
deployment, the engaged kill switch, tenant isolation, and canonical owners
remain authoritative.
