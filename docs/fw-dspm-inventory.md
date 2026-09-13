# FW-DSPM-001 — Data security posture ownership inventory

## Existing canonical controls

FW-DSPM composes existing ForgeWarden owners. It does not create a second data
catalog, identity system, DLP engine, policy engine, incident system, or
evidence store.

| Concern | Existing owner and boundary |
| --- | --- |
| Endpoint and asset attribution | FW-ENDPOINT caller-supplied fixtures, FW-ID, and canonical asset references |
| Browser, email, and hostile-content facts | `swarm.browser_email` and FW-AID; content remains untrusted data and is not ingested by DSPM |
| SaaS and cloud posture | FW-SAAS immutable caller-supplied metadata and canonical correlation references |
| Repository and dependency provenance | FW-SUPPLY plus the vulnerability index; no repository crawl is added |
| AI-workflow attribution | FW-HARNESS, FW-AID, Approved Model Registry, leases, and Action Tickets |
| Identity and secret boundaries | FW-ID identities and FW-KEYS opaque handles; no secret material is admitted |
| Policy and authorization | Deterministic policy/Z3 boundary and signed single-use Action Tickets |
| Incidents, chronology, and evidence | FW-SOC and FW-EVID canonical references |
| Operator visibility | Mission Control read-only canonical or explicitly simulated projections |

The repository does not yet have one strict tenant-bound DSPM observation for
caller-supplied data-classification and posture facts across those owners.

## First missing boundary

`FW-DSPM-002` will add an immutable caller-supplied observation containing only
bounded metadata: data-asset reference, classification, location class, owner
identity reference, access-path class, copy count, encryption state,
AI/agent-access state, policy state, observation time, and Evidence reference.

It will not read content, enumerate files, query endpoints, browsers, mailboxes,
SaaS/cloud services, databases, repositories, models, or MCP servers. It accepts
no credential, secret, prompt, document body, row value, message, token, key,
connection string, or customer content.

## Incremental route

1. `FW-DSPM-002`: immutable tenant-bound caller-supplied data-posture observation.
2. `FW-DSPM-003`: deterministic exposure, access, encryption, copy, and AI-access risk classification.
3. `FW-DSPM-004`: canonical asset, identity, SaaS, supply, AI-workflow, policy, incident, and Evidence reference binding.
4. `FW-DSPM-005`: inert policy and Action Ticket-bound DLP/risk-reduction proposal.
5. `FW-DSPM-006`: integrated lifecycle proof and Mission Control projection.

Each ID is a substantive gated milestone. No successor placeholder is created.

## Authority boundary

All inputs remain caller-supplied untrusted metadata. FW-DSPM adds no content
discovery or inspection, filesystem/database/cloud/SaaS query, credential use,
classification by model, data copying, deletion, encryption, token revocation,
DLP enforcement, quarantine, containment, remediation, deployment, or response
execution. DRY_RUN, disabled deployment, the engaged kill switch, tenant
isolation, privacy minimization, and canonical owners remain authoritative.
