# FW-SUPPLY-001 — Software supply-chain ownership inventory

## Existing canonical controls

ForgeWarden already has bounded pieces of software supply-chain protection. They
remain owned by their existing modules and are inputs to FW-SUPPLY rather than
new parallel engines.

| Concern | Existing owner and boundary |
| --- | --- |
| Dependency discovery and advisory matching | `swarm.vulnerability_index`; read-only requirements/package inventory and normalized OSV, NVD, and CISA KEV matches |
| Add-on manifests and package admission | `swarm.addons` and `swarm.addon_catalog`; exact manifest digest, trusted publisher, safe entrypoint, duplicate-ID denial, local catalog |
| Signed security-definition provenance | `TrustedSignatureCatalog` and FW-KEYS lifecycle binding |
| Release fixture validation | Existing Phase 5 release-readiness/candidate/audit controls; deployment stays disabled |
| Artifact inspection | FW-AV bounded artifact, archive, document, and script evaluators |
| Vulnerability and integrity visibility | Product Integrity dependency checks and existing vulnerability reports |
| Identity, authorization, and evidence | FW-ID, FW-KEYS, deterministic policy, Action Tickets, and FW-EVID |
| Operator incident visibility | FW-SOC and Mission Control read-only projections |

These controls do not yet form a canonical FW-SUPPLY lifecycle. In particular,
the repository does not have one strict tenant-bound component observation that
can carry a caller-supplied package identity, ecosystem, version, artifact
digest, source/provenance references, and Evidence reference through
classification, proposal, and Mission Control stages.

## First missing boundary

`FW-SUPPLY-002` will add that immutable caller-supplied metadata contract. It
will accept no package contents, credentials, source code, build logs, network
responses, or executable commands. It will not fetch vulnerability feeds,
install packages, alter lockfiles, run builds, publish artifacts, or deploy.

The observation will reuse the current vulnerability and trusted-catalog owners
through canonical references. Later milestones will classify exact supplied
facts, bind existing catalog/signature/vulnerability references, create only an
inert policy and Action Ticket proposal, and prove the lifecycle through Mission
Control.

## Incremental route

1. `FW-SUPPLY-002`: immutable tenant-bound component/provenance observation.
2. `FW-SUPPLY-003`: deterministic vulnerability and provenance classification.
3. `FW-SUPPLY-004`: canonical vulnerability, catalog, signature, and Evidence reference binding.
4. `FW-SUPPLY-005`: inert policy and Action Ticket-bound remediation proposal.
5. `FW-SUPPLY-006`: integrated lifecycle proof and Mission Control projection.

Each ID is a substantive gated milestone. No placeholder successor is created.

## Authority boundary

All inputs remain caller-supplied untrusted metadata. FW-SUPPLY adds no live
repository, registry, package-manager, CI/CD, container, cloud, feed, or build
access. It adds no dependency update, install, deletion, publication, signing,
release, deployment, rollback, quarantine, remediation, or response execution.
DRY_RUN, disabled deployment, the engaged kill switch, tenant isolation, and
canonical FW-KEYS/FW-EVID/Action Ticket ownership remain authoritative.
