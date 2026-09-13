# Phase 5 public-release readiness plan

Release: `forgewarden_public_release_v1`

Status: `PLANNING_ONLY`; publication: DISABLED. It authorizes no visibility
change, export, push, publication, deployment, credential use, or external act.

## Canonical boundary

Phase 5 remains the single public-release readiness owner. This repository is
`PRIVATE_CORE` and stays private. A later deletion would not remove internal
records from Git history, so a public export must use an explicit file
allowlist and `SANITIZED_SINGLE_COMMIT`; `PRESERVE_HISTORY` is unsupported. The
export must start a new repository with one initial commit and no source-history
or source-reference metadata.

- `PUBLIC_SDK` may eventually contain approved standalone contracts, schemas,
  client code, synthetic examples, and public documentation.
- `SOURCE_AVAILABLE_DEMO` may eventually contain an allowlisted simulated
  demonstration surface under separately selected terms.
- `PRIVATE_CORE` contains the trusted controller, security engines, policy,
  Evidence, provider adapters, operations, tests, reviews, and deployment
  configuration.

The public tracks exclude private Core and make no OSI open-source claim. Public
visibility and OSI licensing are separate: visibility alone grants no license.
No entity, license, trademark policy, or media license has been selected.

## Required gates

Legal review must verify chain of title and contributor rights, select the
entity and track license, clear trademarks, and establish commercial-use
provenance for every bundled or generated asset.

Dependency evidence must cover direct and transitive dependencies, immutable
artifact hashes, third-party notices, an SBOM, and container base-image
digests. A tracked-file secret audit and full-history secret audit must pass.
Private Evidence, reviewer transcripts, credentials, local audits, usernames,
home paths, personal names, email addresses, machine fingerprints, internal
URLs/hosts, cloud tenant/subscription/client/registry/resource/deployment IDs,
historical commit/job/evidence/provider-session IDs, credential-shaped
fixtures, customer/tenant/endpoint examples, unproven assets and their metadata,
and private configuration must be absent from the allowlist. Only canonical
ForgeWarden requirement, schema, and API identifiers plus deterministic
fictional demo IDs are identifier-sanitization exceptions.

Security, licensing, chain-of-title, trademark/media, dependency/SBOM,
secret/history, reproducible-build, documentation, and clean-export CI reviews
must approve the exact export. Legal and Customer Root approval bind to that
commit. AI, CI, schema data, and tests cannot approve or enable publication.

This admission milestone creates no license, notice, SBOM, dependency lock,
sanitized export, public SDK, demo package, repository, artifact, legal opinion,
or publication workflow. It performs no dependency lookup or license decision.
