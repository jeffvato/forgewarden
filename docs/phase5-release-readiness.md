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

## Local allowlisted candidate

FWQ-0081 adds a local disposable candidate builder for the exact `PUBLIC_SDK`
and `SOURCE_AVAILABLE_DEMO` allowlists. The SDK track contains the existing
add-on SDK documentation and schema contract without its private Core dependency
chain; the demo track contains the existing Mission Control UI
and deterministic demo provider. The builder binds regular tracked files to an
expected source commit, scans each included byte for prohibited identifiers and
credential-shaped data, applies file and byte budgets, and emits a normalized
digest manifest with `publication: DISABLED`. The public manifest contains a
domain-separated one-way source binding instead of the private repository's raw
historical commit identifier. It copies no unlisted file, Git
history, ref, private Core, review, Evidence, generated state, or unproven media.

The candidate is not a repository and the builder cannot select a license,
initialize Git, add a remote, use a network/provider/credential, publish,
deploy, change visibility, or grant authority. A later release controller and
explicit human gates must independently authorize any release operation.

## Offline dependency provenance candidate

FWQ-0082 validates an exact local export manifest, its one-way private-source
binding, the current export policy, every allowlisted path, size, and digest,
and the absence of extra paths or Git metadata. It then classifies bounded
Python, Markdown, JavaScript, HTML, CSS, and JSON references without installing
packages or consulting a registry. The SDK track is explicitly documentation
and schema only. The source-available Demo includes its deterministic local
data fallback; canonical same-origin API routes remain declared optional
interfaces and are not required for the static Demo to load.

The deterministic result is a `FORGEWARDEN_SBOM_CANDIDATE_V1` document aimed at
future SPDX 2.3 conversion. It is not a conformance, license-clearance, legal,
or production-readiness claim. File and reference licenses remain
`NOASSERTION`; legal, chain-of-title, trademark/media, dependency-review, and
Customer Root gates remain pending. The result includes only file, manifest,
policy, and one-way source-binding digests, never the private source commit.
Network, package installation, provider, credential, Git-remote, publication,
deployment, and authority operations remain absent.


## Reproducible local repository candidate

FWQ-0083 materializes an exact FWQ-0081 candidate only after the FWQ-0082
offline provenance facts and their caller-supplied digests validate. The
controller writes the unchanged candidate files and public manifest plus one
canonical `FORGEWARDEN-PROVENANCE.json` document into a new local directory.
It initializes a fresh SHA-1 Git object database, stages only those files, and
uses Git plumbing with fixed ForgeWarden release-controller identity, timestamp,
branch, and message metadata to create one reproducible parentless commit.

The verifier requires exactly `refs/heads/main`, one reachable root commit,
the expected tree and worktree path sets, clean status, no extra or unreachable
objects, and no hooks, alternates, remotes, tags, inherited refs, local identity,
or credential configuration. Git runs with system/global configuration disabled
and a constant environment; only a small command allowlist and bounded output,
runtime, and command count are accepted. The same inputs must produce the same
tree and root commit. Any candidate drift, binding mismatch, existing or unsafe
destination, link/special file, extra path/object/ref, budget failure, or Git
failure removes the partial output and fails closed.

This result remains a disposable local repository candidate. Its files retain
`NOASSERTION` license status, all legal and Customer Root gates remain
pending, and publication and production readiness remain disabled. The
controller has no remote creation, network, provider, credential, package,
visibility, publication, deployment, or authority capability.
