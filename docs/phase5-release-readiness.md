# Phase 5 public-release readiness plan

Release: `forgewarden_public_release_v1`

Status: planning-only. No publication, push, package upload, or external
repository operation is authorized by this plan.

## Release boundary

Before any public release, the repository must be detached from Jeff-specific
usernames, home paths, local audits, source-repository state, credentials,
machine fingerprints, and private infrastructure details. The release must
ship safe configuration templates, pinned dependencies and lockfiles, and
documented install, validation, update, rollback, and uninstall paths.

## Required reviews

Security review must confirm no secret, private audit, remote-host detail, or
unsafe default remains. Licensing review must cover source and bundled assets.
Reproducible-build review must verify the declared environment and lockfiles.
Documentation review must verify that every operational path fails closed and
does not imply production authorization.

CI must run the declared portable validator in a clean environment. Publication
remains disabled until all reviews, clean-room checks, and an explicit release
approval are recorded.
