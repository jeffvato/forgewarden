# Public CI security inventory

ForgeWarden's public validation workflow is a read-only assurance boundary. It
runs deterministic tests and produces bounded advisory review artifacts; it
does not authorize merge, mutation, release, deployment, model invocation, or
changes to the kill switch.

## Enforced in repository source

- GitHub Actions receive only `contents: read` for pull-request validation.
- Every external action reference is pinned to a full 40-character commit SHA.
- Checkout credentials are not persisted in the validation worktree.
- Duplicate runs on the same ref are cancelled and every job and substantive
  command has a timeout.
- Python 3.11 and 3.12 run the portable fixture proof, the current full pytest
  suite, the dependency-free Mission Control Node contract, and the Git
  whitespace check.
- Pull requests also produce the existing read-only quality report and
  revision-bound codebase-index evidence. Published artifacts contain bounded
  reports, not credentials or runtime state.
- Deterministic tests parse every workflow for immutable action pins and parse
  validation for least privilege, time bounds, required proofs, and checkout
  credential handling.

The workflow intentionally performs no deployment. The separate hosted Azure
vulnerability-image publishing workflow is retired and unavailable; Azure
resources are not an active publishing target. The local read-only
vulnerability tooling and `Dockerfile.vulnerability-job` remain non-deployed
artifacts. `DRY_RUN`, deployment `DISABLED`, and the engaged kill switch remain
product invariants.

## Operator-controlled protections

Repository rules and GitHub security products cannot be enabled by this
workflow. An operator must separately configure branch protection and required
checks, read-only default workflow tokens, fork approval policy, secret
scanning and push protection, dependency graph and alerts, and any code-scanning
entitlements. Those settings should fail closed and must not grant pull-request
workflows write access.

CodeQL, dependency review, Dependabot, Scorecard, Sonar, license policy, SBOM,
container scanning, release signing, and provenance attestations are not part
of this increment. Enabling hosted analysis also requires an explicit decision
about source-derived data, artifact retention, licensing, and external service
terms. The absence of those controls must not be interpreted as a passing
security assessment.
