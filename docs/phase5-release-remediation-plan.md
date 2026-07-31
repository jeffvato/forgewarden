# Phase 5 release remediation plan

Status: planning-only. This plan does not edit, publish, or delete repository
files.

## Finding batches

1. User/home paths — 128 findings. Replace only after confirming each path is
   documentation, test fixture, generated output, or active runtime behavior.
2. Private audits — 32 findings. Remove from public artifacts; retain only in
   protected local evidence stores with explicit exclusions.
3. Credential-like assignments — 12 findings. Review manually, rotate any
   real credential if present, and replace examples with synthetic placeholders.
4. Machine fingerprints — 2 findings. Replace distro, hostname, machine ID,
   and serial-specific references with declared-environment placeholders.
5. Unreadable files — 167 findings. Classify binary, permission-protected,
   generated, or unsupported files; do not weaken read protections to scan them.

## Safe sequence

First produce an inventory with path, category, ownership, and intended public
status. Then apply narrow, reviewable patches only to confirmed public-release
artifacts. Re-run the scrubber, secret scan, dependency lock checks, and clean
portable validator after each batch. A clean result is required before any
release approval; publication remains disabled throughout remediation.
