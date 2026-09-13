# FW-INTEGRITY capability reality audit

## Purpose

ForgeWarden needs a machine-checkable answer to a basic product question:
does an accepted requirement still point to concrete implementation,
validation, Evidence, and Git history? The audit_completed_requirement_work
function adds that narrow traceability proof to the existing Product Integrity
owner.

The audit does not execute tests and does not infer that a feature is live,
effective in production, deployed, or production-ready. Those claims require
current deterministic validation, exact review, operational integration, and
separate activation evidence.

## Existing owners reused

- WORK_QUEUE.md remains the accepted requirement and completion record.
- swarm.integrity remains the Product Integrity and functionality-map owner.
- Git remains the exact commit/history owner.
- Existing source, tests, Golden Paths, and saved review/integrity documents
  remain the implementation and validation artifacts.
- Mission Control remains a read-only consumer in a later milestone.

No second status registry, Evidence store, queue, policy engine, or UI schema is
created.

## Deterministic contract

For every DONE stable requirement item other than historical FWQ control
records, the audit:

1. reads its declared allowed paths and test command;
2. distinguishes documentation-only records from implementation records;
3. verifies referenced repository artifacts still exist;
4. resolves at least one recorded completion commit through Git;
5. records explicit reasons for any unsupported claim;
6. compares accepted families with the canonical functionality map.

Wildcard Evidence references are accepted only when they match existing
repository files. Paths remain repository-relative and are never executed.

The Product Integrity Gate treats unsupported accepted-work traceability as a
hard failure. Accepted families missing from the older functionality map are a
YELLOW product-status gap because the missing map entry is not proof that the
underlying accepted work is absent.

## Inventory result before candidate review

The first run reconciled 114 accepted requirement tasks across 22 families.
After correcting four stale completion-record references, all 114 were
traceable to surviving paths, declared tests where applicable, and at least one
resolvable completion commit.

The audit also found that 14 accepted families were absent from the static
functionality map: FW-API, FW-ASM, FW-BME, FW-DSPM, FW-ENDPOINT, FW-GOV,
FW-HARNESS, FW-MCP, FW-NET, FW-RANSOM, FW-SAAS, FW-SOC, FW-SUPPLY, and FW-UX.
That gap is now visible in Product Integrity rather than hidden by a green test
count.

The corrected historical metadata named an unused FW-AID fixture directory, an
obsolete endpoint-adapter module, a nonexistent ownership YAML file, and a
control-mapping candidate SHA damaged by an escape character. The corrections
point to the actual existing canonical files and commit; they do not replay or
reimplement those completed milestones.

## Limits and next milestone

This milestone proves traceability only. It does not establish code coverage,
mutation resistance, runtime effectiveness, clean-start behavior, or live
sensor/provider/containment capability.

The next bounded milestone should reconcile the 14 missing family entries into
a truthful capability-status projection with explicit operating boundaries,
then expose that projection read-only in Mission Control. A later Golden Path
must execute representative cross-family behavior at the current exact commit
instead of relying on recorded historical test counts.
