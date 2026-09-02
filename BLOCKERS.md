# ForgeWarden Blockers

This file records only genuine blockers that require Customer Root authority, unavailable external resources, or a condition that makes further safe work impossible.

## Current blockers

### B-003 — FW-AV Stage 2 definition-intake scope

- Related task/requirement: FW-AV publisher-signed detection-content trust; roadmap definition-source and endpoint-protection work
- Exact condition: FW-AV-40 through FW-AV-46 have completed the safe offline declaration, provenance, non-admission Evidence, snapshot, and timestamp-integrity controls. The next meaningful source-review control must interpret a named signed definition-bundle format and pass only verified content to the existing canonical catalog/trust/anti-rollback owners. The active boundary explicitly prohibits a parser and catalog admission, and Customer Root has not selected the initial format or confirmed its license boundary.
- Why work cannot continue safely: choosing a source format or translating opaque candidate bytes without that decision would create an unauthorized parser/admission system and could misrepresent upstream licensing or signature semantics. Additional non-admission metadata checks would not reduce a material product risk.
- Required authority: Customer Root selects and authorizes one initial offline signed definition-bundle format and its licensing scope. The recommended implementation boundary is a local, caller-supplied bundle adapter only; it must remain disabled by default and add no network, endpoint, credential, downloader, quarantine, remediation, or response authority.
- Canonical owners preserved: `DefinitionSourceRegistry` / `DefinitionSourceCandidateReview` for offline review evidence; `FWKeysCatalogTrustRoot`, `TrustedSignatureCatalog`, and `DurableCatalogSequenceStore` for verification, catalog admission, and anti-rollback. No parallel trust, catalog, cache, or transport system may be created.
- Checkpoint/evidence: `1915549` product proof; `09fc02c` status checkpoint. Focused FW-AV proof passed (20 tests); full Linux suite passed (665 passed, 1 skipped); default integrity gate passed every hard check and Golden Path.
- First resume action: after Customer Root selects the format/license, define the smallest non-network adapter with malformed, unsigned/untrusted, wrong-provenance, stale/replayed, and Evidence-failure denials before canonical catalog mutation.

### B-002 — Independent Gemini review capacity unavailable

- Related task/requirement: FWQ-0008 — Immutable accepted-work evidence bundle; D-004 and D-014 exact-commit review/evidence requirements
- Exact condition: agy launches but either ignores the no-tools boundary and times out, or reports `Individual quota reached`; no valid Gemini payload has been returned for candidate `9feb4ee68d91c8e2936459228d31082c50b2655e`.
- Why work cannot complete safely: FWQ-0008 requires an independent exact-commit Gemini review; provider output cannot be fabricated or replaced by Claude evidence.
- Required resource: a functioning Gemini/agy review capacity bound to the exact candidate.
- Independent READY work: FWQ-0009 audit-event integrity reader.
- Current candidate/checkpoint: `9feb4ee68d91c8e2936459228d31082c50b2655e` / FWQ-0008.
- First resume action: obtain a valid Gemini payload for the exact candidate, validate its job ID and SHA, then resume FWQ-0008 acceptance.

## Resolved blockers

### B-001 — Required exact-commit review resources failed closed (resolved)

- Related task/requirement: FWQ-0006 — Supervisor continuation loop; D-004 and D-014 exact-commit review/evidence requirements
- Resolution: Jeff supplied a complete manual Gemini payload. It validates against `schemas/gemini-review.schema.json` and the repository exact-SHA contract for candidate `514217e474e46872c12efdad181d11ae90bfe57e`; it is preserved in `docs/fwq-0006-gemini-manual-review-514217e.json`. The automated adapter remained unavailable and was not used as success evidence.

## What is not a blocker

The following do not justify stopping the swarm:

- a failing test;
- a reviewer finding;
- a need to refactor;
- a failed implementation approach;
- documentation that can be resolved from repository evidence;
- completion of the current task;
- the next task being difficult;
- ordinary model disagreement.

When these occur, investigate, repair, revalidate, or move to another independent READY task.

## Blocker record format

When a genuine blocker exists, record:

- Blocker ID
- Related task/requirement
- Exact condition
- Why work cannot continue safely
- What authority/resource/decision is required
- Independent READY work still available, if any
- Current commit/checkpoint
- First action to resume after resolution

Do not convert uncertainty into permission. If the issue is an authority boundary, fail closed and record it here.
