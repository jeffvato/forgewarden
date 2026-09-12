# FW-COMP ownership inventory

FW-COMP maps existing ForgeWarden controls to external framework references. It
does not own requirements, policy decisions, Evidence, tenant identity,
approvals, tests, implementation status, certification, or control execution.

| Fact | Canonical owner |
|---|---|
| Requirement identity and lifecycle | `WORK_QUEUE.md`, `ROADMAP.md` |
| Internal control identity | ForgeWarden Control Registry roadmap boundary |
| Tenant and actor identity | FW-ID |
| Policy decision and authority | FW-ROOT/Z3, Action Tickets, leases |
| Evidence and provenance | FW-EVID |
| Test and integrity status | FW-TEST, FW-INTEGRITY |
| Product implementation status | FW-INTEGRITY functionality map |
| Framework references | FW-COMP mapping metadata |
| Certification or attestation | external authorized assessor; not ForgeWarden mapping metadata |

`ControlMapping` is immutable, tenant-bound, Evidence-referenced descriptive
metadata. Supported initial reference namespaces are NIST CSF 2.0, NIST 800-53,
and CIS Controls v8. `MAPPING_ONLY` is the sole claim status. A mapping cannot
certify a tenant, execute a control, change policy, or grant authority.

## Canonical Evidence admission

`ComplianceEvidenceAdapter` resolves an exact create-once mapping from the
canonical registry, hashes every mapping field, and admits only that digest and
the mapping's bounded existing Evidence references to the canonical tenant
`EvidenceLedger`. The ledger remains the sole durability, replay, and chain
authority. Missing, substituted, cross-tenant, duplicate, stale-chain, invalid,
and durability-failed admission fails closed without advancing mapping or
Evidence state. Admission records that the mapping exists; it does not certify
the control or authorize an operation.

## Assessment observations

`ControlAssessmentObservation` records a bounded point-in-time result against an
exact registered mapping digest. Observations require same-tenant canonical
Evidence plus policy/test fact references, an FW-ID assessor, and finite expiry.
The create-once Evidence-first registry rejects substitution, replay, expiration,
cross-tenant facts, and durability failure. Outcomes remain `OBSERVATION_ONLY`;
they cannot change mapping status, policy, tests, Evidence, or authority and do
not represent certification or continuous compliance.

## Integrated lifecycle proof

The tested FW-COMP lifecycle composes one canonical mapping registry, the
canonical FW-EVID ledger adapter, and the assessment registry. Exact mapping
digests and tenant/control/Evidence bindings survive end to end; duplicate,
replay, substitution, cross-tenant, expiry, and durability failures leave
protected state unchanged. Product Integrity reports this narrow metadata-only
DRY_RUN lifecycle as Proven while explicitly excluding certification,
attestation, external reporting, control execution, and continuous compliance.
