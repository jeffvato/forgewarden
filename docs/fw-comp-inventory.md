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
