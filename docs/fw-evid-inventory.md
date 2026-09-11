# FW-EVID inventory and canonical envelope

FW-EVID owns the common Evidence envelope, lifecycle integrity, chain of custody, retention, and future export interfaces. Domain producers retain ownership of their payload schemas. This prevents a second audit system from replacing working controls.

## Existing capabilities

| Producer or component | Current responsibility | Reused boundary | Gap after FW-EVID-001 |
|---|---|---|---|
| `swarm.core.AuditLog` | Private append-only local JSONL writes with redaction and locking | Local audit writer | Does not yet emit the canonical envelope or a mandatory hash chain |
| `swarm.audit_integrity` | Bounded read-only audit validation and optional hash-chain verification | Integrity reader | Legacy event shapes remain supported; canonical migration is later work |
| `swarm.harness_evidence` | Exact tenant/task/worker/test/review lifecycle payload | Harness payload owner | Must later wrap its payload digest in the canonical envelope |
| `swarm.accepted_work_evidence` | Exact-commit acceptance, review binding, hashes, and create-once private file | Accepted-work payload owner | Its older reviewer fields and chain are not replaced in this milestone |
| `swarm.review_evidence` and phase schemas | Bounded review and release evidence | Domain payload owners | Require gradual adapters rather than schema replacement |
| `NormalizedEventStore`, FW-SOC, FW-ID, FW-KEYS, FW-AV, FW-ENDPOINT | Evidence-first domain events | Domain fact owners | Must adopt the envelope through bounded consumer milestones |

## Canonical contract

`swarm.evidence.EvidenceEnvelope` is immutable metadata. It binds an exact tenant, event, actor, subject, canonical UTC timestamp, data classification, payload schema identifier, payload SHA-256, optional previous-record hash, tenant-bound correlation identifier, and sorted tenant-bound Evidence references. It contains no raw payload and grants no storage, append, signing, export, policy, approval, Action Ticket, Git, deployment, containment, recovery, or response authority.

FW-EVID-006 proves the local canonical lifecycle from validated domain payload digest through tenant-chain admission, private AuditLog durability, restart reconstruction, and replay/tamper denial. Existing evidence formats remain authoritative for their accepted historical records. The Proven boundary is local, unsigned, DRY_RUN Evidence; retention execution, cryptographic signing, replication, external storage, and export remain separate governed capabilities.
