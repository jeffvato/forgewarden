# FW-INTEGRITY Product Functionality Map

The authoritative machine-readable map is swarm.integrity.FUNCTIONALITY_MAP.
Every row describes the currently accepted bounded DRY_RUN capability. Proven
means its declared local scope has recorded implementation, integration, tests,
and exact review; it does not mean the feature is live or production-ready.

| Requirement | Proof | Implementation | Integration | Demo | Operating mode | Live | Production ready | Main limitation |
|---|---|---|---|---:|---|---:|---:|---|
| FW-CORE | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No production deployment or live mutation |
| FW-ASOC | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | In-memory single-process DRY_RUN registries; no full external orchestration or Z3 solver |
| FW-ID | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | In-memory metadata only; no live authentication, federation, OAuth exchange, or device trust |
| FW-KEYS | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No vault/HSM backend, material resolution, signing, encryption, or live credentials |
| FW-EVID | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | Local unsigned Evidence; no external storage, replication, cryptographic signing, or export |
| FW-REC | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | Metadata coordination only; no restore, rollback, restart, repair, or recovery execution |
| FW-COMP | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No certification, attestation, external reporting, or control execution |
| FW-HARNESS | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | YES | DRY_RUN | NO | NO | Bounded local engineering harness; provider invocations remain adapter-controlled and deployment disabled |
| FW-AID | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | YES | DRY_RUN | NO | NO | Caller-supplied metadata only; no live sensor, enforcement, containment, or recovery execution |
| FW-API | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No listener, remote transport, response handler, authentication exchange, or mutation API |
| FW-MCP | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No arbitrary tool execution, live discovery, credential resolution, or external MCP transport |
| FW-UX | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | YES | DRY_RUN | NO | NO | Loopback read-only console; most operational scenario data remains clearly labeled DEMO |
| FW-SOC | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | YES | DRY_RUN | NO | NO | Caller-supplied metadata only; no live SIEM ingestion, case service, or response execution |
| FW-ENDPOINT | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No installed MicroSensor, platform hook, live collection, process control, or endpoint response |
| FW-RANSOM | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | YES | DRY_RUN | NO | NO | No live filesystem sensor, isolation, snapshot, rollback, or remediation execution |
| FW-BME | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No browser extension, mail transport, content retrieval, account action, or network enforcement |
| FW-SAAS | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No SaaS discovery, provider API, OAuth exchange, mutation, or response execution |
| FW-SUPPLY | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No repository scanner, package retrieval, CI/CD integration, signing, or deployment enforcement |
| FW-NET | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No packet/DNS sensor, socket, NAC, firewall change, containment, or network response |
| FW-ASM | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No discovery, DNS resolution, scan, cloud query, exploit, takedown, or remediation |
| FW-DSPM | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No content discovery, inspection, query, data movement, DLP enforcement, or remediation |
| FW-GOV | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | No provider invocation, sovereign infrastructure, ATO/certification, credential resolution, or deployment |
| FW-OPS | Proven / ACCEPTED_BOUNDED | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | Caller-supplied local metadata; no live telemetry, HA/DR control, retention movement, or service operation |
| FW-INTEGRITY | Implemented / CURRENT_REPOSITORY_VALIDATION | IMPLEMENTED | INTEGRATED | NO | DRY_RUN | NO | NO | Current proof is repository-local; clean packaging, mutation testing, and broader production-like execution remain |

FW-INTEGRITY-003 reconciles accepted task records with surviving source, tests,
Evidence references, and Git commits. FW-INTEGRITY-004 requires all 22 accepted
requirement families to appear exactly once in this map; FW-ASOC and FW-CORE
remain additional foundational records. Missing, duplicate, malformed, live-enabled,
or production-ready claims fail the Product Integrity gate.

The map remains conservative. No row authorizes deployment, live collection,
credential resolution, containment, remediation, recovery execution, or any
other product mutation. Current execution proof and production-like behavior
are separate future Golden Path and operational-readiness milestones.
