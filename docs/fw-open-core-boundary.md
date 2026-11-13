# ForgeWarden Open-Core / Proprietary-Core Boundary

Status: proposed architecture migration
Authority: explicitly requested by Jeff / Customer Root on 2026-11-12
Base commit: 21329cbd964fbda820ad4d6526a452c13972d64e
Safety posture: DRY_RUN preserved; deployment disabled; kill switch unchanged.

## Goal

ForgeWarden should remain open and extensible at its edges while the authority, intelligence, decision-making, security orchestration, licensing, and commercial platform capabilities remain proprietary assets.

A public clone must be useful for integrations, schemas, SDKs, agents, examples, and verification, but must not be equivalent to the commercial ForgeWarden platform.

This is not a hidden-file design. Privileged operations must require cryptographically authorized responses from the proprietary Core.

## Architectural split

### Public / open-core candidates

- endpoint agent framework
- MicroSensor framework
- telemetry collectors and normalized event formats
- public API schemas and clients
- SDK
- MCP interfaces/adapters
- integration adapters and plugin interfaces
- deployment examples and developer tooling
- public CLI surface
- client-side signature verification
- safe example policies and example detection rules

### Private / proprietary-core candidates

- Z3 Policy Engine internals
- Action Broker
- decision engine
- detection/correlation engine
- AI intrusion-defense decision logic
- RansomGuard decision and recovery orchestration
- Model Broker internals and Approved Model Registry internals
- policy compilation/evaluation internals
- tenant/root authority services
- authorization and lease issuance
- licensing/entitlement service
- Evidence signing/verification authority
- Recovery authorization
- proprietary threat-intelligence correlation
- risk-scoring algorithms
- SOAR/playbook execution
- proprietary behavioral models and commercial rule packs
- cloud-side MCP authorization
- control-plane and Mission Control backend
- production signing/PKI orchestration

## Trust boundary

Target flow:

1. Endpoint/integration detects or collects.
2. Public component normalizes and signs telemetry.
3. Private Core evaluates policy/detection/decision state.
4. Action Broker produces a bounded action authorization.
5. Private authority signs the action.
6. Public agent validates the signature and all bindings.
7. Agent executes only if every deterministic check passes.

The public agent must reject privileged actions that are unsigned, incorrectly signed, expired, replayed, malformed, from an unknown authority, for another tenant/device, outside scope, outside lease, outside capability, or beyond blast-radius limits.

## Signed action requirements

Prefer the canonical ForgeWarden action/ticket structures if they already exist. Any boundary object must bind at minimum:

- schema/version
- action ID
- tenant ID
- device/workload identity
- policy ID/version/hash
- requested action and bounded parameters
- issue/expiry timestamps
- lease/ticket identity
- scope/capabilities
- blast-radius constraints
- nonce/replay protection
- authority identity
- signature algorithm
- signature

Do not invent new cryptography. Reuse FW-ROOT, FW-ID, FW-KEYS, Action Tickets, Evidence, and existing canonical identity/policy contracts.

## Deployment modes

The boundary must support:

- SaaS / ForgeWarden Cloud Core
- enterprise/hybrid self-hosted Core
- government/sovereign Core
- fully air-gapped Core

Self-hosted proprietary Core may eventually ship as signed binaries or signed container images without distributing source. Internet connectivity must not become a permanent runtime requirement. Offline signed entitlements must remain possible.

## Licensing and entitlement

Commercial entitlement and security authority are separate.

Licensing controls what the customer is entitled to run.
Cryptographic authority controls what privileged operations may execute.

The entitlement model should bind:

- tenant
- deployment ID
- deployment mode
- enabled capabilities/features
- issue/expiry/renewal metadata
- signing chain

Do not make licensing the sole security boundary.

## Required license audit before code migration

Inventory repository and dependency licenses before moving or relicensing code. Pay particular attention to GPL, AGPL, LGPL, SSPL, BUSL/BSL, Commons Clause, source-available, and dual-licensed components.

Produce machine-readable and human-readable records for:

- component/package/version
- origin
- license
- modification status
- linked/embedded/network-only status
- redistribution/source/notice obligations
- patent clauses
- copyleft risk
- recommended classification

Classifications:

- PUBLIC
- PRIVATE
- THIRD_PARTY
- REPLACE
- LICENSE_REVIEW

Generate SPDX or CycloneDX SBOM evidence if existing tooling permits.

## Secret and history audit

Before changing visibility boundaries, scan the working tree and Git history for keys, tokens, passwords, certificates, client secrets, cloud credentials, database credentials, signing keys, and usable test credentials.

If found: record, rotate, assess history exposure, and recommend history cleanup. Never print secret values into reports.

## API boundary

Prefer existing canonical endpoints. Where a new protocol seam is required, it must provide:

- explicit schema versioning
- tenant binding
- device/workload identity
- authentication and authorization
- replay protection
- request/correlation IDs
- structured errors
- audit events
- deterministic behavior
- rate/resource limits
- capability negotiation
- compatibility/version checks

Strong workload identity should prefer mTLS, short-lived certificates, rotation/revocation, signed telemetry, and signed actions. API keys must not become the sole authority mechanism.

## Offline behavior

Classify actions as:

- LOCAL_SAFE_ACTION
- CACHED_POLICY_ACTION
- CORE_REQUIRED_ACTION
- HUMAN_REQUIRED_ACTION
- DENIED_WHEN_OFFLINE

Cached authority must be signed, bounded, tenant/device scoped where required, versioned, expiring, auditable, and fail closed.

## MCP boundary

Public MCP integrations may describe capabilities, but only the private Core may authorize them. Preserve Gateway allow-lists, identity/tenant/capability policy, leases, replay protection, rate/resource limits, Evidence, and kill switch. Tool metadata must never self-expand privileges.

## Model boundary

Public components may submit structured model tasks. The private Model Broker owns deterministic approved-model selection, provider/deployment binding, data-release policy, fallback, timeout, cost ceiling, and assurance restrictions. Provider credentials remain private.

## Evidence boundary

Public agents may emit hashes and signed telemetry. The private Evidence authority owns canonical evidence chains, signing/verification authority, correlation, retention metadata, and tamper detection.

## Required migration sequence

Do not rewrite the product in one pass.

Phase 1:
1. inventory modules and dependencies;
2. map current authority flows;
3. classify public/private/third-party/license-review;
4. perform license and secret audits;
5. identify direct calls crossing the intended boundary;
6. define versioned service/API contracts;
7. select one vertical slice;
8. implement the smallest safe slice;
9. add fail-closed tests;
10. run focused tests, full validation, Product Integrity, and exact-commit review.

Preferred first vertical slice:

Telemetry -> private policy/decision service -> signed action envelope -> public agent signature/binding verification -> execution or rejection.

Choose a different slice only if repository analysis proves it is safer and smaller.

## Mandatory boundary tests

At minimum:

- unsigned action rejected
- invalid signature rejected
- expired action rejected
- wrong tenant rejected
- wrong device rejected
- replay rejected
- invalid/expired lease rejected
- unknown authority rejected
- malformed action rejected
- unauthorized capability rejected
- blast-radius violation rejected
- policy-version mismatch handled safely
- Core unavailable behavior fails safely
- cached authority expires correctly
- kill switch prevents prohibited execution
- valid authorized operation still succeeds

## Non-goals / prohibitions

Do not:

- invent cryptography
- hardcode secrets
- weaken tenant isolation
- bypass Z3/Action Tickets
- expose private signing keys
- silently relicense third-party code
- delete required notices
- break air-gapped operation
- add a permanent phone-home dependency
- allow agents to self-authorize
- allow clients/MCP tools to choose or expand authority
- allow unsigned privileged actions
- treat licensing as authority
- activate deployment or clear the kill switch

## Codex execution contract

Codex remains the sole application-code writer. Start by inspecting actual source and tests, not by assuming the conceptual module names already exist. Reuse canonical owners rather than creating duplicate subsystems.

The first implementation commit must be a bounded, reviewable vertical slice with direct negative tests. Do not move large portions of the repository until the license inventory and dependency map are complete.

Completion requires:
- deterministic focused tests
- applicable full suite
- Product Integrity Gate
- exact-commit independent read-only review under the currently authorized reviewer policy
- updated persistent project state
- no unresolved critical/high-confidence findings
