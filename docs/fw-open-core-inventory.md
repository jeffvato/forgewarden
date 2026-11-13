# ForgeWarden Open-Core Inventory

Status: preliminary repository inventory for FW-OPENCORE-001
Branch: architecture/open-core-boundary
Base: 21329cbd964fbda820ad4d6526a452c13972d64e

## Immediate findings

1. GitHub reports no detected repository license.
2. The repository tree contains no root LICENSE, COPYING, or NOTICE file.
3. Therefore the repository is publicly readable, but should not be described as a legally established open-source distribution until a license is deliberately selected and added.
4. Current Python dependency manifests are limited to `requirements-test.txt` and `requirements-vulnerability-job.txt`; no pyproject/Poetry/Cargo/Go/package manifests were found in the current tree.
5. Existing CI already rejects tracked private-key blocks and common runtime/secret artifacts on pull requests.
6. The current architecture already contains canonical Action Ticket, deterministic policy, identity, Evidence, Model Broker, MCP Gateway, recovery, and harness owners. The migration should split interfaces from privileged implementations rather than recreate them.

## Current dependency manifests

### requirements-test.txt

| Package | Version constraint | Current role | Open-core disposition |
| --- | --- | --- | --- |
| jsonschema | 4.10.3 | deterministic tests/schema validation | THIRD_PARTY / LICENSE_REVIEW |
| cryptography | 41.0.7 | crypto primitives/tests | THIRD_PARTY / LICENSE_REVIEW |
| psutil | 5.9.8 | resource/performance validation | THIRD_PARTY / LICENSE_REVIEW |
| pytest | 7.4.4 | tests | THIRD_PARTY / LICENSE_REVIEW |
| PyYAML | 6.0.1 | YAML parsing/tests | THIRD_PARTY / LICENSE_REVIEW |
| tzdata | 2024.1 | timezone data | THIRD_PARTY / LICENSE_REVIEW |

### requirements-vulnerability-job.txt

| Package | Version constraint | Current role | Open-core disposition |
| --- | --- | --- | --- |
| azure-identity | >=1.17,<2 | Azure workload identity | THIRD_PARTY / LICENSE_REVIEW |
| azure-storage-blob | >=12.20,<13 | vulnerability intelligence storage | THIRD_PARTY / LICENSE_REVIEW |

The exact upstream licenses and redistribution/notice obligations must be verified from authoritative package metadata before any commercial/private redistribution decision. This document intentionally does not infer license terms from memory.

## Container/build inventory

- `Dockerfile.console`: packages the management console and copies `config`, `console`, `schemas`, and the complete `swarm` package into the image.
- `Dockerfile.vulnerability-job`: installs Azure dependencies and copies the complete repository into the image.

Both Dockerfiles currently package broad source surfaces. A later migration must ensure proprietary production images are built from private Core sources without requiring the public repository to contain those implementations.

## Preliminary module classification

This is a migration classification, not a relicensing declaration.

### PUBLIC candidates

These are interfaces, edge components, SDK/integration surfaces, schemas, fixtures, or client-side verification candidates.

- `addon_sdk.py`
- `addon_catalog.py`
- `adapters.py` where limited to public integration contracts
- `api_contract.py` public request/schema portions
- `sensor_adapter.py`
- `normalized_events.py`
- platform fixture adapters such as `android_fixtures.py`, `endpoint_fixtures.py`, and `macos_fixtures.py`
- `open_core_boundary.py`
- public schemas under `schemas/`
- selected packaging/examples/documentation

### PRIVATE candidates

These contain or are expected to contain high-value decision, orchestration, authority, commercial-security, or control-plane behavior.

- `model_broker.py`
- `ai_agent_defense.py`
- `anti_malware.py` proprietary detection/decision portions
- `ransomware.py` proprietary decision/recovery orchestration portions
- `autonomous_loop.py`
- `harness_controller.py`
- `harness_authority.py`
- `high_assurance.py`
- `mission_control.py` backend/control-plane portions
- `soc.py` orchestration/correlation portions
- `asoc.py` orchestration/authorization portions
- `data_security.py` proprietary risk/correlation portions
- `attack_surface.py` proprietary scoring/correlation portions
- `browser_email.py` proprietary decision portions
- `saas_security.py` proprietary decision portions
- `network_security.py` proprietary decision portions

### SPLIT candidates

These currently mix public protocol/value objects with privileged issuance, policy, signing, or authority logic.

| Module | Public side | Private side |
| --- | --- | --- |
| `action_ticket.py` | ActionTicket schema/canonical serialization and verification contract | ticket registry, issuance, revocation/consumption authority |
| `policy_gate.py` | safety-state constants and public compatibility contract where needed | deterministic authorization rules/evaluation and protected policy data |
| `asoc.py` | lease/action schemas and client verification interfaces where needed | lease issuance, orchestration, private signer/key binding and authorization |
| `identity.py` | public identity identifiers/schema portions | authoritative registry/lifecycle/trust decisions |
| `keys.py` | key-reference formats and verification interfaces | key material, rotation, HSM/secret resolution, signing authority |
| `evidence.py` | evidence reference/envelope formats | canonical append/sign/verification authority and retention controls |
| `recovery.py` | recovery request/status schema | recovery authorization and destructive/rollback control |
| `mcp_gateway.py` | capability descriptions/client protocol | authorization, allow-list policy, credential isolation and kill-switch control |
| `api_contract.py` | versioned API request/response schemas | privileged admission handlers and private service implementation |

## First implemented vertical slice

The first boundary slice is deliberately public-side only:

`SignedActionEnvelope -> PublicActionVerifier -> PublicActionAdmission`

Properties:

- outer envelope must be signed by the configured trusted private-Core authority;
- public verification must use verification-only asymmetric trust anchors; the public component must not possess HMAC/shared signing secrets or private signing keys;
- embedded canonical Action Ticket must independently verify;
- authority and signing-key references are pinned by the public verifier configuration;
- tenant, subject/agent, lease, capability, resource, action class, and policy version must exactly match;
- ticket lifetime is checked deterministically;
- consumed tickets are rejected;
- action IDs and ticket IDs are consumed through an injected atomic replay-store contract; production storage must persist across restarts and coordinate concurrent verifier instances;
- ticket lifetime is evaluated against an injected trusted clock rather than request-supplied time;
- current ForgeWarden safety invariants are rechecked;
- successful admission still returns `execution_permitted=False` because DRY_RUN and deployment-disabled safety remain mandatory.

This proves the public edge cannot manufacture its own privileged action merely by constructing JSON or changing metadata.

## Current-tree secret controls

The pull-request validation workflow currently checks for:

- tracked `.env` files;
- PEM/key/P12 artifacts;
- SQLite/runtime/log/jsonl artifacts;
- Python cache/test cache artifacts;
- tracked private-key blocks.

This is useful current-tree coverage but is not a complete Git-history secret audit. Full history scanning remains required before any public/private repository split.

## Required next inventory work

1. Verify authoritative upstream licenses for every direct and transitive dependency.
2. Generate an SBOM from an environment that can install/query dependencies.
3. Run Git-history secret scanning from a full clone with network/history access.
4. Map import dependencies for every PRIVATE/SPLIT candidate.
5. Identify the minimum protocol package that public agents require.
6. Split schema/verification code from issuance/decision implementations without changing canonical wire formats.
7. Design private image/repository build paths for SaaS, enterprise, and air-gapped deployment.

## Decision gate

Before calling ForgeWarden an open-source project, Customer Root must deliberately select the public license strategy. No license choice is inferred by this inventory.
