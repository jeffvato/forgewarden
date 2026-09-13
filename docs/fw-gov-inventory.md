# FW-GOV-001 — High-assurance ownership inventory

## Existing canonical controls

FW-GOV composes existing ForgeWarden trust owners. It does not create a second
model registry, router, identity system, policy engine, evidence store, or
deployment controller.

| Concern | Existing owner and boundary |
| --- | --- |
| Model authorization and eligibility | `swarm.harness_models` Approved Model Registry admission and deterministic routing metadata |
| Assurance tier | `swarm.harness_risk.AssuranceTier`; T4 and human-required decisions do not route a model |
| Tenant, role, data, tool, and environment scope | Harness model admission, FW-ID, FW-ASOC leases, and API contract |
| Provider failure | Deterministic routing selects only an approved same-or-higher eligible equivalent and otherwise fails closed |
| Model invocation | FW-HARNESS worker boundary; a model route never grants invocation or deployment authority |
| Policy and approval | Deterministic policy/Z3 boundary, leases, and signed Action Tickets |
| Audit and chronology | FW-EVID canonical records and exact registry Evidence references |
| Operator visibility | Mission Control read-only model and Harness projections |
| Offline/sovereign operation | Existing local CLI and deterministic interfaces permit no-provider operation; infrastructure remains planned |

Existing tests already prove no opaque router decision, no T4 self-routing, no
assurance downgrade, no silent fallback, exact tenant/environment/data/tool
scope, and fail-closed behavior when no approved model is available.

## First missing boundary

The repository does not yet have one canonical immutable FW-GOV authorization
profile that binds a tenant, security boundary, environment, data classes,
assurance tier, authorization status, ATO reference, FedRAMP state, DoD impact
level, sovereign/offline constraints, validity window, and Evidence reference.

`FW-GOV-002` will add that caller-supplied metadata contract. An authorization
profile is an input to deterministic admission. It is not an ATO, FedRAMP or
DoD authorization, does not certify compliance, and grants no provider access,
credential, invocation, deployment, or authority.

## Incremental route

1. `FW-GOV-002`: immutable tenant-bound high-assurance authorization profile.
2. `FW-GOV-003`: deterministic profile and Approved Model Candidate admission.
3. `FW-GOV-004`: approved-equivalent failover plus sovereign/offline fail-closed decisions.
4. `FW-GOV-005`: canonical Evidence binding and Mission Control projection.
5. `FW-GOV-006`: integrated high-assurance lifecycle and adversarial proof.

Each ID is a substantive gated milestone. No placeholder successor is created.

## Authority boundary

FW-GOV initially evaluates caller-supplied metadata only. It does not contact a
provider, resolve credentials, create sovereign infrastructure, activate an
air-gapped deployment, issue an authorization, claim ATO/FedRAMP/DoD status,
invoke a model, change policy, approve a task, enable deployment, clear the kill
switch, or expand authority. Missing or mismatched authorization fails closed.
