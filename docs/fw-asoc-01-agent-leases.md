# FW-ASOC-01 — Agent identity and bounded capability leases

This implementation adds a narrow authorization boundary to ForgeWarden Core.
It does not create a second identity or authorization service.

## Reused architecture

- `swarm.policy_gate.validate_safety_evidence` remains the safety invariant
  validator for dry-run, disabled deployment, and kill-switch state.
- `CapabilityAuthorizer` now accepts a safety-evidence provider and routes every
  decision through that canonical validator before checking agent authority;
  the default provider derives only the current local safety state.
- `audit_log_sink` binds the module's audit sink directly to the existing
  `AuditLog` and a ForgeWarden `Job`; authorization results are therefore
  written as canonical durable Evidence records without a second audit format.
- Existing FW-ID/FW-ROOT/FW-KEYS concepts are represented by the explicit
  `cryptographic_identity_ref` and `key_reference` handles. Secret key material
  is supplied to `HMACLeaseSigner` and is never stored in an identity or lease.
- Existing Model Broker and MCP Gateway integrations can pass exact model
  bindings and MCP tool names into the canonical `CapabilityAuthorizer`.
- Action Tickets remain an upstream approval artifact. The authorizer requires
  a validated ticket result for mutating action classes; it does not mint or
  replace Action Tickets.

## New interfaces

`swarm.asoc` provides `AgentIdentity`, `ModelBinding`, `CapabilityLease`,
`AgentRegistry`, `LeaseRegistry`, `CapabilityAuthorizer`, `ASOCControlPlane`,
and `AuthorizationRequest`.

There is no database migration. The first endpoint is an in-memory, explicitly
constructed boundary so callers can attach the existing durable registries and
Evidence/AuditLog implementation without duplicating persistence.

Roles are policy inputs only. Capabilities are an allow-list of narrow names;
wildcards and broad privilege names are rejected. Resources and MCP tools are
exactly scoped. Model/provider/deployment/version and policy version must match.

## Security invariants

Every decision checks active agent state, tenant, signature, lease validity,
revocation, capability, resource, data classification, action class, blast
radius, tool, policy version, model binding, Action Ticket requirement, and
current kill-switch state. Expiry is checked from the current clock, so cleanup
jobs are not required. Revocation is checked on the next decision.

The kill switch blocks new lease issuance and mutating authorization while
allowing already-valid analytical reads according to policy. The control plane
can revoke one agent, a role, model deployment, tenant, or all AI leases.

## Deliberate limits

The current endpoint does not implement multi-agent delegation, persistent
lease storage, asymmetric signatures, or a full external Z3 solver adapter.
`delegation_allowed` and `delegation_depth` are present for safe future
extension, but no child lease issuance path exists yet. A caller must connect
the existing signed Action Ticket and Model Broker records before using a
mutating capability.

Next approved target after a meaningful review is FW-ASOC-02 — Action Risk
Classes & Blast-Radius Accounting.
