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
- `swarm.model_broker.ModelBroker` and `swarm.mcp_gateway.MCPGateway` are the
  canonical exact-match approval and tool-grant boundaries consumed by
  `CapabilityAuthorizer`; their grants are tenant- and agent-bound and are
  revoked with ASOC recovery actions.
- `swarm.action_ticket` is the canonical signed, tenant-bound, short-lived,
  single-use Action Ticket implementation. For mutating actions,
  `CapabilityAuthorizer` can consume a ticket only when it exactly matches the
  agent, lease, tenant, capability, resource, action class, and policy version.
  A caller-provided boolean remains insufficient authority.

## New interfaces

`swarm.asoc` provides `AgentIdentity`, `ModelBinding`, `CapabilityLease`,
`AgentRegistry`, `LeaseRegistry`, `CapabilityAuthorizer`, `ASOCControlPlane`,
and `AuthorizationRequest`. `swarm.action_ticket` provides `ActionTicket` and
`ActionTicketRegistry`; `swarm.model_broker` provides `ApprovedModel` and
`ModelBroker`; and `swarm.mcp_gateway` provides `MCPToolGrant` and `MCPGateway`.

There is no database migration. The first endpoint is an in-memory, explicitly
constructed boundary so callers can attach the existing durable registries and
Evidence/AuditLog implementation without duplicating persistence.

Roles are policy inputs only. Capabilities are an allow-list of narrow names;
wildcards and broad privilege names are rejected. Resources, MCP tools, and
action classes are exactly scoped to supported allow-lists. Model/provider/deployment/version and policy version must match;
the identity's provider/deployment reference must also match its exact approved
model binding, including the model approval version.

## Security invariants

Every decision checks active agent state, tenant, signature, lease validity,
revocation, capability, resource, data classification, action class, blast
radius, tool, policy version, model binding, Action Ticket requirement, and
current kill-switch state. Agent and lease expiry are checked from the current
clock, so cleanup jobs are not required. Revocation is checked on the next
decision.

An authorization success is returned only after its canonical Evidence/audit
write succeeds. If that write fails, the request receives the bounded
`EVIDENCE_WRITE_FAILED` denial and no authority result is returned.
If a best-effort diagnostic audit write fails while the request is already being
denied, ForgeWarden still returns the original bounded denial rather than a raw
writer error.

The kill switch blocks new lease issuance and mutating authorization while
allowing already-valid analytical reads according to policy. The control plane
can revoke one agent, a role, model deployment, tenant, or all AI leases. An
AI kill-switch event revokes only model-bound agent identities and their leases;
unbound human deterministic-administration identities remain available.
Model-deployment revocation resolves the deployment through the canonical agent
identity binding before revoking its leases; it never compares a deployment to
an unrelated key reference.

## Deliberate limits

The current endpoint does not implement multi-agent delegation, persistent
lease storage, asymmetric signatures, or a full external Z3 solver adapter.
`delegation_allowed` and `delegation_depth` are present for safe future
extension, but no child lease issuance path exists yet. Non-delegable leases
must carry a depth of zero. The Model Broker and MCP Gateway are integrated;
the remaining policy limit is a full external Z3 solver adapter.

Next approved target after a meaningful review is FW-ASOC-02 — Action Risk
Classes & Blast-Radius Accounting.
