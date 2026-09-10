# FW-ID canonical identity inventory

FW-ID owns identity facts and lifecycle state. It does not own permissions,
capability leases, policy decisions, Action Tickets, model approval, secret
material, Evidence, Git, tool execution, or deployment.

## Existing consumers

| Consumer | Existing identity use | Canonical boundary |
|---|---|---|
| `swarm.asoc.AgentIdentity` | Agent, tenant, owner, model and cryptographic identity references | Consume an FW-ID identity reference; FW-ASOC continues to own roles, leases and authorization. |
| `swarm.harness_worker.WorkerRegistration` | Worker, provider, model and role metadata | Bind a worker to FW-ID later; the harness continues to own invocation admission. |
| `swarm.model_broker.ModelBroker` | Provider/model/deployment approval identity | Model Broker retains model approval; FW-ID identifies the invoking actor. |
| `swarm.action_ticket.ActionTicketRegistry` | Subject and approver references | Action Tickets retain action authority; FW-ID only validates referenced actors. |
| `swarm.mcp_gateway.MCPGateway` | Tenant and agent request binding | MCP Gateway retains tool admission and mediation. |
| `swarm.approval` | Approver identity references | Approval remains a separate deterministic authority record. |
| `swarm.harness_evidence` and `swarm.core.AuditLog` | Actor/provider labels in Evidence | FW-EVID remains the record owner and stores only identity references. |

## FW-ID-001 contract

`swarm.identity.IdentityRecord` is the canonical immutable identity metadata
contract. Stable `fw-id/...` references bind identity kind, tenant, owner,
purpose, lifecycle timestamps, an optional opaque provider-subject reference,
and an optional `fwkeys://...` handle. Exact schemas and bounded values reject
unknown fields, credential-like material, malformed owners, unsupported kinds,
and invalid lifecycle timestamps.

The contract performs no registration, authentication, OAuth exchange,
credential resolution, permission grant, persistence, network call, or action.
Those behaviors belong to later bounded milestones and their canonical owners.
