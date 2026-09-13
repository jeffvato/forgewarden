# FW-API bounded architecture

FW-API is the versioned least-privilege interface family. Its first accepted
scope is a local caller-supplied read-only admission contract. It reuses FW-ID,
the deterministic policy owner, canonical capability leases, and FW-EVID. It
does not create an identity provider, policy engine, lease issuer, Action Ticket
owner, Evidence store, listener, transport, credential resolver, or handler.

`APIReadAdmissionRegistry` validates an immutable version-1 request, active
tenant-bound identity, exact deterministic allow rule, signed active lease, data
classification, current engaged kill switch, and disabled deployment. Evidence
must succeed and return a same-tenant canonical reference before an immutable
admission is retained. Replay and concurrent duplicate admission fail closed.

This milestone admits metadata only. No response body is produced and no
handler, model, MCP tool, filesystem/process operation, network request,
response/recovery action, Git operation, or deployment is invoked. Mutation
requests are rejected by the request contract; later mutation design must use
the existing signed single-use Action Ticket owner and requires a separately
authorized milestone.
