# FW-KEYS canonical secret-handle inventory

FW-KEYS owns opaque secret-handle metadata and, in later approved milestones,
its deterministic lifecycle. It does not own identity, policy, roles,
capabilities, approvals, Action Tickets, model registration, Evidence, Git,
deployment, or response execution. Secret material remains outside ForgeWarden
task state, prompts, logs, review material, and Evidence.

## Existing consumers and owners

| Consumer | Existing use | Canonical boundary |
|---|---|---|
| `swarm.identity.IdentityRecord` and `DelegatedProviderIdentity` | Tenant-bound opaque provider credential references | FW-ID owns actor/provider binding; it consumes a validated FW-KEYS handle. |
| `swarm.harness_credentials.CredentialRecord` | Approved provider profile and opaque handle admission | FW-HARNESS owns invocation admission; a trusted adapter may eventually resolve only an admitted handle. |
| `swarm.harness_worker.WorkerInvocationPlan` | Carries an admitted opaque API handle to the trusted adapter | Worker plans do not resolve or reveal material and gain no credential authority. |
| `swarm.asoc.HMACLeaseSigner` | In-memory test and lease signing key material | FW-ASOC retains lease semantics; replacing fixture material with a FW-KEYS signing interface is later work. |
| `swarm.action_ticket.ActionTicketRegistry` | Consumes the FW-ASOC signer for ticket authenticity | Action Tickets retain authorization and replay control; FW-KEYS never grants action authority. |
| `swarm.addon_catalog.TrustedSignatureCatalog` and anti-malware catalogs | Trusted signer/key identifiers and signature verification | Catalog owners retain definition admission and verification policy; FW-KEYS owns future key lifecycle references only. |
| `swarm.core.AuditLog`, `swarm.harness_evidence`, and review evidence | Records actor, decision, and lifecycle references | FW-EVID owns evidence. Secret material and resolvable backend locators are forbidden. |

## FW-KEYS-001 contract

`swarm.keys.SecretHandleRecord` is the canonical immutable metadata contract.
An exact record binds a stable `fwkeys://<tenant>/...` handle, credential class,
FW-ID owner, purpose, backend reference class, lifecycle timestamps, generation,
and the mandatory `NON_EXPORTABLE` policy. Unknown fields, cross-tenant
handles, exportable policies, malformed values, and secret-shaped content fail
closed.

Backend reference classes name trust domains only. They are not addresses and
do not activate a vault, HSM, environment variable, file, OAuth exchange,
network route, provider, or credential resolver. The contract creates no
authentication, authorization, signing, encryption, policy, Git, deployment,
or response capability.
