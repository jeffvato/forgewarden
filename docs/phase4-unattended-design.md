# Phase 4 unattended deployment design

Profile: `forgewarden_low_risk_unattended_v1`

Status: design-only. This profile does not enable unattended execution,
register a worker, start a service, or authorize deployment.

## Boundary

Phase 4 is limited to the explicitly named low-risk disposable staging fixture
`forgewarden-synthetic-fixture-v1`. High-risk categories, production services,
remote hosts, customer data, credentials, network access, and arbitrary
commands remain excluded.

## Required prerequisites

The profile cannot leave design-only status until four independent evidence
bundles exist: Phase 2A connection/replay proof, supervised persistent-worker
proof, human-approved deployment proof, and rollback/health proof. Each bundle
must be bound to the service, exact commit, evidence hash, and low-risk class.

Initial enablement requires one-time human approval. The kill switch must be
present and independently verifiable; any missing prerequisite, stale approval,
replay, risk mismatch, worker duplication, health timeout, or audit failure
must fail closed.

## Worker and rollback controls

Only one job may run at a time. The worker must be supervised and persistent,
but no worker is started by this design. Deployment remains disabled until all
gates are separately satisfied. A health failure within 30 seconds triggers
automatic rollback, durable audit, notification, and kill-switch engagement.

## Required tests before admission

Fake tests must cover prerequisite absence, stale and replayed approvals, risk
escalation, duplicate worker rejection, kill-switch enforcement, health
timeout, rollback, audit failure, notification failure, cleanup, and final
disabled state. A human review is required before any admission or enablement.
