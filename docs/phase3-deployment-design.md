# Phase 3 deployment design

Profile: `forgewarden_synthetic_service_deployment_v1`

Status: design-only. No deployment adapter exists or may be invoked from this
profile yet.

The approved design binds commit `06a22f1c431867cede1265bae7edf706e5a5ae04`
and uses the durable local audit as its required notification channel.

## Scope

The first Phase 3 target is the explicitly named disposable staging fixture
`forgewarden-synthetic-fixture-v1`. It is not a production service, remote
host, customer environment, or protected repository. The design does not add
service start, restart, network, credential, or remote-host capability.

## Required gates

Every future deployment must bind one human approval to the job ID, exact
approved commit, evidence SHA-256, and service profile. The approval is
single-use, expires, and is rejected on replay or any mismatch. Gemini approval
is evidence only and never substitutes for deployment approval.

Before mutation, the fixed adapter must verify a clean target, exact commit,
engaged kill-switch policy transition, deployment mode, backup destination, and
the absence of another deployment. It must create a protected backup before
changing anything.

After mutation, the fixed health check must pass within 30 seconds. Failure,
timeout, commit mismatch, audit failure, or loss of the required state must
trigger the fixed rollback adapter. Rollback must restore atomically with
no-follow path handling, rerun the health check, and leave deployment disabled
unless a new human approval is issued.

## Safety boundaries

- no arbitrary service, command, path, repository, host, or environment input;
- no remote execution, credentials, network access, or production targeting;
- one deployment at a time and bounded backup/log sizes;
- every state transition and approval decision recorded in the durable audit;
- no automatic retry after rollback or approval consumption;
- failure to prove any precondition fails closed without mutation.

## Required implementation evidence

Before this profile can leave design-only status, it needs fake-adapter tests for
approval binding and replay, exact-commit checks, backup/restore, health failure,
timeout, audit failure, symlink rejection, cleanup, and final disabled state.
It also needs a human review of the adapter and a disposable staging exercise.

## Fake adapter milestone

The disposable-only simulator `swarm/phase3_fake_deployment.py` now covers
exact approval binding, one-time replay rejection, backup creation, health
failure and timeout rollback, audit-failure rollback, identifier validation,
service/commit mismatch rejection, and symlink rejection. Its focused checks
pass 11/11 and the portable suite passes 119 tests. It never
starts a service, runs an external command, opens a network connection, or
enables deployment. The profile remains design-only.
