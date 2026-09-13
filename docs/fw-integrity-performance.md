# FW-INTEGRITY bounded control-plane performance baseline

## Contract

The performance baseline measures five representative pure deterministic paths:
canonical identity plus policy evaluation, Evidence hashing, approved-model
routing, normalized AI-event construction, and Mission Control Demo projection.
The scenarios reuse their existing canonical owners. They add no alternate
identity, policy, Evidence, Model Broker, event, or Mission Control component.

A versioned tracked JSON policy fixes scenario order, iteration counts, wall
time, traced peak memory, process count, timeout, and output limits. Policy data
contains no commands. Each scenario runs sequentially in one bounded local
Python child against a safely extracted archive of one exact commit. The child
environment includes only locale, archive import, no-user-site, and no-bytecode
settings; provider and network credentials are not forwarded. Shell command
construction is never used.

The proof rejects a missing, changed, malformed, duplicated, reordered, or
unsafe policy; commit drift; archive hazards; child timeout or crash; excessive,
secret-bearing, non-JSON, or schema-invalid output; process, latency, memory, or
safety threshold violations; and cleanup failure. Child output and fixture
checksums are not retained. The result binds its policy hash and exact commit.

Run it with:

```text
bash scripts/run-performance-baseline.sh
```

## Limits

These deliberately conservative limits detect catastrophic local regressions.
They are not production capacity, throughput, latency SLO, load, concurrency,
endpoint-impact, or scalability evidence. Results vary with the host and are
reported only as local measurements against fixed ceilings. No benchmark
dependency is installed; no provider, network, service, sensor, response,
recovery, deployment, credential, or authority capability is added.
