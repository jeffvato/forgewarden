# FW-ENDPOINT-14 — Endpoint and RansomGuard continuation inventory

## Accepted boundary

ForgeWarden already has one canonical endpoint event path. Windows and Linux
caller-supplied records pass through `DryRunSensorPipeline` into
`NormalizedEventStore`; Android caller-supplied records use the same store.
The store owns tenant/device binding, bounded batches, duplicate rejection,
backpressure, Evidence-first admission, FIFO inspection, acknowledgement, and
recovery replay. These accepted controls are not continuation work and must not
be rebuilt.

RansomGuard already consumes canonical `EndpointObservation` values. Its
accepted bounded controls cover activity scoring, ticket-bound isolation
proposals, canary touches, SMB propagation, and defensive-control tamper
signals. They remain fixture-only, `DRY_RUN`, and `DETECT_ONLY`. A new endpoint
platform should reuse this evaluator when its normalized event vocabulary is
compatible; it does not require a second ransomware engine.

## Canonical owners reused

| Concern | Canonical owner |
| --- | --- |
| Endpoint normalization and queue lifecycle | `NormalizedEventStore` |
| Windows/Linux caller-supplied mapping | `DryRunSensorPipeline` |
| Android caller-supplied mapping | `android_fixtures` |
| Ransomware detection and proposal boundary | `ransomware` |
| Tenant identity and provider binding | FW-ID |
| Secret and credential handles | FW-KEYS |
| Lifecycle chronology | FW-EVID |
| Resume and acknowledgement | FW-REC |
| AI workload attribution | FW-AID references on the endpoint envelope |
| Response authority | deterministic policy and Action Tickets |

## Genuine continuation gaps

The roadmap names macOS, iOS/iPadOS, WSL2, container nodes, and Kubernetes in
addition to the accepted Windows, Linux, and Android fixture boundaries. The
next bounded platform gap is macOS caller-supplied fixture normalization. It
can reuse the existing canonical event vocabulary and store without adding a
service, platform API, filesystem/process hook, network transport, credential
access, or response path.

The next implementation milestone is `FW-ENDPOINT-MACOS-01`: a pure macOS
record mapper plus single-record and atomic bounded-batch admission through
`NormalizedEventStore`. It must fail closed on malformed fields, unknown event
types, source mismatch, tenant/device mismatch, duplicate IDs, invalid batch
bounds, Evidence failure, and canonical store pressure. RansomGuard integration
is deferred until that mapper is accepted; the proof should then demonstrate
that compatible macOS observations reach the existing evaluator unchanged.

iOS/iPadOS, WSL2-specific attribution, container/Kubernetes fixtures, and live
platform collectors remain later independent milestones. Their roadmap
presence grants no sensor, hook, process, filesystem, network, credential,
containment, remediation, recovery-execution, deployment, or kill-switch
authority.

## Safe sequence

1. Implement and prove `FW-ENDPOINT-MACOS-01` as a caller-supplied fixture seam.
2. Prove compatible macOS observations against the existing RansomGuard
   evaluator without changing response authority.
3. Inventory the next platform only after the macOS lifecycle is accepted.

Each candidate stays small enough for a fresh exact-commit AnythingLLM/Qwen
review under the configured Groq limits. Provider throttling fails closed and
does not weaken exact SHA, job, schema, or reviewer separation.
