# FW-MODEL-001 -- Feasibility and ownership inventory

Status: **DESIGNED / PLANNED**. No private model has been trained, registered, or deployed.

## Existing canonical owners

- **Model Broker:** `swarm/model_broker.py` owns exact tenant and worker binding for approved model/provider/deployment/version/approval records. A model cannot be used when its approval is absent or revoked.
- **FW-HARNESS review path:** `swarm/review_runner.py` owns exact-SHA reviewer binding, sequential fallback, schema validation, and non-authoritative reviewer disposition.
- **Azure Foundry boundary:** `swarm/azure_foundry_adapter.py` accepts only approved Azure HTTPS hosts and the OpenAI v1 route, bounds prompt/response/resource values, resolves credentials at the transport boundary, and never gives the reviewer repository tools.
- **Azure credit protection:** the adapter requires fresh operator-verified credit-only evidence and a spending-protection flag, reserves a bounded per-call ceiling in a locked ledger, enforces a daily call limit, and fails closed when evidence or limits are absent.
- **Identity and secrets:** FW-ID and FW-KEYS own identity binding and opaque credential handles. Raw provider credentials are not model inputs or task data.
- **Evidence and safety:** FW-EVID, deterministic policy, DRY_RUN/DETECT_ONLY, deployment-disabled state, and the engaged kill switch remain authoritative.

## Safest initial model strategy

Start with a retrieval/policy specialization benchmark and a sanitized evaluation corpus. Consider a LoRA/PEFT adapter only after license, provenance, benchmark, and budget gates pass. Training from scratch is deferred because feasibility, data volume, hardware, and commercial licensing are not yet established.

## Azure credit gate

The available startup balance may fund a capped feasibility or PEFT experiment, but eligibility, quota, model availability, and current balance must be verified at execution time. The experiment must use a hard ceiling below the remaining credit, no automatic scale-up, bounded runtime and calls, budget alerts, and deterministic stop-at-limit behavior. No production endpoint or deployment activation is part of this phase.

## Open decisions before FW-MODEL-004

1. Approved foundation model and commercial-use license.
2. Retrieval-only versus PEFT experiment.
3. Sanitized corpus sources and holdout split.
4. Azure Foundry project/deployment eligible for the approved data classification.
5. Exact experiment ceiling and expiry cleanup procedure.
6. Benchmark thresholds and independent reviewer assignment.

These decisions require evidence and, where they expand authority or activate an external model deployment, separate human approval.
