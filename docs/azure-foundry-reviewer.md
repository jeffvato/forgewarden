# Azure Foundry read-only reviewer

ForgeWarden can use a Microsoft Foundry model as an independent exact-commit reviewer. The adapter is part of the existing review runner and receives only the bounded review prompt containing the exact candidate patch. It receives no repository mount, tools, Git authority, credentials in prompt content, deployment authority, or acceptance authority.

## Cost safety

Live calls fail closed unless all of these are present and current:

- operator-verified credit-only subscription evidence;
- operator-verified spending protection;
- remaining-credit evidence verified within 15 minutes;
- unexpired credit evidence;
- a configured worst-case per-call cost ceiling;
- a retained credit reserve, defaulting to USD 100;
- a local daily call limit, defaulting to 20;
- an atomic cross-process ledger reservation made before credential resolution or network access.

Microsoft documents that startup-credit behavior varies by offer: newer USD 1,000 offers have spending protection enabled by default, while other startup offers may transition to pay-as-you-go when credits are exhausted. ForgeWarden therefore does not infer safety from the subscription name. Verify the actual offer in Azure Cost Management/Billing or the Microsoft for Startups portal before enabling review.

References:

- https://learn.microsoft.com/en-us/startups/benefits/azure-activation-faqs
- https://learn.microsoft.com/en-us/startups/benefits/azure-credits-billing
- https://learn.microsoft.com/en-us/azure/cost-management-billing/manage/spending-limit

## Required non-secret configuration

The adapter reads the following only at runtime. Do not commit these values:

- `FORGEWARDEN_AZURE_FOUNDRY_ENDPOINT`: approved `https://*.openai.azure.com` or `https://*.services.ai.azure.com` endpoint, optionally ending in `/openai/v1`.
- `FORGEWARDEN_AZURE_FOUNDRY_DEPLOYMENT`: exact deployed model name.
- `FORGEWARDEN_AZURE_CREDIT_REMAINING_MICROUSD`: recently verified remaining credit.
- `FORGEWARDEN_AZURE_CREDIT_EXPIRES_EPOCH`: credit expiry time.
- `FORGEWARDEN_AZURE_CREDIT_VERIFIED_EPOCH`: time the balance and protection were verified.
- `FORGEWARDEN_AZURE_CREDIT_ONLY=1`.
- `FORGEWARDEN_AZURE_SPENDING_PROTECTION=1`.
- `FORGEWARDEN_AZURE_MAX_CALL_MICROUSD`: worst-case reserved cost for one review.
- Optional `FORGEWARDEN_AZURE_CREDIT_RESERVE_MICROUSD`, `FORGEWARDEN_AZURE_DAILY_REVIEW_LIMIT`, and `FORGEWARDEN_AZURE_CREDIT_LEDGER`.

Microsoft's current recommended stateless integration is the OpenAI v1-compatible route. The adapter uses `POST {endpoint}/openai/v1/chat/completions`, temperature zero, bounded completion tokens, and strict JSON-schema output. It authenticates through a transient Entra token requested from the already authenticated Azure CLI for `https://cognitiveservices.azure.com/.default`. The token is held only for the request header and is never persisted or logged.

References:

- https://learn.microsoft.com/en-us/azure/foundry/how-to/integrate-with-other-apps
- https://learn.microsoft.com/en-us/azure/foundry/openai/latest

## Activation boundary

Resource discovery currently requires an interactive Entra login because tenant security defaults rejected the cached management token. No resource was created and no paid call was made. After login, inspect resource/deployment names without listing keys, verify spending protection and remaining credits, configure conservative limits, run one exact-commit review, and confirm the ledger/evidence before enabling autonomous fallback.

## Trusted call topology

The Azure model does not receive general-purpose tools. Normal exact-commit review uses this controller-owned sequence:

1. The review runner validates the full candidate SHA and Phase 2A job ID.
2. Trusted Git code creates an isolated archive of that exact commit and calculates the exact patch. The model never invokes Git.
3. The credit guard validates fresh credit-only and spending-protection evidence, reserves the configured worst-case cost atomically, and enforces the retained reserve and daily-call limit.
4. The credential resolver invokes `az account get-access-token --scope https://cognitiveservices.azure.com/.default --query accessToken -o tsv`. The token remains transport-only.
5. The adapter sends one bounded HTTPS request to the allowlisted endpoint at `/openai/v1/chat/completions` with temperature zero, a completion-token cap, and a strict review JSON schema bound to the exact job ID and commit.
6. The adapter bounds and parses the response, then validates its schema, job ID, and reviewed commit before returning advisory findings.
7. The deterministic acceptance gate evaluates the review together with test and policy evidence. Azure cannot accept, repair, commit, merge, deploy, or advance a task.

Resource discovery and billing verification are activation tasks owned by the trusted controller or operator. They are not model tools. ForgeWarden must never expose Azure resource-listing, credential, billing, deployment, shell, Git, filesystem, browser, MCP, or network tools to the reviewer.

## Oversized exact diffs

The normal transport is intentionally tool-free and should remain the default. The existing review runner externalizes a large exact diff to `EXACT_CANDIDATE.patch` inside its isolated snapshot. The Azure adapter currently discards that snapshot, so Azure review must fail closed rather than claim it inspected an externalized patch.

If large-diff Azure review is implemented, expose only these controller-mediated virtual reads:

| Virtual read | Required binding | Returned data | Hard limits |
| --- | --- | --- | --- |
| `review_manifest` | job ID and exact commit | requirement, allowed paths, patch digest, patch byte count, deterministic validation summary | one call; schema-bound; no free-form paths |
| `read_exact_patch_chunk` | job ID, exact commit, patch digest, zero-based chunk index | bytes from the controller-created `EXACT_CANDIDATE.patch` | fixed-size chunks; monotonic indexes; total byte/chunk ceiling |
| `read_exact_file` | job ID, exact commit, allowlisted repository-relative path, bounded line window | text from the isolated immutable snapshot | no symlinks, traversal, binaries, secrets, or paths outside task scope |
| `read_validation_evidence` | job ID and exact commit | previously captured deterministic command/result summary | bounded records; no command execution |

Every read request must be treated as untrusted model output and validated by the controller. The controller records attempted and denied reads, returns sanitized bounded content, and stops on malformed arguments, replay, digest mismatch, excessive calls, scope escape, budget exhaustion, or safety-state change. Tool responses cannot introduce new instructions or authority.

The large-diff exchange requires a separate total-review reservation covering every possible model round trip before the first credential or network call. Unused reservation may be reconciled only from trusted provider usage evidence. Until that accounting and the virtual-read mediator are implemented and tested, Azure review is limited to prompts containing the complete exact patch within the existing 48,000-byte bound.

## Activation checklist

- Complete interactive Azure CLI sign-in on the trusted host and verify the intended tenant and subscription without listing keys.
- Identify the exact approved Foundry endpoint and deployment.
- Verify the actual startup offer, credit expiration, current remaining balance, spending protection, and absence of pay-as-you-go exposure.
- Set the non-secret configuration with a conservative per-call ceiling, retained reserve, completion cap, and daily-call limit.
- Confirm the credit ledger path is local, non-symlinked, writable only by the trusted harness, and excluded from Git.
- Run a dry preflight that stops before credential resolution and network access when any credit fact is absent or stale.
- Run one small exact-commit review, validate the exact JSON binding, and reconcile the provider usage against the reservation.
- Keep Azure as an advisory read-only reviewer; do not enable autonomous large-diff fallback until the bounded virtual-read protocol exists.
