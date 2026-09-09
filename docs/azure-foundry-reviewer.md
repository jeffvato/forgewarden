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
