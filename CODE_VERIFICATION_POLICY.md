# ForgeWarden Code Verification Policy

## Required independent reviewer

Effective for new ForgeWarden code-verification work, the required independent
review path is **OpenAI Daybreak Blue** using:

- model alias: `gpt-daybreak-blue-latest`
- cyber access program: `daybreak_blue`
- role: read-only exact-commit verifier

The reviewer receives the exact candidate commit/patch and deterministic test
evidence. It has no source-write, Git, merge, deployment, credential, policy,
or authority-expansion capability.

## Fail-closed rule

Daybreak Blue verification is mandatory for acceptance once this policy is
active. If the approved Daybreak project, model access, credential path, or
review service is unavailable, ForgeWarden records verification as unavailable
and does **not** silently substitute Claude, Gemini, another model, or a paid
fallback.

No existing AI reviewer becomes execution authority. Deterministic validation,
trusted Git ownership, Action Tickets, policy enforcement, kill switch, and
human authority remain separate.
