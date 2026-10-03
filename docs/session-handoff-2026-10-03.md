# ForgeWarden session handoff — 2026-10-03

Use this as the current dated checkpoint. Older handoff files remain historical and may mention superseded reviewer/cloud plans; this file and current Git state take precedence.

## Repository and current work

- Canonical remote: `https://github.com/jeffvato/forgewarden` (`origin`).
- Working branch: `feat/fwq-0115-prerequisites`; it was clean at start of today's work and six commits ahead of `origin/main`.
- The base contained accepted FWQ-0115 prerequisite hardening (`b79f829fc4afe3cafe804ce2c0c1eb5c416e361d`) with its recorded isolated Daybreak review; that is historical evidence for the prior commit only.
- Jeff directed Daybreak Blue be wired as the only active reviewer. D-027 now supersedes D-026 for active policy. `gpt-daybreak-blue-latest` is routed through OpenAI Responses with `access_programs: {cyber: daybreak_blue}`, strict structured output, exact job/SHA binding, bounded input/output, no tools, and no fallback. The direct CLI is now `daybreak-review`; generic review-cycle defaults to Daybreak. Legacy records remain readable and historical review evidence is not rewritten.
- The new adapter and policy have mocked tests; focused suites passed 212 tests. No OpenAI API credential was read and no billable API call was made. Exact Daybreak review of the current candidate has not occurred. User approval for this implementation is not itself approval to incur an API charge; obtain explicit approval for a live exact-review call and its spend before sending one.
- A complete suite was attempted under WSL but did not pass: 2,249 passed, 1 skipped, 35 failed, 37 errors. Many integration failures/errors trace to WSL interpreting this Windows worktree's `.git` indirection as an invalid path; shell-launcher checks also encounter CRLF behavior. The focused tests pass. Re-run the required broad gates only in a compatible Linux checkout; do not claim full repository integrity is green.
- `python -m pytest` under native Windows Python cannot collect Linux-only modules (`fcntl`/`resource`); use the project's compatible Linux checkout/environment.

## Today's IONOS server facts and blocker

Jeff reported a paid IONOS VPS-1 / VPS 2-4-120: 2 vCores, 4 GB RAM, 120 GB NVMe, 1 Gb bandwidth, one IPv4 address, Ubuntu 24.04 reinstall, and $14/month with no add-ons. Supplied IP: `104.254.245.79`. The target's final OS, architecture, billing and active state have not been independently verified.

Jeff created user `forgewarden`, changed its password, installed a public SSH key with `ssh-copy-id`, and reported a sudo change. Never repeat or store the temporary password from chat. A later SSH failure showed `/etc/ssh/sshd_config.d/99-forgewarden.conf` beginning with invalid `printf:` text. Current SSH, sudoers and hardening state are unknown; preserve IONOS console recovery access and inspect before making repairs.

The old VPS/provider/IP, website origin/stack, actual `btgunco.com` DNS and Cloudflare configuration, site backup, and data migration plan are not yet known. See [the migration plan](forgewarden-vps-migration-plan.md). It is planning-only and does not authorize DNS, server, production, or deployment changes.

## Immediate safe next steps

1. Finish review adapter/code and documentation validation; inspect the diff and Git state. The current uncommitted branch work is not available to a new Codex Cloud task until it is safely committed and pushed.
2. Keep FWQ-0116 in REVIEW until a live, exact Daybreak review and compatible broad validation have been separately authorized and completed. Do not claim the current code was Daybreak-approved merely because Daybreak is now the configured reviewer.
3. Ask Jeff for approval before any billable live Daybreak review and state the estimated call cost/spend cap.
4. Prepare Codex Cloud only after the exact reviewed candidate is in the canonical private GitHub repository: connect the correct GitHub account/repository in Codex, create and publish a cloud environment with pinned, least-privilege build/test dependencies, then verify a non-mutating cloud task against the exact commit. Do not create a ChatGPT Work Cloud task as a substitute for Codex Cloud.
5. Do not transfer `.env` values, API keys, SSH private keys, browser sessions, VPS credentials, or local `.n8n` data into the cloud environment. Cloud tasks should use repository-scoped GitHub access and no production secrets by default.
6. Before any server work, ask which old VPS to migrate from and confirm the website origin/stack; verify IONOS console access, OS, architecture, SSH and sudoers safely.
7. Keep application deployment, website DNS cutover, Cloudflare changes, credentials and old-server retirement behind their own explicit approvals.

## Codex Cloud transition

Jeff wants ForgeWarden work to continue when the PC is off. Codex Cloud is the desired execution environment, not a request to migrate the production VPS or website into a cloud service. As of this checkpoint, the repository is only available as a local saved project in Codex; the latest changes are uncommitted, so cloud continuation is not yet ready. The intended sequence and security boundaries are documented in [the migration and cloud transition plan](forgewarden-vps-migration-plan.md#codex-cloud-for-pc-independent-development).

Codex Cloud task workspaces are separate from this local checkout. Preserve work in the canonical GitHub repository before starting cloud work, then explicitly prepare/publish the environment and verify its dependencies and permissions. Never rely on the PC being on for cloud execution; never assume local uncommitted state or a local credential automatically appears in a cloud task.

## Safety invariants

Codex remains the sole code writer. Daybreak is read-only and has no tool, Git, deployment, credential, or authority-expansion permission. Preserve DRY_RUN, deployment disabled, kill switch engaged, exact evidence binding, least privilege, user-controlled DNS/cutover, and no-secrets-in-Git/Markdown rules.
