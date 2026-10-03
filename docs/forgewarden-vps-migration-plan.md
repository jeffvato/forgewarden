# ForgeWarden and btgunco.com VPS migration plan

Date: 2026-10-03  
Status: planning only; no server, DNS, firewall, website, or deployment changes authorized by this plan.

## Confirmed target details

Jeff reported an IONOS VPS-1 / VPS 2-4-120 with 2 vCores, 4 GB RAM, 120 GB NVMe, 1 Gb bandwidth, one IP, Ubuntu 24.04 after reinstall, and a stated price of $14/month with no add-ons. The address supplied is `104.254.245.79`. These are user-provided details, not independently verified in the provider console. Confirm the current bill, renewal date, public IP assignment, CPU architecture, and final OS before migration.

Jeff created a `forgewarden` Linux user, changed its password, and used `ssh-copy-id` to install a public key. A screenshot showed an ED25519 host-key fingerprint at that time; a reinstall may have changed it. Do not reuse a fingerprint without checking the provider console. Jeff later reported changing sudo configuration, but the exact active sudoers state has not been verified. Do not place passwords, private keys, API keys, recovery codes, browser-session material, or SSH command secrets in Git or Markdown.

The reported SSH session later closed because `/etc/ssh/sshd_config.d/99-forgewarden.conf` contained the literal invalid directive `printf:`. Whether this was repaired and whether SSH currently works are unknown. The reported previous VPS, its provider/address, installed ForgeWarden version, and website origin/stack are also unknown. Domain `btgunco.com` is in scope; its current DNS records, Cloudflare proxy/WAF configuration, origin, and website deployment method must be inventoried before any move.

ForgeWarden's canonical source remains `https://github.com/jeffvato/forgewarden`. The checked-out application describes itself as DRY_RUN/local-first; its production deployment controller remains disabled. The new VPS must not be treated as production-ready merely because SSH works.

## Sequenced plan and gates

### 1. Inventory and recovery access

1. Identify the old VPS/provider/IP, all workloads and data on it, and which service currently serves `btgunco.com`.
2. From the IONOS console, verify target state, Ubuntu 24.04 release, CPU architecture, disk layout, public IP, firewall/security-group state, and billing terms. Preserve console access as the recovery channel.
3. Before changing SSH, inspect and back up the exact `sshd_config` and drop-ins, validate with `sudo sshd -t`, then open a second independent key-authenticated session and confirm `sudo -v`. Keep the recovery console and current access usable until that test passes. Do not disable root/password login or alter port/firewall policy speculatively.
4. Inspect `sudo -l` and the exact sudoers drop-ins with `visudo -c`. Prefer a named administrative account with password-confirmed sudo over unrestricted `NOPASSWD:ALL`; if passwordless automation is still wanted, define and approve a narrowly scoped command policy separately.

Gate: if SSH, sudo, host identity, OS, IP, or provider billing is ambiguous, stop and resolve it before installing or migrating anything.

### 2. Secure and prepare the target

After explicit approval to administer the host: apply supported Ubuntu security updates; retain the provider console; configure SSH key access and least-privilege administration; validate each SSH change before reload; then configure a host firewall that permits only the required management source and web ports. Add unattended security updates, time synchronization, log rotation, disk monitoring, and a tested backup/snapshot procedure. Do not expose the ForgeWarden console, database, Docker socket, SSH to the world, or model/API ports. Do not install unreviewed package repositories or paid add-ons.

Record configuration changes and validation outcomes without recording secret values. Confirm the resource budget (4 GB RAM / 120 GB disk) before choosing Docker, a reverse proxy, or co-location; measure actual usage and leave operating-system/update headroom.

### 3. Stage ForgeWarden without activating production authority

1. Clone only the canonical GitHub repository and record the exact commit and branch.
2. Run the approved portable test/validation suite in an isolated location; record failures separately from environmental limitations.
3. Determine which ForgeWarden components are genuinely intended to run on this VPS. The present repository has DRY_RUN and deployment-disabled boundaries; do not create a systemd service, enable an autonomous worker, deploy, or connect provider credentials unless Jeff separately approves a concrete deployment design.
4. Daybreak Blue is the sole reviewer under D-027. Its Responses API route may incur token charges and needs authorized account access. The application must fail closed without that configuration; do not place an API key on the VPS or enable unattended reviews without a separately approved key-management and spend-limit design.
5. Store operational secrets only in an explicitly chosen host-side secret mechanism with least privilege and backups that exclude secret values. Never commit `.env`, private keys, passwords, or session tokens. A `.env` file is not a substitute for an approved secret-management boundary.

Gate: do not enable services, background jobs, automatic pulls, writes to GitHub, model calls, or deployment until the operational scope, rollback plan, and required credentials/budget are approved.

### 4. Stage the website separately

1. Identify the actual website stack (static, CMS, framework, database, uploads, forms/email integrations), current origin, source repository, build process, dependencies, and backup/restore procedure. No stack or current origin has yet been verified.
2. Make an encrypted, restorable backup of site files and databases, then test restoration in a non-production location. Do not copy credentials into this repository.
3. Build and test the site on the new VPS using a non-public test hostname or local hosts-file override. Keep ForgeWarden and the public website in separate service identities, paths, containers/systemd units, logs, and secrets. Use only the inbound ports required for SSH/HTTP/HTTPS.
4. Configure HTTPS and origin access only after confirming the existing Cloudflare mode, certificate strategy, proxy state, WAF rules, and IPv4/IPv6 behavior. Preserve the current “Block all but US” policy unless a separately reviewed change is approved. Do not add the proposed `2a12::/12` or rate-limit rules without validating the exact current Cloudflare configuration and user approval.
5. Check page rendering, redirects, contact forms, uploads, database writes, email delivery, analytics, TLS, logs, backups, and recovery before DNS cutover.

### 5. Cut over with a rollback window

After a maintenance window and explicit cutover approval, reduce DNS TTL in advance if supported, snapshot both systems, change only the necessary `btgunco.com` records to the new origin, and monitor DNS, HTTPS, Cloudflare security events, application health, forms, and resource use. Keep the old VPS and its data intact for an agreed rollback interval (suggested minimum 48–72 hours) and document the exact DNS rollback values before cutover. Do not delete, cancel, wipe, or stop the old VPS until Jeff confirms the new website and ForgeWarden scope are stable and backups are verified.

## Codex Cloud for PC-independent development

This is a development-workflow move, separate from the IONOS VPS and `btgunco.com` production migration. Jeff wants Codex to continue repository work while his PC is off. Codex Cloud is the intended destination; do not interpret this as approval to deploy ForgeWarden or the website to a cloud host.

### Current readiness

- The canonical GitHub remote is `jeffvato/forgewarden` (private access must be verified in the Codex account, not inferred from the local remote URL).
- The local Codex project is not currently a saved Git-backed Codex project, and the current Daybreak reviewer changes and documentation are uncommitted. A separate cloud task cannot see them yet.
- No Codex Cloud environment has been created or published in this work. The local checkout, Windows/WSL state, and local secrets should be assumed unavailable to cloud tasks.
- Cloud environment creation and GitHub connection must be completed in Codex's supported UI. Do not use a ChatGPT Work Cloud task as an equivalent substitute.

### Safe setup sequence

1. Finish validating and reviewing the current branch candidate. Keep the current failed broad-suite results visible; do not make a commit look fully accepted while the required checks/review are outstanding.
2. After gates pass, commit the candidate locally, obtain the required exact-commit Daybreak review, and push only through the authorized Git workflow to the canonical private GitHub repository. Do not expose the repository publicly to simplify setup.
3. In Codex Cloud, connect Jeff's intended GitHub account and only the `jeffvato/forgewarden` repository, using the narrowest supported repository permissions. Verify the connected identity and repository before creating workspaces.
4. Create and publish a ForgeWarden cloud environment from the repository's documented setup. Pin runtime/tool versions and install only test/build dependencies needed for the repository. Avoid broad package managers, privileged setup hooks, Docker socket access, arbitrary host mounts, and persistent secret injection unless separately reviewed and approved.
5. Start a read-only smoke task on the exact accepted commit. Confirm the environment checks out the expected repository and SHA, runs a harmless status/test command, cannot access production credentials, and cannot deploy or mutate external services. Record the environment setup and first successful task in the session handoff.
6. Thereafter, have Codex Cloud work on explicit branches/commits and submit reviewable diffs/PRs. Keep the deterministic orchestrator and Daybreak read-only reviewer policy; cloud execution does not grant either reviewer or agent production authority.

### Cloud security and lifecycle boundaries

- Do not upload VPS passwords, SSH private keys, `.env` files, API keys, browser/session tokens, recovery codes, or local `.n8n` data. Do not paste them into cloud task prompts or setup commands.
- Use repository-scoped GitHub authorization for source work. Any model/API credential needed for Daybreak is a separate billing and secret-management decision; no credential is authorized by the Cloud move request. Keep live model calls disabled until Jeff separately approves scope and spend.
- Cloud workspaces are isolated task checkouts, not a synchronized continuation of the local filesystem. Commit/push only after applicable validation and exact review; retain a commit/PR as the durable handoff.
- Cloud execution can continue without the user's PC running, but cloud environment availability, retention, plan entitlement, and spend controls must be checked in the signed-in Codex UI before enabling recurring or long-running work. Do not create a recurring automation or autonomous always-on agent as part of setup.
- This cloud-development setup does not change IONOS, Oracle tenancy, website hosting, DNS, Cloudflare, email, billing, or production credentials. Those remain separate stages and approvals above.

### Action list

- [ ] Finish current branch validation and exact Daybreak review before cloud publication.
- [ ] Commit and push only the validated/reviewed candidate to the existing private GitHub repository.
- [ ] Connect the correct GitHub account and only the ForgeWarden repository in Codex Cloud.
- [ ] Publish a minimal, pinned, no-secrets cloud environment and run a read-only smoke task at an exact SHA.
- [ ] Record verified environment name, setup steps, permissions, task result, and any plan/retention limits in the next handoff.

## Action list (not yet authorized for execution)

- [ ] Jeff identifies the old VPS/provider/IP and what it runs.
- [ ] Confirm IONOS target billing, Ubuntu version, architecture, IP, and console access.
- [ ] Re-establish SSH safely and verify sshd/sudoers state; preserve recovery access.
- [ ] Inventory the website source, stack, data, DNS/Cloudflare records, and backup/restore path.
- [ ] Decide ForgeWarden's permitted runtime role on this VPS; current policy does not authorize deployment.
- [ ] Create and validate backups; stage site and any approved ForgeWarden components separately.
- [ ] Approve cutover date, DNS changes, monitoring, rollback window, and eventual old-server retirement separately.

No checklist item is complete based on this plan alone. No cloud, network, DNS, host, secret, or deployment change was performed while authoring it.
