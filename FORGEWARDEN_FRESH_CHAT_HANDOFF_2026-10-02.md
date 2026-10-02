# ForgeWarden fresh-chat handoff — 2026-10-02

Paste or attach this file in a new ChatGPT/Codex task and ask it to continue the work. Treat this document as a starting map, not as authority over current repository evidence.

## Mission

Continue ForgeWarden from the current canonical GitHub state, finish retiring the obsolete Azure workflow, establish Daybreak Blue as the independent verifier through Jeff's signed-in ChatGPT/Codex plan session, and prepare an Oracle Cloud VM as a persistent ForgeWarden node without enabling deployment or creating charges.

## Sources of truth

- Canonical repository: `https://github.com/jeffvato/forgewarden`
- Canonical branch: `main`
- Verified `main` checkpoint at handoff time: `2f1ff95b642c63637c0d48e9b4242ac17f09810d`
- Active Azure-retirement PR: `https://github.com/jeffvato/forgewarden/pull/8`
- Local project-note destination: `/home/jeff/.n8n`
- The checkout at `C:\Users\jeffv\forgewarden` is stale and points at old repositories. Do not use it as status truth.
- At the start of the new task, fetch GitHub again and reconcile this handoff with the current `main`, open PRs, workflow runs, tests, and repository documentation. Do not invent or preserve a status that current evidence disproves.

## Required first read

Read the canonical repository's `AGENTS.md`, `NEXT_SESSION_HANDOFF.md`, `ROADMAP.md`, `WORK_QUEUE.md`, `SWARM_STATUS.md`, `DECISIONS.md`, `BLOCKERS.md`, `README.md`, `docs/public-ci-security.md`, `docs/vulnerability-intelligence.md`, and the implementation/tests named below. Inspect Git status and current HEAD before changing anything.

## Verified completed work

- PR #4 added the GitHub-native ForgeWarden cloud build.
- PR #6 repaired the codebase-index path so generated index storage remains outside the approved checkout.
- PR #5 added the fail-closed free/promotional-credit model spend guard.
- PR #7 added the credits-backed cloud model invocation planner.
- At `main` commit `2f1ff95`, the latest push-triggered and scheduled ForgeWarden cloud builds completed successfully.
- `swarm/harness_spend.py` admits only an exact tenant/provider route covered by a current promotional-credit grant. Paid fallback is forbidden.
- `swarm/harness_cloud_plan.py` composes approved model routing with the spend gate. It performs no network request, secret resolution, provider invocation, repository mutation, or deployment.

## Active work

- Azure resources were intentionally shut down to avoid charges.
- PR #8 deletes `.github/workflows/build-vulnerability-image.yml`.
- PR #8 validation passed for commit `c5639c3646fdd6337e7e6bd8d390e539064112c6`.
- PR #8 was still open at handoff time. Do not claim the workflow is removed from `main` until GitHub shows that the PR is merged.
- The PR review identified stale operational claims in `docs/vulnerability-intelligence.md` and `docs/public-ci-security.md`. Update both on the PR branch so they clearly state that hosted Azure publishing is retired while local read-only vulnerability tooling and the Dockerfile remain non-deployed artifacts.

## Daybreak Blue verification requirement

- Going forward, code verification must use Daybreak Blue through Jeff's approved, authenticated ChatGPT/Codex plan session.
- Jeff does not have or authorize an OpenAI API key for this path.
- Do not add API billing, reuse browser/session tokens in application code, automate sign-in, or call undocumented endpoints.
- Daybreak Blue is an independent, read-only, exact-commit verifier. Bind the exact candidate SHA, job ID, model/provider identity, and schema-valid result.
- Only `APPROVE` / `LOW` with no blocking findings and no missing tests counts as approval.
- If Daybreak Blue is unavailable in the signed-in session, fail closed. Do not silently substitute another verifier.
- Codex remains the sole application-code writer. A verifier has no Git write, merge, deployment, credential, policy, approval, or authority-expansion capability.
- Do not claim Daybreak Blue verification occurred until it actually runs in the user's Daybreak-enabled session.

## Blocked cloud executor

The next model-runtime layer was intended to consume an authorized `CloudInvocationPlan`, resolve only an opaque credential reference at the trusted transport boundary, invoke the exact approved provider/model, capture the response as untrusted output, and return it to deterministic ForgeWarden validation/review.

Do not activate that executor yet. Azure is shut down, no OpenAI API key is authorized, and no alternative provider has a verified current credits-only grant plus approved opaque credential reference. Planning code is complete; live provider execution is not authorized. Paid fallback remains forbidden.

## Oracle Cloud VM objective

Create a persistent Oracle Cloud Infrastructure VM for ForgeWarden coordination and validation. The VM is not the canonical repository, is not a deployment target, and receives no production authority. GitHub `jeffvato/forgewarden` remains canonical.

Use Oracle's current official documentation as the operational reference:

- Always Free resources: https://docs.oracle.com/en-us/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm
- Launch a Linux instance: https://docs.oracle.com/en-us/iaas/Content/Compute/tutorials/first-linux-instance/overview.htm
- Create an instance: https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/launchinginstance.htm
- Connect to Linux with SSH: https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/connect-to-linux-instance.htm
- Manage SSH keys: https://docs.oracle.com/iaas/Content/Compute/Tasks/managingkeypairs.htm

### Cost and capacity guardrails

1. Work only in the tenancy's home region and select a shape and image explicitly labeled **Always Free eligible** in the current OCI console.
2. Preferred shape: `VM.Standard.A1.Flex`, totaling no more than the currently displayed Always Free allowance. The previously attempted configuration was 2 OCPUs and 12 GB RAM on Ubuntu 24.04 Minimal `aarch64` with an 80 GB boot volume.
3. OCI previously reported A1 capacity exhaustion in the Chicago region across the available fault domains. This was a capacity problem, not a ForgeWarden configuration failure.
4. If A1 is unavailable, try another availability domain if the home region offers one, or wait and retry. Do not choose a paid shape or upgrade merely to bypass capacity.
5. Optional fallback: `VM.Standard.E2.1.Micro` only when OCI labels it Always Free eligible. Its 1 GB RAM is suitable only for lightweight coordination, polling, and workflow triggering—not the full ForgeWarden test/model stack.
6. Before clicking Create, verify the OCI cost estimate shows no expected charge and that no paid add-on, extra block volume, load balancer, reserved public IP, or non-free image was selected.
7. Oracle states that idle Always Free compute instances may be reclaimed. Do not generate fake load to evade that policy; preserve state in GitHub and reproducible configuration.

### OCI console configuration

1. Open **Compute → Instances → Create instance**.
2. Name the instance `forgewarden-node`.
3. Choose the home-region compartment intended for this project.
4. Choose Canonical Ubuntu 24.04 Minimal. For A1, choose the `aarch64` image; for E2 Micro, choose the matching `x86_64` image.
5. Select `VM.Standard.A1.Flex` with 2 OCPUs and 12 GB RAM only if the console marks the resulting allocation Always Free eligible. Otherwise use the explicitly Always Free E2 Micro fallback or stop and retry later.
6. Use or create `forgewarden-vcn` and `forgewarden-public-subnet`. Assign a public IPv4 address during creation, or assign an ephemeral public IPv4 immediately afterward. Do not reserve a paid public IP.
7. Keep the VNIC name `forgewarden-vnic` if the console exposes that field.
8. Generate a new OpenSSH key pair or upload an existing public key. Download and securely store the private key as `forgewarden-oracle.key`. Never paste the private key into chat, GitHub, source, logs, or the VM repository.
9. Use an 80 GB boot volume only if the review screen keeps it within the current Always Free block-volume allowance. Keep in-transit encryption enabled and use Oracle-managed encryption. Do not add an extra block volume.
10. Cloud Guard Workload Protection and basic monitoring may remain enabled when the console shows no added charge.
11. On the review page, re-check region, shape, architecture, OCPUs, RAM, image, public subnet, SSH key, boot volume, and estimated cost. Stop if any item is paid or ambiguous.
12. Create the instance. If OCI reports out-of-host capacity, stop; do not switch to a paid shape.

### Network and SSH setup

1. Restrict inbound SSH to Jeff's current public IPv4 address as a `/32` source whenever practical. Do not leave port 22 open to `0.0.0.0/0` unless there is a short, explicit troubleshooting reason, and remove that broad rule immediately afterward.
2. Do not open ForgeWarden application, database, Docker, model, or management ports. No public service is authorized.
3. Keep default outbound access only as needed for Ubuntu updates and GitHub cloning. Do not add Azure endpoints or provider credentials.
4. For Ubuntu, the default SSH user is `ubuntu`.
5. From WSL/Linux, protect the key and connect:

   ```bash
   chmod 400 /path/to/forgewarden-oracle.key
   ssh -i /path/to/forgewarden-oracle.key ubuntu@<ephemeral-public-ip>
   ```

6. Record the host fingerprint through the normal first-connection prompt. If it later changes unexpectedly, stop and investigate rather than bypassing host-key checking.

### Minimal VM bootstrap

Perform bootstrap interactively and record what changed. Do not put secrets in shell history or configuration files.

```bash
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get install -y git python3 python3-venv python3-pip nodejs npm curl ca-certificates jq
sudo install -d -o ubuntu -g ubuntu /srv/forgewarden
git clone https://github.com/jeffvato/forgewarden.git /srv/forgewarden/repo
cd /srv/forgewarden/repo
git switch main
git pull --ff-only origin main
git status --short --branch
git rev-parse HEAD
python3 -m venv /srv/forgewarden/venv
/srv/forgewarden/venv/bin/python -m pip install --disable-pip-version-check -r requirements-test.txt
HERMES_SWARM_PYTHON=/srv/forgewarden/venv/bin/python bash scripts/validate-swarm.sh --portable
node --test tests/test_console_frontend.js
```

If the selected image/package repositories do not provide a compatible Node version, stop and document the mismatch; do not add an unreviewed third-party package repository. A1 is ARM64, so every installed binary and future container must support `linux/arm64`.

### VM safety state after bootstrap

- Do not install or start a ForgeWarden systemd service yet.
- Do not enable deployment, mutation, automatic pull, automatic merge, provider invocation, or background model work.
- Do not copy API keys, GitHub write tokens, Azure credentials, ChatGPT session material, or the SSH private key onto the VM.
- The initial clone should use public read-only HTTPS. If later work needs GitHub authentication, use a separately approved least-privilege mechanism; do not infer write authority.
- Keep `DRY_RUN` enforced, deployment `DISABLED`, and the kill switch engaged.
- Treat the VM as replaceable. Persistent project truth belongs in GitHub; evidence copied off the VM must remain revision-bound and sanitized.

## Required work sequence for the new chat

1. Re-fetch the canonical GitHub repository and PR status. Confirm whether PR #8 is still open.
2. If PR #8 is open, update the two stale Azure documents on its branch, run the applicable validation, obtain the required exact-commit Daybreak Blue review if available, and merge only when the gate passes.
3. Update this handoff's status claims if GitHub changed. Do not rewrite historical facts.
4. Guide Jeff through the Oracle VM console setup. Stop on paid/ambiguous cost, capacity exhaustion, missing SSH key, or an unexpected security choice.
5. Bootstrap the VM only after it reaches RUNNING and SSH succeeds. Clone the canonical repository read-only and run portable validation.
6. Record the VM architecture, image, shape, region, public/private IP handling, exact Git commit, tests run, results, and any blocker. Do not record private keys or credentials.
7. Keep the live cloud model executor blocked until a separately authorized credits-only provider route exists.

## Non-negotiable authority model

ForgeWarden follows **autonomous security without autonomous authority**.

- Jeff / Customer Root owns activation and authority expansion.
- The trusted Python orchestrator owns deterministic workflow control, policy, paths, hashes, tests, Git operations, evidence, limits, state, cleanup, rollback, and deployment controls.
- Codex is the sole application-code writer inside bounded approved work.
- Daybreak Blue is a read-only exact-commit verifier through the user's signed-in plan/session.
- Model output is untrusted advisory data and never grants authority.
- Deterministic checks outrank model opinions.
- `DRY_RUN` remains enforced; deployment remains disabled; the kill switch remains engaged.
- No Azure reconnection, paid fallback, OpenAI API key, credential exposure, public ForgeWarden service, production activation, or silent verifier substitution is authorized by this handoff.

## Checkpoint report format

At each accepted checkpoint, report:

- exact commit SHA;
- branch and PR status;
- files changed;
- tests/checks run and results;
- exact verifier/provider status;
- VM state and cost eligibility, when relevant;
- completed, active, blocked, and next work.

Stop only for a genuine authority expansion, a paid/ambiguous cloud choice, missing user-session/model access, a required credential or resource the user must provide, a security-sensitive decision, or a blocker that cannot safely be resolved from repository evidence.
