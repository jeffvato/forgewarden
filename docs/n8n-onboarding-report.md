# n8n repository onboarding report

Status: inspection only. The repository was not added to the swarm allowlist,
no repair job was started, the kill switch remains engaged, and deployment
remains disabled.

## Repository identity and working state

The inspected Git root is `/home/jeff/n8n`.

```text
branch: main
HEAD: dd847c7e86ea62369537f46cf887aba799a441fa
modified tracked paths: 36
untracked, non-ignored paths: 3429
ignored paths: 2524
```

The modified tracked paths are:

```text
.gitignore
backup-db.sh
csv-processor/app/ai/client.py
csv-processor/app/ai/descriptions.py
csv-processor/app/ai/overnight.py
csv-processor/app/ai/prompt_store.py
csv-processor/app/ai/prompts.py
csv-processor/app/bulk_sync.py
csv-processor/app/content_pipeline.py
csv-processor/app/gunbroker_sync.py
csv-processor/app/main.py
csv-processor/app/routers/ai.py
csv-processor/app/routers/content_pipeline.py
csv-processor/app/routers/manufacturer_logos.py
csv-processor/app/routers/map_management.py
csv-processor/app/routers/suppliers.py
csv-processor/app/scripts/fix_missing_descriptions.py
csv-processor/app/security.py
csv-processor/app/supplier_interface.py
csv-processor/app/templates/_sidebar.html
csv-processor/app/templates/ai.html
csv-processor/app/templates/index.html
csv-processor/app/templates/manufacturer_logos.html
csv-processor/app/templates/map_management.html
csv-processor/app/wc_image_sync.py
csv-processor/tests/test_background_worker_lifecycle.py
csv-processor/tests/test_content_pipeline_model_selection.py
csv-processor/tests/test_description_prompts.py
csv-processor/tests/test_manufacturer_logo_api.py
csv-processor/tests/test_provider_chain_status.py
csv-processor/tests/test_security_middleware.py
csv-processor/tests/test_supplier_images.py
docker-compose.yml
project_context.md
searxng/settings.yml
vps/docker-compose.vps.yml
```

The 3429 untracked paths are dominated by `.agents/skills` (3369 paths).
Other untracked groups include 31 `csv-processor` paths, 22 paths under the
untracked `hermes-swarm-phase1` directory, two `scripts` paths, one `vps`
path, `top_keywords_rank.csv`, `skills-lock.json`,
`phase1-inventory.md`, and `NVIDIA_SKILLS_IMPLEMENTATION_PLAN.md`. The full
read-only enumeration command is:

```bash
git -C /home/jeff/n8n ls-files --others --exclude-standard
```

No untracked path was staged, changed, or otherwise modified.

## Ignored sensitive and configuration paths

Contents were not displayed. The read-only inventory identified these path
classes and examples:

| Classification | Filename/path examples |
|---|---|
| Credentials and tokens | `.env`, `.hermes/secrets/telegram_token`, `workflows/mcp-credentials.json`, `workflows/mcp-bearer-token-cred.json`, `workflows/mcp-http-bearer-token-cred.json` |
| TLS/private material | `csv-processor/app/certs/gas-network-solutions-rsa-dv-ssl-ca-4.pem` |
| Database/backups | `backups/*.sql.gz`, `backups/*.tar.gz`, `backup.log`, `backups/backup.log` |
| Runtime logs | `logs/`, `.hermes/logs/agent.log` |
| Deployment/configuration | `docker-compose*.yml`, `vps/docker-compose.vps.yml`, `searxng/settings.yml` |
| Generated/cache data | `__pycache__/`, ignored worktrees under `.hermes/workspace/`, `node_modules/` |

The ignored-path count is 2524. These paths must remain excluded from any
future onboarding snapshot unless Jeff separately approves a reviewed,
redacted inventory.

## Subrepositories

The following nested Git repositories were found by metadata inspection:

| Path | Branch | HEAD | Current state |
|---|---|---|---|
| `/home/jeff/n8n/e4473` | `master` | `a5cdd091eb8e4d100c970419ac9f3072e7be7f07` | modified and deleted tracked paths |
| `/home/jeff/n8n/.hermes/workspace` | `main` | `dd847c7e86ea62369537f46cf887aba799a441fa` | reflects the parent working tree; not an onboarding target |

The parent repository itself is the only inspected candidate. Neither nested
repository was added to the swarm allowlist.

## Components and risk classification

| Component/path family | Evidence found | Recommended classification |
|---|---|---|
| `docker-compose*.yml`, Dockerfiles, `vps/`, `vps-deploy/` | Container definitions, service wiring, VPS deployment files | SECURITY / DEPLOYMENT — Jeff required |
| `csv-processor/app/database.py`, `alembic/`, `*_migrate.sql` | SQLAlchemy/PostgreSQL access and schema migrations | DATABASE / DATA — Jeff required |
| `csv-processor/app/pricing.py`, `gunbroker_pricing.py`, `routers/pricing.py`, `routers/map_prices.py`, `map-price-protection` | Pricing, MAP, and price-protection paths | PRICING — Jeff required |
| `csv-processor/app/ordering.py`, `routers/orders.py`, `routers/order_management.py`, order templates/tests | Order creation and order management | ORDERS / CHECKOUT — Jeff required |
| `csv-processor/app/woocommerce.py`, `projects/ffl-flow/backend/woo.js`, Woo templates/plugins | WooCommerce API and product synchronization | CHECKOUT / EXTERNAL DATA — Jeff required |
| `csv-processor/app/supplier_interface.py`, `suppliers.py`, `projects/ffl-flow/backend/distributors/`, `gunbroker_sync.py` | Supplier/distributor/GunBroker integrations | DISTRIBUTOR / EXTERNAL SYSTEM — Jeff required |
| `csv-processor/app/security.py`, `app/ai/`, `workflows/`, `.env*`, credential-named paths | Security middleware, AI providers, workflow credentials/configuration | SECURITY / GOVERNANCE — Jeff required |
| `workflows/`, n8n service definitions, MCP setup files | n8n workflows and MCP integrations | GOVERNANCE / PRODUCTION AUTOMATION — Jeff required |
| `vps-analytics/`, `pypos/`, `e4473/` | Additional applications with database, Docker, or service code | DATA / DEPLOYMENT — Jeff required |
| `csv-processor/tests/`, Python utility modules without the above integrations | Deterministic tests and isolated utility logic | LOW only after separate review; default MEDIUM |

Because the working tree is dirty and the repository contains production-facing
integrations, no component is currently eligible for automatic repair.

## Test and build command inventory

The repository metadata and documentation identify these commands. They were
not run against n8n during this inspection:

```text
csv-processor: pytest (the documented host environment may lack dependencies)
csv-processor: python -m pytest -q <selected test paths>
csv-processor migrations: alembic commands (schema-changing; Jeff required)
FFL Flow backend: npm start; npm run sync
wordpress-plugins/mcp-adapter: npm test; composer test; composer lint; composer phpstan
stack operations: docker compose ps/up/down/logs/restart/build
POS stack: docker compose -f docker-compose.pos.yml build/up
```

No Docker command, test command, build command, migration, or service action
was executed. The commands above are inventory only; production-affecting
commands remain outside the dry-run onboarding scope.

## Baseline decision still required

The current uncommitted state cannot be silently included in a repair baseline.
It contains 36 modified tracked paths, 3429 untracked paths, and nested
repository changes. A repair against `HEAD` would omit those changes from the
baseline and could produce a misleading diff; a repair against the working
tree would make user-owned changes part of the agent's input without a
reviewed boundary.

Safe alternatives, presented without selecting one:

1. Use committed `HEAD` only, with explicit acknowledgement that all working
   tree changes are excluded.
2. Create a reviewed checkpoint commit containing the intended current changes.
3. Create a separate protected snapshot branch after reviewing exactly what it
   contains.
4. Onboard only a clean subrepository after independently reviewing its root,
   branch, status, allowlist, and production boundaries.

Jeff must select and approve the baseline. Until then, `/home/jeff/n8n` must
remain absent from the repository allowlist and the kill switch must remain
engaged.

## Durable audit readiness

The swarm implementation now targets `/home/jeff/hermes-swarm-audit` for
durable audit records, separate from disposable runtime directories. The
directory is intended to be `0700` and `audit.jsonl` `0600`. Records retain
job IDs, UTC timestamps, state transitions, commit SHAs, deterministic-check
results, reviewer decisions, resource limits, and learned-rule decisions.
Full model payloads, prompts, command output, credentials, tokens, customer
data, order data, and distributor secrets are not recorded; sensitive fields
are redacted or omitted.

The implementation includes a test that removes the disposable runtime while
asserting the durable audit remains and is permission-restricted. Installation
of the durable root and launcher update is a separate filesystem action; it
does not authorize repairs and must leave the kill switch engaged.
