# Protected CSV processor onboarding baseline

Status: baseline created; the first controlled repair attempt was blocked by
the complete-tree secret scan before a worktree or agent was started. The
swarm kill switch remains engaged, deployment remains disabled, and
`/home/jeff/n8n` is not in the allowlist.

## Source and independent clone

```text
source repository: /home/jeff/n8n
source HEAD: dd847c7e86ea62369537f46cf887aba799a441fa
requested base: dd847c7e86ea62369537f46cf887aba799a441fa
independent clone: /home/jeff/swarm-repositories/n8n-csv-baseline
baseline commit: 1815f77634a81adfdb0383139f37cd663a951393
```

The initial copy used `--no-local --no-hardlinks --no-shared --no-tags`.
Because a normal clone would retain prohibited blobs in its imported Git
history, the final protected repository is a sanitized single-commit snapshot
of that clone's final tree. The final repository has no source history, no
`objects/info/alternates` file, no shared Git objects, and no prohibited paths
or their historical blobs. A reversible write probe to a clone file left the
source file hash unchanged. The source repository received no Git or
filesystem write.

## Captured tracked changes

The current tracked working-tree diff was captured from the source with:

```bash
git -C /home/jeff/n8n diff --binary dd847c7e86ea62369537f46cf887aba799a441fa -- csv-processor/
```

That diff was applied to the independent clone before the final sanitized
snapshot commit. It contained these 30 paths:

```text
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
```

## Secret scan

The complete sanitized baseline tree was scanned before the controlled
exercise. The scan covered 420 regular files. The initial audit matcher
recorded 47 raw matches; a subsequent read-only calibration using
high-confidence credential formats identified these five filename-only
findings:

```text
docker-compose.yml                  SECRET_OR_PRIVATE_MATERIAL
test_wc_api.py                      SECRET_OR_PRIVATE_MATERIAL
project_context.md                  SECRET_OR_PRIVATE_MATERIAL
vps/docker-compose.vps.yml          SECRET_OR_PRIVATE_MATERIAL
csv-processor/app/templates/content_pipeline.html  SECRET_OR_PRIVATE_MATERIAL
```

The scan therefore blocked the exercise. No credential values were printed or
copied by the onboarding operation. The earlier 31-path scan also found two
test fixtures with embedded username/password-style URLs; both remain
excluded. No `.env`, credential, token, certificate, private material, log,
backup, database, cache, runtime output, customer data, order data, or
distributor data was copied from the original repository.

## Untracked path disposition

`PASS` means the selected file passed the secret scan. `PROTECTED` means the
file is source or test material for a human-required integration. `EXCLUDED`
means it was not copied to the clone.

| Path | Type / purpose | Secret risk | Generated/runtime? | Appears necessary? | Decision |
|---|---|---|---|---|---|
| `csv-processor/alembic/versions/20260715_001_harden_product_videos.py` | Alembic schema migration | High: database | No | Feature-specific | EXCLUDED — migration; Jeff required |
| `csv-processor/app/ai/deadline.py` | Monotonic AI-operation deadline utility | Low | No | Yes; imported by modified AI code | INCLUDED — isolated utility, scan PASS |
| `csv-processor/app/ai/evidence.py` | Supplier/catalog evidence collection | High: database and distributor data | No | Yes for modified AI paths | EXCLUDED — protected data access |
| `csv-processor/app/legacy_video_cleanup.py` | Legacy media cleanup logic | High: destructive production media | No | Feature-specific | EXCLUDED — destructive operation |
| `csv-processor/app/product_media_pilot.py` | Product-media discovery and pilot processing | High: external/media/product data | No | Feature-specific | EXCLUDED — protected integration |
| `csv-processor/app/routers/staging_sync.py` | Staging synchronization API router | High: WooCommerce/staging writes | No | Yes for modified app wiring | EXCLUDED — protected write path |
| `csv-processor/app/scraping/verified_product_media.py` | External product-media scraping | High: external network/product data | No | Feature-specific | EXCLUDED — external integration |
| `csv-processor/app/scripts/cleanup_legacy_product_videos.py` | Cleanup CLI | High: destructive media | No | Feature-specific | EXCLUDED — destructive CLI |
| `csv-processor/app/scripts/dump_seo_for_wp.py` | SEO export | Medium: production/content data | No | Feature-specific | EXCLUDED — production data export |
| `csv-processor/app/scripts/generate_top_keywords.py` | Keyword generation | Medium: production/content data | No | Feature-specific | EXCLUDED — data-processing script |
| `csv-processor/app/scripts/run_product_media_pilot.py` | Media pilot CLI | High: external/product data | No | Feature-specific | EXCLUDED — protected CLI |
| `csv-processor/app/scripts/sync_logos_metadata.py` | Logo metadata synchronization | High: external/media writes | No | Feature-specific | EXCLUDED — protected sync |
| `csv-processor/app/scripts/sync_yoast_indexables.py` | Yoast indexable SQL export/sync | High: database/content data | No | Feature-specific | EXCLUDED — database/data operation |
| `csv-processor/app/scripts/sync_yoast_meta.php` | WordPress SEO metadata sync | High: WooCommerce/WordPress writes | No | Feature-specific | EXCLUDED — protected write path |
| `csv-processor/app/scripts/wincher_sync.py` | Wincher integration | High: external credential/API use | No | Feature-specific | EXCLUDED — protected external API |
| `csv-processor/app/staging_mirror.py` | Staging product mirror | Critical: database/WooCommerce writes | No | Yes for modified app wiring | EXCLUDED — Jeff-required component |
| `csv-processor/app/templates/staging_sync.html` | Staging sync UI | High: exposes protected operation | No | Yes for excluded router | EXCLUDED — protected UI |
| `csv-processor/scripts/run_legacy_video_cleanup_stage1.sh` | Cleanup host script | Critical: destructive shell operation | No | Feature-specific | EXCLUDED — destructive host script |
| `csv-processor/scripts/run_product_media_pilot.sh` | Media pilot host script | High: external/product operation | No | Feature-specific | EXCLUDED — operational script |
| `csv-processor/scripts/transfer_media_quarantine.sh` | Media quarantine transfer | Critical: file/data transfer | No | Feature-specific | EXCLUDED — production data operation |
| `csv-processor/scripts/transfer_product_media_review.sh` | Product-media review transfer | High: product-data transfer | No | Feature-specific | EXCLUDED — production data operation |
| `csv-processor/tests/test_ai_dashboard_controls.py` | AI dashboard regression tests | Low; fixture URLs only | No | Yes as tests | INCLUDED — tests scope, scan PASS |
| `csv-processor/tests/test_ai_watcher_deadline.py` | AI watcher deadline tests | Low; mocked endpoints only | No | Yes as tests | INCLUDED — tests scope, scan PASS |
| `csv-processor/tests/test_content_pipeline_watcher_pause.py` | Watcher lifecycle tests | Low; mocks only | No | Yes as tests | INCLUDED — tests scope, scan PASS |
| `csv-processor/tests/test_content_pipeline_yoast_seo.py` | SEO transformation tests | Medium: content path | No | Yes as tests | INCLUDED — tests scope; implementation remains protected |
| `csv-processor/tests/test_legacy_video_cleanup.py` | Cleanup safety tests | High: tests protected cleanup | No | Yes as tests | INCLUDED — tests only; no cleanup authorization |
| `csv-processor/tests/test_product_evidence.py` | Evidence collection tests | High: database/catalog path | No | Yes as tests | INCLUDED — tests only; no data access authorization |
| `csv-processor/tests/test_product_media_pilot.py` | Media pilot tests | High: product/external path | No | Yes as tests | INCLUDED — tests only; no pilot authorization |
| `csv-processor/tests/test_product_media_pilot_host_script.py` | Host-script syntax tests | High: operational script | No | Yes as tests | INCLUDED — syntax test only; no script execution |
| `csv-processor/tests/test_staging_mirror_safety.py` | Staging mirror safety tests | High: database/WooCommerce path | No | Yes as tests | EXCLUDED — embedded authenticated fixture URL; protected |
| `csv-processor/tests/test_verified_product_media.py` | External media validation tests | High: external network path | No | Yes as tests | EXCLUDED — embedded authenticated fixture URL; protected |

The included tests are not permission to modify or execute the protected
components they cover. The two excluded tests remain available in the source
repository for Jeff's later reviewed handling; they were not copied.

## Initial allowlist and protected scope

The committed swarm profile now contains exactly one repository root:

```text
/home/jeff/swarm-repositories/n8n-csv-baseline
```

`/home/jeff/n8n` is absent. The eligible scope is limited to:

```text
/home/jeff/swarm-repositories/n8n-csv-baseline/csv-processor/app/ai/deadline.py
/home/jeff/swarm-repositories/n8n-csv-baseline/csv-processor/tests/swarm_regressions/
```

Every existing test is read-only. All other source and configuration are
read-only. The diff gate rejects existing-test mutations or deletions,
out-of-scope changes, escaping renames, symlinks, traversal paths, test
skipping or xfail, unconditional-success tests, and assertion removal.

The following remain human-required even inside the clone: database,
migrations, pricing, MAP, checkout, payments, orders, WooCommerce writes,
distributor APIs, GunBroker writes, credentials, security middleware, Docker,
deployment, FFL rules, state restrictions, and NFA filtering.

## Discovered test and build commands

These commands were discovered from repository metadata and documentation. No
repair job, Docker command, migration, build, or production-facing test was
run for this baseline:

```text
cd csv-processor && pytest -q
cd csv-processor && python -m pytest -q <selected test>
cd csv-processor && alembic <command>                 # schema-changing; Jeff required
cd projects/ffl-flow/backend && npm start             # outside eligible scope
cd projects/ffl-flow/backend && npm run sync          # outside eligible scope
cd wordpress-plugins/mcp-adapter && npm test           # outside eligible scope
cd wordpress-plugins/mcp-adapter && composer test     # outside eligible scope
docker compose ...                                     # never run by this onboarding
```

The initial baseline is a protected snapshot, not a claim that all tests are
currently runnable in this WSL shell.

## Rollback / deletion

If Jeff rejects this baseline, stop the swarm and verify the target path before
removing only the independent clone. This command is documented, not executed:

```bash
/home/jeff/.local/bin/hermes-swarm kill-switch
test "$(git -C /home/jeff/swarm-repositories/n8n-csv-baseline rev-parse --show-toplevel)" = "/home/jeff/swarm-repositories/n8n-csv-baseline"
rm -rf -- /home/jeff/swarm-repositories/n8n-csv-baseline
```

This does not remove or roll back anything under `/home/jeff/n8n`.
