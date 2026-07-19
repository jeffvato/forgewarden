# Final v2 deterministic environment proof

Result: **STOPPED at the unchanged-baseline test gate.**

The runner now configures deterministic pytest with the same project working
directory, argument array, and minimal environment that a future authorized
repair would use. No repair authorization was consumed.

## Configuration proved

For a temporary worktree rooted at `<worktree>`:

```text
working directory: <worktree>/csv-processor
argument array: [<resolved-python-executable>, -m, pytest, -q, -p, no:cacheprovider, tests/swarm_regressions/test_deadline_contract.py]
PYTHONDONTWRITEBYTECODE=1
PYTHONNOUSERSITE=1
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1
network: blocked by the repair runner's systemd scope
```

The environment is constructed from an explicit allowlist containing only
`PATH`, `HOME`, `LANG`, and `LC_ALL` when present, plus the deterministic
Python variables above. Proxy variables are removed. Production, database,
credential, token, customer, order, WooCommerce, distributor, Docker, and
unrelated environment variables are not passed.

## Disposable baseline proof

The temporary worktree was created from exactly:

```text
9cf4d5933b5563fe079e17ccdd8d33b8169de2db
```

The resolved Python executable was `/home/jeff/anaconda3/bin/python3`. The
unchanged test command reached pytest successfully, proving the import path
correction, but the baseline test itself failed:

```text
1 failed, 1 passed
app.ai.deadline.ProductDeadlineExceeded: Product deadline exhausted before product processing
```

The failure occurs while entering `product_deadline(0)` in
`test_expired_deadline_is_authoritative`, before that test’s inner exception
handler. The baseline was not changed to compensate. Because the unchanged
baseline did not pass, no defect was introduced, the kill switch was not
cleared, and Codex and Gemini were not invoked.

The worktree was removed afterward. No `__pycache__`, `.pyc`, pytest cache,
log, or source file was written to the baseline repository. The v2 baseline
remains clean at the exact SHA above.

## Tests and changes

The process-level integration test creates the same disposable layout and
executes real pytest using the corrected command. The complete swarm test
suite passes: **28 tests passed**.

Changed and committed only in the swarm repository:

- `swarm/adapters.py`: explicit minimal deterministic test environment.
- `swarm/baseline.py`: project working directory and exact pytest argument
  array, including cache suppression and bytecode policy.
- `tests/test_baseline.py`: real process-level pytest proof and preflight
  coverage.
- this documentation.

## Safety state

- Kill switch: **ENGAGED**.
- Deployment: **DISABLED**.
- Codex: not invoked.
- agy/Gemini: not invoked.
- v2 baseline: unchanged.
- Old baseline, `/home/jeff/n8n`, Docker, and production: untouched.

The baseline test must be corrected through a separately authorized,
human-reviewed baseline change before any future repair exercise can pass
this gate. No further exercise was attempted.
