# FW-INTEGRITY clean-checkout reproducibility

## Contract

`validate_clean_checkout` asks Git for a tar archive of one exact commit and
extracts it into a function-owned temporary directory. It accepts only bounded
regular files and directories with safe unique relative paths. Links, special
files, oversized members, missing required entrypoints, runtime/developer state,
and commit mismatch fail before startup validation.

The proof requires the canonical package, safety configuration, invariant,
Mission Control, current product Golden Path, and test entrypoints. Runtime and
proof dependencies must be exactly pinned in the tracked dependency manifest.
Selected packaged source, console, configuration, and policy files are checked
for high-confidence credential material. No credential is resolved or used.

The extracted `swarm` package is compiled and its Core, Mission Control,
Product Integrity, and policy modules are imported from the temporary checkout
with the ambient `PYTHONPATH` removed. Configuration is parsed and must retain
DRY_RUN, disabled deployment, unconfigured credentials, and automatic
deployment disabled. The temporary checkout is removed before the bounded
manifest is returned.

## Limits

This is clean tracked-artifact and local startup proof. It does not install
dependencies, build or publish a distribution, invoke a model/provider, start
a service/listener, install a sensor, execute response or recovery, access a
credential, or establish production readiness. It uses the current Python
environment, so a separate isolated installation proof remains future work.

Run it with:

```text
bash scripts/run-clean-checkout-proof.sh
```
