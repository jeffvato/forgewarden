# FW-INTEGRITY baseline — 2026-08-28

Known-good checkpoint assessed: `45daee019fb3c8ad15bbb9142d4613a5d9816266`.

## Actual baseline

- The checkout builds as Python source and imports its Core, console, ASOC, and
  integrity modules.
- The full suite currently collects 544 tests. The latest full run was **543
  passed, 1 skipped**. The skipped test is the host-dependent Codex process
  adapter check, which requires a user systemd bus unavailable in the current
  execution context. The explicit real Hermes MCP lifecycle diagnostic was
  separately enabled and passed with **3 tests passed**.
- The first current-product Golden Path is the existing Core dry-run/review
  chain represented by `tests/test_swarm.py`, `tests/test_phase2a.py`,
  `tests/test_phase2b_profiles.py`, and `tests/test_console.py`: **70 passed**.
- There is no package metadata or lockfile in this checkout. Imports currently
  rely on the repository being on `PYTHONPATH`.
- The OS-managed Python reports missing `tzdata` for installed Oslo packages.
  This is a local-environment warning, not a repository dependency omission:
  on 2026-08-30, a new isolated environment installed the pinned
  `requirements-test.txt`, passed `pip check`, and passed the full suite.
- `requirements-test.txt` pins the deterministic test dependencies and both CI
  workflows install from it; the repository does not mutate the local OS
  environment.
- The roadmap and decisions name FW-ID, FW-ROOT/Z3, FW-EVID, FW-SOC, FW-COMP,
  Model Broker, MCP Gateway, and Action Tickets, but several have no concrete
  module in this checkout. They are recorded as Defined or Integration Pending,
  not falsely marked Proven.
- `swarm.core.AuditLog` is the canonical audit primitive. `swarm.asoc` accepts
  an audit sink and does not create a competing persistence format.

## Gate and map

`swarm.integrity.run_product_integrity_gate` checks Git cleanliness, Python
build/import startup, configuration parsing, tests, an explicit Golden Path,
dependency health, and missing canonical ownership implementations. The gate
returns GREEN/YELLOW/RED evidence and includes the exact commit in the
functionality map.

Operators can run it directly with `PYTHONPATH=. python3 -m swarm.cli
integrity-gate --repository . --golden-command "python3 -m pytest -q
tests/test_swarm.py"`. Use `--output` to save the structured report.

`swarm.integrity.CANONICAL_OWNERSHIP` is the ownership registry. The
Defined/Implemented/Integrated/Proven map is exposed as `FUNCTIONALITY_MAP` and
updated at each meaningful checkpoint.

## Current health

**YELLOW — functioning but with product-integrity risk.** Core behavior and
the representative Golden Path are healthy. Dependency reproducibility,
packaging, several roadmap primitives, and full cross-family integration are
not yet Proven.

The next consolidation work should close dependency reproducibility and wire
FW-ASOC-01 through real Model Broker, MCP Gateway, Action Ticket, Evidence,
and canonical identity/policy owners before FW-ASOC-01 is called Proven.
