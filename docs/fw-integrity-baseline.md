# FW-INTEGRITY baseline — 2026-08-28

Known-good checkpoint assessed: `45daee019fb3c8ad15bbb9142d4613a5d9816266`.

## Actual baseline

- The checkout builds as Python source and imports its Core, console, ASOC, and
  integrity modules.
- The full suite currently collects 532 tests. The latest full run was **531
  passed, 1 skipped**. The skip is the explicit real Hermes lifecycle test;
  that diagnostic was separately run and passed with **3 tests passed**.
- The first current-product Golden Path is the existing Core dry-run/review
  chain represented by `tests/test_swarm.py`, `tests/test_phase2a.py`,
  `tests/test_phase2b_profiles.py`, and `tests/test_console.py`: **70 passed**.
- There is no package metadata or lockfile in this checkout. Imports currently
  rely on the repository being on `PYTHONPATH`.
- `pip check` reports missing `tzdata` for installed Oslo packages. This is a
  dependency-environment warning and remains an integrity risk until the
  environment is reproducibly declared.
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
