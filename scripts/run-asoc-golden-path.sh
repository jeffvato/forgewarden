#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"
export PYTHONPATH="$repo_root${PYTHONPATH:+:$PYTHONPATH}"
export DRY_RUN=true
exec python3 -m pytest -q \
  tests/test_asoc.py::test_asoc_canonical_golden_path_uses_policy_broker_gateway_ticket_and_evidence \
  tests/test_asoc.py::test_asoc_golden_path_investigate_then_deny_mutation
