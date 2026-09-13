#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository"
PYTHONPATH=. python3 -m pytest -q -s tests/test_clean_checkout.py
