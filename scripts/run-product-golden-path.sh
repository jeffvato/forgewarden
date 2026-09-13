#!/usr/bin/env bash
set -euo pipefail

repository="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository"
PYTHONPATH=. python3 -m pytest -q -s tests/test_product_golden_path.py
