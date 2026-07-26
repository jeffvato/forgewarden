#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
ROOT="$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd -P)"
PYTHON="${HERMES_SWARM_PYTHON:-python3}"

if ! command -v "$PYTHON" >/dev/null 2>&1 && ! test -x "$PYTHON"; then
  echo "validate-swarm: configured Python executable is unavailable" >&2
  exit 1
fi

usage() {
  cat <<'EOF'
Usage: validate-swarm.sh [--portable|--full]

  --portable  shell checks and fixture-only tests suitable for CI
  --full      all local tests, including pinned WSL integration diagnostics
EOF
}

case "${1:---portable}" in
  --portable)
    bash -n "$ROOT/packaging/hermes-swarm"
    bash -n "$ROOT/packaging/hermes-swarm-mcp"
    exec env PYTHONPATH="$ROOT" "$PYTHON" -m pytest -q \
      "$ROOT/tests/test_swarm.py" \
      "$ROOT/tests/test_codex_telemetry.py" \
      "$ROOT/tests/test_environment_safety.py" \
      "$ROOT/tests/test_gemini_reviewer.py" \
      "$ROOT/tests/test_packaging.py" \
      "$ROOT/tests/test_paths.py" \
      "$ROOT/tests/test_repository_hygiene.py" \
      "$ROOT/tests/test_systemd_scope.py" \
      "$ROOT/tests/test_systemd_unit.py"
    ;;
  --full)
    exec env PYTHONPATH="$ROOT" "$PYTHON" -m unittest discover -s "$ROOT/tests" -q
    ;;
  -h|--help)
    usage
    ;;
  *)
    echo "validate-swarm: unknown mode: $1" >&2
    usage >&2
    exit 2
    ;;
esac
