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
    validation_root="${TMPDIR:-/tmp}/hermes-swarm-validation-$$"
    export HERMES_SWARM_RUNTIME_ROOT="${HERMES_SWARM_RUNTIME_ROOT:-$validation_root/runtime}"
    export HERMES_SWARM_AUDIT_ROOT="${HERMES_SWARM_AUDIT_ROOT:-$validation_root/audit}"
    bash -n "$ROOT/packaging/hermes-swarm"
    bash -n "$ROOT/packaging/hermes-swarm-mcp"
    exec env PYTHONPATH="$ROOT" "$PYTHON" -m pytest -q \
      "$ROOT/tests/test_swarm.py" \
      "$ROOT/tests/test_codex_telemetry.py" \
      "$ROOT/tests/test_environment_safety.py" \
      "$ROOT/tests/test_gemini_reviewer.py" \
      "$ROOT/tests/test_packaging.py" \
      "$ROOT/tests/test_paths.py" \
      "$ROOT/tests/test_quality_review.py" \
      "$ROOT/tests/test_repository_hygiene.py" \
      "$ROOT/tests/test_systemd_scope.py::SystemdScopeSafetyTests" \
      "$ROOT/tests/test_systemd_unit.py" \
      "$ROOT/tests/test_phase2b_profiles.py" \
      "$ROOT/tests/test_phase2b_console_profile.py" \
      "$ROOT/tests/test_phase2b_admission.py" \
      "$ROOT/tests/test_phase2b_candidate_b_design.py" \
      "$ROOT/tests/test_phase2b_audit_review_profile.py" \
      "$ROOT/tests/test_phase3_deployment_design.py" \
      "$ROOT/tests/test_phase3_fake_deployment.py" \
      "$ROOT/tests/test_phase3_deployment_executor.py" \
      "$ROOT/tests/test_phase3_staging_fixture.py" \
      "$ROOT/tests/test_phase4_unattended_design.py" \
      "$ROOT/tests/test_phase4_fake_unattended.py" \
      "$ROOT/tests/test_phase5_release_readiness.py" \
      "$ROOT/tests/test_phase5_release_audit.py" \
      "$ROOT/tests/test_addon_sdk.py" \
      "$ROOT/tests/test_addons.py" \
      "$ROOT/tests/test_installation.py" \
      "$ROOT/tests/test_prerequisites.py" \
      "$ROOT/tests/test_install_smoke.py" \
      "$ROOT/tests/test_harness_models.py" \
      "$ROOT/tests/test_harness_spend.py" \
      "$ROOT/tests/test_harness_cloud_plan.py" \
      "$ROOT/tests/test_console.py" \
      "$ROOT/tests/test_addon_catalog.py"
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
