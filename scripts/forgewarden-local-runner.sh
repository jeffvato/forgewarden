#!/usr/bin/env bash
set -euo pipefail

REPO="/home/jeff/hermes-swarm-phase1"
MAX_ROUNDS="${FORGEWARDEN_MAX_ROUNDS:-100}"
INTERVAL_SECONDS="${FORGEWARDEN_INTERVAL_SECONDS:-1800}"
RUN_ROOT="${FORGEWARDEN_RUN_ROOT:-/tmp/forgewarden-local-runner}"
MASTER_RECORD="docs/Hermes-Codex-Gemini-Swarm-Master-Project-Record.md"

mkdir -p "$RUN_ROOT"
exec 9>"$RUN_ROOT/runner.lock"
if ! flock -n 9; then
    echo "Forgewarden local runner is already active" >&2
    exit 0
fi

cd "$REPO"

status_is_expected() {
    local status
    status="$(git status --porcelain)"
    [[ -z "$status" || "$status" == "?? $MASTER_RECORD" ]]
}

safety_is_expected() {
    local status
    status="$(PYTHONPATH=. python3 -m swarm.cli workflow-status)"
    python3 -c 'import json, sys; value=json.loads(sys.argv[1]); raise SystemExit(0 if value.get("autonomous_dry_run") == "DISABLED" and value.get("deployment") == "DISABLED" and value.get("kill_switch") == "ENGAGED" else 1)' "$status"
}

for ((round=1; round<=MAX_ROUNDS; round++)); do
    status_is_expected || { echo "Unexpected working-tree changes; stopping" >&2; exit 2; }
    safety_is_expected || { echo "Safety markers are not in the required state; stopping" >&2; exit 3; }

    timeout --signal=TERM --kill-after=30s 25m \
        agy --print --mode accept-edits --output-format text --add-dir "$REPO" \
        --prompt "You are the Forgewarden local coding worker. Complete exactly one safe, bounded coding work unit in /home/jeff/hermes-swarm-phase1. Inspect the current git history and tests, choose the next confirmed local bug or hardening task, use TDD where appropriate, run focused and relevant full validators, review the diff, commit, and push to origin/main. Preserve unrelated changes and leave docs/Hermes-Codex-Gemini-Swarm-Master-Project-Record.md untracked. Do not access VPS systems, forgewarden.org, production, services, credentials, or databases. Do not enable autonomous dry-run, clear the kill switch, deploy, restart anything, or modify safety markers. Stop and report if human approval is required. If the completion criteria are met and no safe local work remains, include the exact marker NO_SAFE_WORK_REMAINS in your final response. Do not begin a second work unit." \
        >"$RUN_ROOT/round-${round}.log" 2>&1 || {
            echo "Forgewarden round $round stopped; inspect $RUN_ROOT/round-${round}.log" >&2
            exit 4
        }

    status_is_expected || { echo "Worker left unexpected working-tree changes; stopping" >&2; exit 5; }
    safety_is_expected || { echo "Worker changed safety markers; stopping" >&2; exit 6; }
    if grep -q 'NO_SAFE_WORK_REMAINS' "$RUN_ROOT/round-${round}.log"; then
        echo "Forgewarden reported completion after $round bounded rounds"
        break
    fi
    if (( round == MAX_ROUNDS )); then
        break
    fi
    sleep "$INTERVAL_SECONDS"
done

echo "Forgewarden local runner completed $MAX_ROUNDS bounded rounds"
