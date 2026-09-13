from __future__ import annotations

import re
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_ROOT = ROOT / ".github" / "workflows"
VALIDATION = WORKFLOW_ROOT / "swarm-validation.yml"
ACTION_REF = re.compile(r"^[^\s@]+@[0-9a-f]{40}$")


def load_workflow(path: Path) -> dict:
    value = yaml.load(path.read_text(encoding="utf-8"), Loader=yaml.BaseLoader)
    assert isinstance(value, dict), f"{path} is not a workflow mapping"
    return value


def test_all_external_actions_are_immutable_commit_pins():
    workflows = sorted(WORKFLOW_ROOT.glob("*.yml"))
    assert workflows
    for path in workflows:
        workflow = load_workflow(path)
        for job in workflow.get("jobs", {}).values():
            for step in job.get("steps", []):
                action = step.get("uses")
                if action is not None:
                    assert ACTION_REF.fullmatch(action), f"{path}: mutable action reference {action!r}"


def test_validation_workflow_is_read_only_and_cannot_persist_checkout_credentials():
    workflow = load_workflow(VALIDATION)
    assert workflow["permissions"] == {"contents": "read"}
    for job_name, job in workflow["jobs"].items():
        permissions = job.get("permissions", workflow["permissions"])
        assert permissions.get("contents") == "read"
        assert "write" not in permissions.values(), job_name
        for step in job["steps"]:
            if step.get("uses", "").startswith("actions/checkout@"):
                assert step.get("with", {}).get("persist-credentials") == "false"


def test_validation_workflow_has_bounded_jobs_commands_and_cancellation():
    workflow = load_workflow(VALIDATION)
    assert workflow["concurrency"]["cancel-in-progress"] == "true"
    assert workflow["concurrency"]["group"]
    for job_name, job in workflow["jobs"].items():
        timeout = int(job["timeout-minutes"])
        assert 1 <= timeout <= 30, job_name
        for step in job["steps"]:
            command = step.get("run")
            bounded_markers = ("python -m pip", "python -m pytest", "node --test", "python -m swarm.cli")
            if command and any(marker in command for marker in bounded_markers):
                assert "timeout " in command, f"{job_name}/{step.get('name')} is unbounded"


def test_validation_runs_current_required_local_proofs():
    text = VALIDATION.read_text(encoding="utf-8")
    required = (
        "bash scripts/validate-swarm.sh --portable",
        "python -m pytest -q",
        "node --test tests/test_console_frontend.js",
        "git diff --check HEAD",
        "python -m swarm.cli quality-review",
        "python -m swarm.cli codebase-index-build",
        "python -m swarm.cli index-evidence",
    )
    for command in required:
        assert command in text


def test_pull_request_workflows_do_not_receive_write_permissions():
    for path in sorted(WORKFLOW_ROOT.glob("*.yml")):
        workflow = load_workflow(path)
        if "pull_request" not in workflow.get("on", {}):
            continue
        inherited = workflow.get("permissions", {})
        for job_name, job in workflow.get("jobs", {}).items():
            permissions = job.get("permissions", inherited)
            assert "write" not in permissions.values(), f"{path}/{job_name}"
