import os
import json
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "packaging" / "hermes-swarm"
VALIDATOR = ROOT / "scripts" / "validate-swarm.sh"


def test_launcher_accepts_absolute_external_path_overrides(tmp_path):
    env = os.environ.copy()
    env.update(
        {
            "HERMES_SWARM_RUNTIME_ROOT": str(tmp_path / "runtime"),
            "HERMES_SWARM_AUDIT_ROOT": str(tmp_path / "audit"),
            "HERMES_SWARM_BASELINE_REPOSITORY": str(tmp_path / "baseline"),
        }
    )
    result = subprocess.run(
        ["/bin/bash", str(LAUNCHER), "--help"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "deployment is permanently disabled" in result.stdout.lower()


def test_launcher_rejects_relative_external_path_override(tmp_path):
    env = os.environ.copy()
    env["HERMES_SWARM_RUNTIME_ROOT"] = "relative/runtime"
    result = subprocess.run(
        ["/bin/bash", str(LAUNCHER), "--help"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "must be absolute" in result.stderr


def test_launcher_rejects_unavailable_python_override(tmp_path):
    env = os.environ.copy()
    env["HERMES_SWARM_PYTHON"] = str(tmp_path / "missing-python")
    result = subprocess.run(
        ["/bin/bash", str(LAUNCHER), "--help"],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode != 0
    assert "python executable is unavailable" in result.stderr.lower()


def test_validation_script_rejects_unknown_mode():
    result = subprocess.run(
        ["/bin/bash", str(VALIDATOR), "--unknown"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 2
    assert "unknown mode" in result.stderr


def test_launcher_routes_quality_review_without_runtime_activation(tmp_path):
    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "safe.py").write_text("def ok():\n    return True\n", encoding="utf-8")
    report = tmp_path / "review.json"
    env = os.environ.copy()
    env["HERMES_SWARM_PYTHON"] = sys.executable
    result = subprocess.run(
        ["/bin/bash", str(LAUNCHER), "quality-review", "--repository", str(repository), "--output", str(report)],
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert json.loads(report.read_text(encoding="utf-8"))["mode"] == "READ_ONLY"
