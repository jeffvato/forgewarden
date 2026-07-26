import os
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "packaging" / "hermes-swarm"


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
