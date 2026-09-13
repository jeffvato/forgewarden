"""Clean tracked-commit proof and fail-closed archive boundaries."""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from swarm.integrity import _clean_archive_name, validate_clean_checkout


ROOT = Path(__file__).parents[1]


def _head(root: Path) -> str:
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, text=True, capture_output=True, check=True).stdout.strip()


def _clone(tmp_path: Path) -> Path:
    target = tmp_path / "fixture"
    subprocess.run(["git", "clone", "-q", "--no-hardlinks", str(ROOT), str(target)], check=True)
    subprocess.run(["git", "config", "user.name", "ForgeWarden Test"], cwd=target, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.invalid"], cwd=target, check=True)
    return target


def _commit(root: Path, message: str) -> str:
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)
    subprocess.run(["git", "commit", "-qm", message], cwd=root, check=True)
    return _head(root)


def test_clean_checkout_proves_exact_tracked_commit_and_removes_temporary_state() -> None:
    report = validate_clean_checkout(ROOT, _head(ROOT))
    assert report["proof"] == "CLEAN_TRACKED_COMMIT"
    assert report["build"] == "PASS" and report["startup"] == "PASS"
    assert report["temporary_checkout_removed"] is True
    assert report["mode"] == "DRY_RUN" and report["deployment"] == "DISABLED"
    assert report["kill_switch"] == "ENGAGED"
    assert report["live_enabled"] is False and report["production_ready"] is False
    assert report["authority_granted"] is False
    print("FW_CLEAN_CHECKOUT=" + json.dumps(report, sort_keys=True, separators=(",", ":")))


def test_clean_checkout_rejects_current_commit_mismatch() -> None:
    with pytest.raises(ValueError, match="current commit mismatch"):
        validate_clean_checkout(ROOT, "0" * 40)


@pytest.mark.parametrize("name", ["../escape", "/absolute", "folder\\windows"])
def test_clean_checkout_rejects_unsafe_archive_paths(name: str) -> None:
    with pytest.raises(ValueError, match="unsafe|malformed"):
        _clean_archive_name(name)


def test_clean_checkout_rejects_missing_required_tracked_artifact(tmp_path: Path) -> None:
    fixture = _clone(tmp_path)
    (fixture / "console/app.js").unlink()
    commit = _commit(fixture, "remove required artifact")
    with pytest.raises(ValueError, match="missing required tracked artifacts"):
        validate_clean_checkout(fixture, commit)


def test_clean_checkout_rejects_tracked_symlink(tmp_path: Path) -> None:
    fixture = _clone(tmp_path)
    os.symlink("core.py", fixture / "swarm/unsafe-link.py")
    commit = _commit(fixture, "add unsafe link")
    with pytest.raises(ValueError, match="link or special file"):
        validate_clean_checkout(fixture, commit)


def test_clean_checkout_rejects_secret_bearing_packaged_content(tmp_path: Path) -> None:
    fixture = _clone(tmp_path)
    with (fixture / "config/readiness.yaml").open("a", encoding="utf-8") as handle:
        handle.write("\nexternal_api_key: 'sk-abcdefghijklmnopqrstuvwxyz123456'\n")
    commit = _commit(fixture, "add unsafe secret fixture")
    with pytest.raises(ValueError, match="secret-bearing"):
        validate_clean_checkout(fixture, commit)


def test_clean_checkout_rejects_undeclared_proof_dependency(tmp_path: Path) -> None:
    fixture = _clone(tmp_path)
    requirements = fixture / "requirements-test.txt"
    requirements.write_text(
        "\n".join(line for line in requirements.read_text(encoding="utf-8").splitlines() if not line.lower().startswith("pyyaml==")) + "\n",
        encoding="utf-8",
    )
    commit = _commit(fixture, "remove required dependency declaration")
    with pytest.raises(ValueError, match="dependency is undeclared"):
        validate_clean_checkout(fixture, commit)
