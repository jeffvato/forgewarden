import importlib
from pathlib import Path

from swarm import paths


def test_project_root_is_derived_from_package_location():
    root = paths.project_root()
    assert root == Path(paths.__file__).resolve().parents[1]
    assert (root / "config").is_dir()
    assert (root / "schemas").is_dir()
    assert (root / "swarm").is_dir()


def test_project_root_does_not_depend_on_current_directory(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    reloaded = importlib.reload(paths)
    assert reloaded.project_root() == Path(reloaded.__file__).resolve().parents[1]


def test_configured_external_paths_require_absolute_values(monkeypatch, tmp_path):
    monkeypatch.setenv("HERMES_SWARM_RUNTIME_ROOT", str(tmp_path / "runtime"))
    monkeypatch.setenv("HERMES_SWARM_AUDIT_ROOT", str(tmp_path / "audit"))
    monkeypatch.setenv("HERMES_SWARM_LAUNCHER", str(tmp_path / "bin" / "hermes-swarm"))
    assert paths.runtime_root() == tmp_path / "runtime"
    assert paths.audit_root() == tmp_path / "audit"
    assert paths.audit_path() == tmp_path / "audit" / "audit.jsonl"
    assert paths.launcher_path() == tmp_path / "bin" / "hermes-swarm"

    monkeypatch.setenv("HERMES_SWARM_RUNTIME_ROOT", "relative/runtime")
    try:
        paths.runtime_root()
    except RuntimeError as exc:
        assert "absolute path" in str(exc)
    else:
        raise AssertionError("relative runtime path was accepted")
