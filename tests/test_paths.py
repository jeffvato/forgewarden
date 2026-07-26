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
