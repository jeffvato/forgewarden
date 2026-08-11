from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from swarm.installation import (
    InstallationManifestError,
    build_manifest,
    main,
    promote_install,
    rollback_install,
    stage_install,
    uninstall_preview,
    validate_manifest,
)


def test_manifest_owns_only_regular_files_under_root():
    with TemporaryDirectory() as temp:
        root = Path(temp); file = root / "bin" / "forgewarden"; file.parent.mkdir(); file.write_text("safe\n")
        manifest = build_manifest(root, "0.1.0", [file])
        assert manifest["files"][0]["path"] == "bin/forgewarden"
        assert uninstall_preview(manifest) == [file]


def test_manifest_rejects_home_root_and_escape():
    with TemporaryDirectory() as temp:
        root = Path(temp); file = root / "safe"; file.write_text("safe")
        with pytest.raises(InstallationManifestError):
            build_manifest(Path.home(), "0.1.0", [file])
        manifest = {"manifest_version": 1, "product": "forgewarden", "release": "0.1.0", "install_root": str(root), "files": [{"path": "../outside", "sha256": "0" * 64}]}
        with pytest.raises(InstallationManifestError):
            validate_manifest(manifest)


def test_manifest_rejects_symlink_owned_file():
    with TemporaryDirectory() as temp:
        root = Path(temp); real = root / "real"; link = root / "link"; real.write_text("safe"); link.symlink_to(real)
        with pytest.raises(InstallationManifestError):
            build_manifest(root, "0.1.0", [link])


def test_preview_requires_exact_install_root():
    with TemporaryDirectory() as temp, TemporaryDirectory() as other:
        root = Path(temp); file = root / "owned"; file.write_text("safe")
        manifest = build_manifest(root, "0.1.0", [file])
        with pytest.raises(InstallationManifestError):
            uninstall_preview(manifest, Path(other))


def test_uninstall_requires_explicit_confirmation():
    with TemporaryDirectory() as temp:
        root = Path(temp); file = root / "owned"; file.write_text("safe")
        manifest = build_manifest(root, "0.1.0", [file])
        with pytest.raises(InstallationManifestError):
            from swarm.installation import uninstall
            uninstall(manifest, root)
        assert file.exists()


def test_installer_and_uninstaller_scripts_are_safe_foundations():
    root = Path(__file__).resolve().parents[1]
    assert "stage-install" in (root / "packaging/forgewarden-install").read_text()
    assert "--confirm-uninstall" in (root / "packaging/forgewarden-uninstall").read_text()


def test_stage_install_copies_only_declared_regular_files_and_writes_final_manifest():
    with TemporaryDirectory() as temp:
        temp_root = Path(temp); source = temp_root / "release"; target = temp_root / "install"
        (source / "bin").mkdir(parents=True); (source / "bin" / "forgewarden").write_text("v1\n")
        (source / "ignored").write_text("not shipped\n")
        staged, manifest = stage_install(source, target, "1.0.0", ["bin/forgewarden"])
        assert staged != target
        assert (staged / "bin" / "forgewarden").read_text() == "v1\n"
        assert not (staged / "ignored").exists()
        assert manifest["install_root"] == str(target.resolve())
        assert (staged / ".forgewarden-manifest.json").exists()


def test_promote_install_backs_up_previous_release_and_rollback_restores_it():
    with TemporaryDirectory() as temp:
        temp_root = Path(temp); source = temp_root / "release"; target = temp_root / "install"
        (source / "bin").mkdir(parents=True); (source / "bin" / "forgewarden").write_text("v1\n")
        staged_v1, _ = stage_install(source, target, "1.0.0", ["bin/forgewarden"])
        first = promote_install(staged_v1, target)
        assert first["backup"] is None
        assert (target / "bin" / "forgewarden").read_text() == "v1\n"
        (source / "bin" / "forgewarden").write_text("v2\n")
        staged_v2, _ = stage_install(source, target, "2.0.0", ["bin/forgewarden"])
        second = promote_install(staged_v2, target)
        assert second["backup"]
        assert (target / "bin" / "forgewarden").read_text() == "v2\n"
        rollback_install(Path(second["backup"]), target)
        assert (target / "bin" / "forgewarden").read_text() == "v1\n"


def test_stage_install_rejects_symlink_and_path_escape():
    with TemporaryDirectory() as temp:
        temp_root = Path(temp); source = temp_root / "release"; target = temp_root / "install"
        source.mkdir(); (source / "real").write_text("safe\n"); (source / "link").symlink_to(source / "real")
        with pytest.raises(InstallationManifestError):
            stage_install(source, target, "1.0.0", ["link"])
        with pytest.raises(InstallationManifestError):
            stage_install(source, target, "1.0.0", ["../outside"])


def test_lifecycle_cli_stages_promotes_and_rolls_back_explicitly():
    with TemporaryDirectory() as temp:
        temp_root = Path(temp); source = temp_root / "release"; target = temp_root / "install"
        (source / "bin").mkdir(parents=True); (source / "bin" / "forgewarden").write_text("v1\n")
        assert main(["stage-install", "--source", str(source), "--root", str(target), "--release", "1.0.0", "--file", "bin/forgewarden"]) == 0
        stage = next(temp_root.glob(".forgewarden-stage-*"))
        assert main(["promote", "--stage", str(stage), "--root", str(target)]) == 0
        assert (target / "bin" / "forgewarden").read_text() == "v1\n"


def test_installer_wrapper_exposes_explicit_lifecycle_commands():
    root = Path(__file__).resolve().parents[1]
    script = (root / "packaging/forgewarden-install").read_text()
    assert "stage-install" in script and "promote" in script and "rollback" in script


def test_prerequisite_check_is_an_explicit_cli_command():
    import sys
    assert main(["check-prerequisites", "--tool", sys.executable]) == 0
