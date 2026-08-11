import json
from pathlib import Path
from tempfile import TemporaryDirectory

from swarm.addon_sdk import scaffold
from swarm.addons import load_manifest, verify_manifest_digest


def test_scaffold_creates_reviewable_least_privilege_addon_package():
    with TemporaryDirectory() as temp:
        package = scaffold(Path(temp) / "inventory-inspector", "inventory-inspector", "1.0.0")
        manifest = load_manifest(package / "manifest.json")
        verify_manifest_digest(manifest)
        assert manifest["entrypoint"] == "addon/main.js"
        assert manifest["permissions"] == {"read": [], "network": False, "shell": False, "git": False, "production": False}
        assert (package / manifest["entrypoint"]).is_file()
        assert json.loads((package / "manifest.json").read_text()) ["signature"]["key_id"] == "forgewarden-local"


def test_scaffold_rejects_unsafe_identity_and_existing_destination():
    with TemporaryDirectory() as temp:
        root = Path(temp)
        for addon_id in ("Bad_Addon", "x"):
            try:
                scaffold(root / addon_id, addon_id, "1.0.0")
            except ValueError:
                pass
            else:
                raise AssertionError("unsafe add-on identity was accepted")
        destination = root / "inventory-inspector"
        scaffold(destination, "inventory-inspector", "1.0.0")
        try:
            scaffold(destination, "inventory-inspector", "1.0.1")
        except ValueError:
            pass
        else:
            raise AssertionError("existing destination was overwritten")
