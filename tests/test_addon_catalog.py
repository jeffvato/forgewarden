import json
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from swarm.addon_catalog import admit_package, write_catalog
from swarm.addon_sdk import scaffold
from swarm.addons import AddonManifestError


def test_catalog_admission_requires_digest_and_allowlisted_publisher():
    with TemporaryDirectory() as temp:
        package = scaffold(Path(temp) / "inventory-inspector", "inventory-inspector", "1.0.0")
        entry = admit_package(package, {"Forgewarden Builder"})
        assert entry["id"] == "inventory-inspector"
        assert entry["publisher"] == "Forgewarden Builder"
        with pytest.raises(AddonManifestError):
            admit_package(package, {"Someone Else"})


def test_catalog_is_local_sorted_and_rejects_duplicate_ids():
    with TemporaryDirectory() as temp:
        root = Path(temp); first = scaffold(root / "first", "first-addon", "1.0.0"); second = scaffold(root / "second", "second-addon", "1.0.0")
        catalog = write_catalog(root / "catalog.json", [second, first], {"Forgewarden Builder"})
        assert [entry["id"] for entry in catalog["addons"]] == ["first-addon", "second-addon"]
        assert json.loads((root / "catalog.json").read_text())["catalog_version"] == 1
