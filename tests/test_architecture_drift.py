from pathlib import Path
import pytest
from swarm.architecture_drift import ArchitectureDriftError, find_provider_bypasses, validate_repository

ROOT = Path(__file__).resolve().parents[1]

def test_repository_has_no_direct_provider_bypasses():
    assert find_provider_bypasses(ROOT) == ()
    validate_repository(ROOT)

def test_provider_bypass_is_detected_outside_adapter_allowlist(tmp_path):
    (tmp_path / "swarm").mkdir()
    (tmp_path / "swarm" / "unsafe.py").write_text("import openai\n", encoding="utf-8")
    with pytest.raises(ArchitectureDriftError):
        validate_repository(tmp_path)

def test_ci_entrypoint_is_present():
    assert (ROOT / 'scripts' / 'validate-architecture-drift.py').is_file()

