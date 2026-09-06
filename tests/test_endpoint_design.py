from pathlib import Path


DESIGN = Path(__file__).parents[1] / "docs" / "fw-endpoint-sensor-contract.md"


def test_windows_linux_sensor_contract_preserves_fixture_only_boundaries():
    text = DESIGN.read_text(encoding="utf-8")
    required = (
        "## Contract boundary",
        "caller-supplied JSON objects only",
        "tenant_id",
        "device_id",
        "DRY_RUN",
        "DETECT_ONLY",
        "## Resource and hostile-input limits",
        "## Fixture and proof plan",
        "must not open paths",
        "quarantine",
        "remediation",
    )
    assert all(marker in text for marker in required)
