from pathlib import Path


DESIGN = Path(__file__).parents[1] / "docs" / "fw-endpoint-sensor-adapter-contract.md"


def test_sensor_adapter_contract_is_design_only_and_uses_canonical_owner():
    text = DESIGN.read_text(encoding="utf-8")
    required = (
        "# FW-ENDPOINT-05",
        "design-and-test contract only",
        "NormalizedEventStore.admit_fixture",
        "WINDOWS_SENSOR",
        "LINUX_SENSOR",
        "tenant_id",
        "device_id",
        "DRY_RUN",
        "DETECT_ONLY",
        "must not call platform APIs",
        "filesystem/process monitoring",
        "network collection",
        "quarantine",
        "remediation",
        "separate implementation ticket",
    )
    assert all(marker in text for marker in required)
