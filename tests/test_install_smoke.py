from swarm.install_smoke import run_clean_install_smoke


def test_clean_install_smoke_is_disposable_and_completes_lifecycle():
    result = run_clean_install_smoke()
    assert result["environment"] == "DISPOSABLE_TEMPORARY_DIRECTORY"
    assert result["steps"] == ["STAGE", "PROMOTE", "CONFIRMED_UNINSTALL"]
    assert result["release"] == "1.0.0"
    assert result["removed_files"] == 1
    assert result["cleaned"] is True
    assert result["deployment"] == "DISABLED"
