import sys

from swarm.prerequisites import inspect_prerequisites, require_prerequisites


def test_prerequisite_inspection_reports_python_and_available_tool():
    report = inspect_prerequisites([sys.executable])
    assert report["python"]["ok"] is True
    assert report["tools"][sys.executable]["ok"] is True


def test_required_prerequisite_failure_is_explicit():
    report = inspect_prerequisites(["definitely-not-a-forgewarden-tool"])
    assert report["tools"]["definitely-not-a-forgewarden-tool"]["status"] == "MISSING"
    try:
        require_prerequisites(report)
    except RuntimeError as exc:
        assert "definitely-not-a-forgewarden-tool" in str(exc)
    else:
        raise AssertionError("missing required tool was accepted")
