import json
import os
import subprocess
from pathlib import Path

import jsonschema

from swarm.quality_review import consolidate_report, evaluate_application_gate, scan_repository


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "quality-review.schema.json"


def _finding(result, category):
    return next(item for item in result["findings"] if item["category"] == category)


def test_quality_review_returns_structured_read_only_findings(tmp_path):
    source = tmp_path / "sample.py"
    source.write_text(
        """\ndef passthrough(value):
    return normalize(value)


def risky(value):
    try:
        return value[0]
    except Exception:
        pass


def nested(value):
    return 1 if value else 2 if value > 0 else 3
""",
        encoding="utf-8",
    )
    before = source.read_bytes()

    result = scan_repository(tmp_path)

    jsonschema.validate(result, json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert result["mode"] == "READ_ONLY"
    assert result["repository"] == str(tmp_path.resolve())
    assert result["source_files_scanned"] == 1
    assert result["source_files_read"] == 1
    assert {item["category"] for item in result["findings"]} >= {
        "pass_through_wrapper",
        "silent_failure",
        "nested_ternary",
    }
    assert all(item["auto_apply"] is False for item in result["findings"])
    assert source.read_bytes() == before


def test_quality_review_classifies_suspected_n_plus_one_and_ai_slop(tmp_path):
    source = tmp_path / "service.py"
    source.write_text(
        """\ndef load_all(items, db):
    # Certainly, this important function performs the requested operation.
    for item in items:
        db.execute("select * from items where id = ?", (item.id,))


def do_work():
    return "ok"
    return "unreachable"
""",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)

    n_plus_one = _finding(result, "n_plus_one_query")
    assert n_plus_one["tier"] == "RISKY"
    assert n_plus_one["confidence"] in {"MEDIUM", "HIGH"}
    assert _finding(result, "ai_slop") ["tier"] == "SAFE"
    assert _finding(result, "unreachable_code")["tier"] == "SAFE"


def test_quality_review_scans_javascript_and_typescript_risk_patterns(tmp_path):
    (tmp_path / "client.ts").write_text(
        """export function choose(ok: boolean, value: string) {
    return ok ? value : value.length ? value : "fallback";
}

export async function request() {
    try {
        return await fetch("/items");
    } catch (error) {}
}
""",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)

    assert _finding(result, "nested_ternary")["tier"] == "CAREFUL"
    assert _finding(result, "silent_failure")["tier"] == "RISKY"


def test_quality_review_reports_duplicate_logic_as_careful(tmp_path):
    body = """\ndef first(value):
    normalized = value.strip().lower()
    return normalized
"""
    (tmp_path / "first.py").write_text(body, encoding="utf-8")
    (tmp_path / "second.py").write_text(body.replace("first", "second"), encoding="utf-8")

    result = scan_repository(tmp_path)

    duplicates = [item for item in result["findings"] if item["category"] == "duplicate_logic"]
    assert len(duplicates) == 2
    assert all(item["tier"] == "CAREFUL" for item in duplicates)
    assert all(item["confidence"] == "MEDIUM" for item in duplicates)


def test_quality_review_flags_unbounded_loop_growth_as_risky(tmp_path):
    (tmp_path / "worker.py").write_text(
        """\ndef worker(queue):
    while True:
        queue.append(next_item())
""",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)
    finding = _finding(result, "unbounded_growth")

    assert finding["tier"] == "RISKY"
    assert finding["confidence"] == "LOW"
    assert finding["auto_apply"] is False


def test_quality_review_flags_possible_stale_state_marker(tmp_path):
    (tmp_path / "lifecycle.py").write_text(
        "def start():\n    state = \"RUNNING\"\n    return state\n",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)
    finding = _finding(result, "stale_state")

    assert finding["tier"] == "RISKY"
    assert finding["confidence"] == "LOW"


def test_quality_review_flags_naming_rot_as_careful(tmp_path):
    (tmp_path / "versions.py").write_text(
        "def normalize_v2(value):\n    return value.strip()\n",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)
    finding = _finding(result, "naming_rot")

    assert finding["tier"] == "CAREFUL"
    assert finding["confidence"] == "LOW"


def test_quality_review_flags_private_storage_leak_as_careful(tmp_path):
    (tmp_path / "model.py").write_text(
        """\nclass Model:
    def value(self):
        return self._value
""",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)
    finding = _finding(result, "leaky_abstraction")

    assert finding["tier"] == "CAREFUL"
    assert finding["confidence"] == "LOW"


def test_quality_review_flags_global_state_mutation_as_risky(tmp_path):
    (tmp_path / "shared.py").write_text(
        """\n_count = 0

def increment():
    global _count
    _count += 1
""",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)
    finding = _finding(result, "concurrency_risk")

    assert finding["tier"] == "RISKY"
    assert finding["confidence"] == "LOW"


def test_quality_review_redacts_secret_like_evidence(tmp_path):
    secret = "SECRET_REVIEW_VALUE"
    (tmp_path / "message.py").write_text(
        f"message = 'Certainly, token={secret}'\n",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)
    rendered = json.dumps(result, sort_keys=True)

    assert secret not in rendered
    assert "[REDACTED]" in rendered


def test_quality_review_does_not_follow_external_symlinks(tmp_path):
    outside = tmp_path.parent / f"quality-review-outside-{tmp_path.name}.py"
    outside.write_text("def outside_v2():\n    return True\n", encoding="utf-8")
    link = tmp_path / "linked.py"
    try:
        link.symlink_to(outside)
    except OSError:
        return

    result = scan_repository(tmp_path)

    assert all(item["file"] != "linked.py" for item in result["findings"])
    assert result["source_symlinks_skipped"] == 1


def test_quality_review_cli_refuses_symlink_output(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text("def ok():\n    return True\n", encoding="utf-8")
    target = tmp_path.parent / f"quality-review-target-{tmp_path.name}.json"
    target.write_text("preserve\n", encoding="utf-8")
    output = tmp_path / "review.json"
    try:
        output.symlink_to(target)
    except OSError:
        return

    result = subprocess.run(
        ["python3", "-m", "swarm.quality_review", str(tmp_path), "--output", str(output)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )

    assert result.returncode != 0
    assert target.read_text(encoding="utf-8") == "preserve\n"


def test_quality_review_cli_refuses_symlinked_output_parent(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text("def ok():\n    return True\n", encoding="utf-8")
    target_parent = tmp_path.parent / f"quality-review-parent-{tmp_path.name}"
    target_parent.mkdir()
    linked_parent = tmp_path / "reports"
    try:
        linked_parent.symlink_to(target_parent, target_is_directory=True)
    except OSError:
        return

    result = subprocess.run(
        ["python3", "-m", "swarm.quality_review", str(tmp_path), "--output", str(linked_parent / "review.json")],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )

    assert result.returncode != 0
    assert not (target_parent / "review.json").exists()


def test_quality_review_reports_unreadable_source_instead_of_skipping(tmp_path):
    (tmp_path / "broken.py").write_bytes(b"def broken():\n\xff\n")

    result = scan_repository(tmp_path)
    finding = _finding(result, "unreadable_source")

    assert result["source_files_scanned"] == 1
    assert result["source_files_read"] == 0
    assert finding["tier"] == "RISKY"
    assert finding["confidence"] == "HIGH"


def test_quality_review_skips_sensitive_and_non_source_files(tmp_path):
    (tmp_path / ".env").write_text("TOKEN=do-not-read\n", encoding="utf-8")
    (tmp_path / "notes.txt").write_text("Certainly, this is prose.\n", encoding="utf-8")
    (tmp_path / "safe.py").write_text("def ok():\n    return True\n", encoding="utf-8")

    result = scan_repository(tmp_path)

    assert all(item["file"] == "safe.py" for item in result["findings"])


def test_quality_review_cli_writes_only_requested_report(tmp_path):
    source = tmp_path / "safe.py"
    source.write_text("def ok():\n    return True\n", encoding="utf-8")
    report = tmp_path / "review.json"

    result = subprocess.run(
        ["python3", "-m", "swarm.quality_review", str(tmp_path), "--output", str(report)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(report.read_text(encoding="utf-8"))
    jsonschema.validate(payload, json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert "review.json" not in {item["file"] for item in payload["findings"]}


def test_swarm_cli_exposes_quality_review_without_creating_state(tmp_path):
    (tmp_path / "safe.py").write_text("def ok():\n    return True\n", encoding="utf-8")
    state = tmp_path / "unused-state"

    result = subprocess.run(
        ["python3", "-m", "swarm.cli", "quality-review", "--repository", str(tmp_path)],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
        env={**os.environ, "PYTHONPATH": str(ROOT)},
    )

    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    jsonschema.validate(payload, json.loads(SCHEMA.read_text(encoding="utf-8")))
    assert not state.exists()


def test_consolidator_deduplicates_and_orders_without_enabling_edits(tmp_path):
    (tmp_path / "sample.py").write_text(
        "def wrapper(value):\n    return normalize(value)\n",
        encoding="utf-8",
    )
    report = scan_repository(tmp_path)
    duplicate = dict(report["findings"][0])
    report["findings"].append(duplicate)

    consolidated = consolidate_report(report)

    assert consolidated["consolidation"]["duplicate_findings_removed"] == 1
    assert consolidated["findings"][0]["duplicate_count"] == 2
    assert consolidated["consolidation"]["application_order"] == [
        item["id"] for item in consolidated["findings"]
    ]
    assert consolidated["auto_apply_enabled"] is False
    assert {item["decision"] for item in consolidated["application_policy"]} == {"SAFE_REVIEW_ONLY"}
    jsonschema.validate(consolidated, json.loads(SCHEMA.read_text(encoding="utf-8")))


def test_application_gate_requires_human_for_risky_findings():
    report = {"counts": {"SAFE": 0, "CAREFUL": 0, "RISKY": 1}}

    gate = evaluate_application_gate(report, tests_added_or_changed=["test.py"])

    assert gate["decision"] == "HUMAN_REQUIRED"
    assert gate["mutation_allowed"] is False


def test_application_gate_requires_tests_for_careful_findings():
    report = {"counts": {"SAFE": 0, "CAREFUL": 1, "RISKY": 0}}

    assert evaluate_application_gate(report)["decision"] == "HUMAN_REQUIRED"
    assert evaluate_application_gate(report, tests_added_or_changed=["test.py"])["decision"] == "ALLOW_DRY_RUN"
