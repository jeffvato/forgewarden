import json
import os
import subprocess
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest

from swarm.quality_review import consolidate_report, evaluate_application_gate, scan_repository
from swarm.quality_apply import apply_safe_findings, build_safe_application_plan
from swarm.quality_audit import review_audit
from swarm.review_evidence import build_review_evidence
from swarm.approval import create_approval_record, reconcile_approval


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = ROOT / "schemas" / "quality-review.schema.json"
APPLICATION_PLAN_SCHEMA = ROOT / "schemas" / "quality-application-plan.schema.json"
APPLICATION_RESULT_SCHEMA = ROOT / "schemas" / "quality-application-result.schema.json"
AUDIT_REVIEW_SCHEMA = ROOT / "schemas" / "quality-audit-review.schema.json"
COMBINED_EVIDENCE_SCHEMA = ROOT / "schemas" / "combined-review-evidence.schema.json"


def _finding(result, category):
    return next(item for item in result["findings"] if item["category"] == category)


def _approval(tmp_path, job_id):
    evidence = tmp_path / f"{job_id}-evidence.json"
    evidence.write_text('{"mutation_allowed": false}\n', encoding="utf-8")
    approval = tmp_path / f"{job_id}-approval" / "record.json"
    create_approval_record(evidence, approval, job_id=job_id, reviewer="fixture", decision="APPROVED")
    return approval, evidence


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
    coverage = {item["language"]: item for item in result["detector_coverage"]}
    assert coverage["python"]["mode"] == "SYNTAX_AWARE"
    assert coverage["javascript_typescript"]["mode"] == "TEXT_ONLY"
    assert coverage["supported_source_text"]["mode"] == "TEXT_ONLY"
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

export function load_v2(items, db) {
    for (const item of items) {
        return db.query(item.id);
    }
}

export async function sync_v1(fs) {
    return fs.readFileSync("items.json");
}

export function passthrough(value) {
    return normalize(value);
}
""",
        encoding="utf-8",
    )

    result = scan_repository(tmp_path)

    assert _finding(result, "nested_ternary")["tier"] == "CAREFUL"
    assert _finding(result, "silent_failure")["tier"] == "RISKY"
    assert _finding(result, "naming_rot")["tier"] == "CAREFUL"
    assert _finding(result, "pass_through_wrapper")["tier"] == "SAFE"
    assert _finding(result, "n_plus_one_query")["tier"] == "RISKY"
    assert _finding(result, "concurrency_risk")["tier"] == "RISKY"


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


def test_safe_application_plan_is_explicit_and_allowlisted():
    report = {
        "findings": [
            {"id": "a" * 16, "tier": "SAFE", "category": "unused_import"},
            {"id": "b" * 16, "tier": "RISKY", "category": "silent_failure"},
        ]
    }

    plan = build_safe_application_plan(report)

    jsonschema.validate(plan, json.loads(APPLICATION_PLAN_SCHEMA.read_text(encoding="utf-8")))
    assert plan["eligible_finding_ids"] == ["a" * 16]
    assert plan["blocked_finding_ids"] == ["b" * 16]
    assert plan["requires_explicit_invocation"] is True
    assert plan["mutation_allowed"] is False


def test_application_gate_requires_tests_for_careful_findings():
    report = {"counts": {"SAFE": 0, "CAREFUL": 1, "RISKY": 0}}

    assert evaluate_application_gate(report)["decision"] == "HUMAN_REQUIRED"
    assert evaluate_application_gate(report, tests_added_or_changed=["test.py"])["decision"] == "HUMAN_REQUIRED"
    assert evaluate_application_gate(
        report, tests_added_or_changed=["test.py"], changed_files=["module.py", "test.py"]
    )["decision"] == "ALLOW_DRY_RUN"


def test_safe_apply_changes_only_explicit_unused_import_in_isolated_worktree(tmp_path):
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    (source_repo / "module.py").write_text("import unused\n\ndef ok():\n    return True\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=source_repo, check=True)
    subprocess.run(["git", "add", "."], cwd=source_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "initial"],
        cwd=source_repo,
        check=True,
    )
    isolated = tmp_path / "isolated"
    subprocess.run(["git", "worktree", "add", "--detach", "-q", str(isolated), "HEAD"], cwd=source_repo, check=True)
    report = scan_repository(isolated)
    finding = _finding(report, "unused_import")
    approval_path, approval_evidence_path = _approval(tmp_path, "safe-job-1")

    result = apply_safe_findings(
        isolated,
        report,
        [finding["id"]],
        ["python3", "-c", "from pathlib import Path; assert 'import unused' not in Path('module.py').read_text()"],
        job_id="safe-job-1",
        audit_path=tmp_path / "audit" / "audit.jsonl",
        approval_path=approval_path,
        approval_evidence_path=approval_evidence_path,
    )

    jsonschema.validate(result, json.loads(APPLICATION_RESULT_SCHEMA.read_text(encoding="utf-8")))
    assert result["committed"] is False
    assert result["state"] == "APPLIED_VERIFIED"
    assert result["verification"]["passed"] is True
    assert result["approval_consumed"] is True
    audit = tmp_path / "audit" / "audit.jsonl"
    assert audit.stat().st_mode & 0o777 == 0o600
    audit_entry = json.loads(audit.read_text(encoding="utf-8").strip())
    assert audit_entry["job_id"] == "safe-job-1"
    assert audit_entry["event"] == "safe_application_completed"
    assert audit_entry["verification_passed"] is True
    assert "command" not in audit_entry
    assert result["changed_files"] == ["module.py"]
    assert "import unused" not in (isolated / "module.py").read_text(encoding="utf-8")
    assert "import unused" in (source_repo / "module.py").read_text(encoding="utf-8")
    reconciliation = reconcile_approval(
        approval_path,
        approval_evidence_path,
        audit,
        expected_job_id="safe-job-1",
    )
    jsonschema.validate(reconciliation, json.loads((ROOT / "schemas" / "approval-reconciliation.schema.json").read_text(encoding="utf-8")))
    assert reconciliation["reconciled"] is True


def test_safe_apply_removes_multiple_findings_from_one_file_without_losing_edits(tmp_path):
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    (source_repo / "module.py").write_text(
        "import unused_one\nimport unused_two\n\ndef ok():\n    return True\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=source_repo, check=True)
    subprocess.run(["git", "add", "."], cwd=source_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "initial"],
        cwd=source_repo,
        check=True,
    )
    isolated = tmp_path / "isolated"
    subprocess.run(["git", "worktree", "add", "--detach", "-q", str(isolated), "HEAD"], cwd=source_repo, check=True)
    report = scan_repository(isolated)
    findings = [item for item in report["findings"] if item["category"] == "unused_import"]
    approval_path, approval_evidence_path = _approval(tmp_path, "safe-job-multi")

    result = apply_safe_findings(
        isolated,
        report,
        [item["id"] for item in findings],
        ["python3", "-c", "from pathlib import Path; text=Path('module.py').read_text(); assert 'unused_one' not in text and 'unused_two' not in text"],
        job_id="safe-job-multi",
        audit_path=tmp_path / "audit" / "audit.jsonl",
        approval_path=approval_path,
        approval_evidence_path=approval_evidence_path,
    )

    assert result["state"] == "APPLIED_VERIFIED"
    text = (isolated / "module.py").read_text(encoding="utf-8")
    assert "unused_one" not in text
    assert "unused_two" not in text
    assert "def ok" in text


def test_safe_apply_rolls_back_and_audits_when_mutation_fails_after_approval(tmp_path):
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    original = "import unused\n\ndef ok():\n    return True\n"
    (source_repo / "module.py").write_text(original, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=source_repo, check=True)
    subprocess.run(["git", "add", "."], cwd=source_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "initial"],
        cwd=source_repo,
        check=True,
    )
    isolated = tmp_path / "isolated"
    subprocess.run(["git", "worktree", "add", "--detach", "-q", str(isolated), "HEAD"], cwd=source_repo, check=True)
    report = scan_repository(isolated)
    finding = _finding(report, "unused_import")
    approval_path, approval_evidence_path = _approval(tmp_path, "mutation-failure-job")

    with patch.object(Path, "write_text", side_effect=OSError("simulated mutation failure")):
        result = apply_safe_findings(
            isolated,
            report,
            [finding["id"]],
            ["true"],
            job_id="mutation-failure-job",
            audit_path=tmp_path / "audit" / "audit.jsonl",
            approval_path=approval_path,
            approval_evidence_path=approval_evidence_path,
        )

    jsonschema.validate(result, json.loads(APPLICATION_RESULT_SCHEMA.read_text(encoding="utf-8")))
    assert result["state"] == "ROLLED_BACK_VERIFICATION_FAILED"
    assert result["approval_consumed"] is True
    assert result["audit_recorded"] is True
    assert (isolated / "module.py").read_text(encoding="utf-8") == original
    assert subprocess.run(["git", "status", "--porcelain"], cwd=isolated, capture_output=True, text=True, check=True).stdout == ""


def test_safe_apply_rejects_repository_root_and_non_safe_finding(tmp_path):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "module.py").write_text("def wrapper(value):\n    return normalize(value)\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=repository, check=True)
    subprocess.run(["git", "add", "."], cwd=repository, check=True)
    subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "initial"],
        cwd=repository,
        check=True,
    )
    report = scan_repository(repository)
    finding = _finding(report, "pass_through_wrapper")

    with pytest.raises(ValueError, match="isolated Git worktree"):
        apply_safe_findings(repository, report, [finding["id"]], ["true"], job_id="root-job", audit_path=tmp_path / "audit.jsonl", approval_path=tmp_path / "approval.json", approval_evidence_path=tmp_path / "evidence.json")


def test_safe_apply_rolls_back_when_verification_fails(tmp_path):
    source_repo = tmp_path / "source"
    source_repo.mkdir()
    original = "import unused\n\ndef ok():\n    return True\n"
    (source_repo / "module.py").write_text(original, encoding="utf-8")
    subprocess.run(["git", "init", "-q", "-b", "main"], cwd=source_repo, check=True)
    subprocess.run(["git", "add", "."], cwd=source_repo, check=True)
    subprocess.run(
        ["git", "-c", "user.name=fixture", "-c", "user.email=fixture@example.test", "commit", "-qm", "initial"],
        cwd=source_repo,
        check=True,
    )
    isolated = tmp_path / "isolated"
    subprocess.run(["git", "worktree", "add", "--detach", "-q", str(isolated), "HEAD"], cwd=source_repo, check=True)
    report = scan_repository(isolated)
    finding = _finding(report, "unused_import")
    approval_path, approval_evidence_path = _approval(tmp_path, "rollback-job")

    result = apply_safe_findings(
        isolated,
        report,
        [finding["id"]],
        ["python3", "-c", "raise SystemExit(7)"],
        job_id="rollback-job",
        audit_path=tmp_path / "audit" / "audit.jsonl",
        approval_path=approval_path,
        approval_evidence_path=approval_evidence_path,
    )

    jsonschema.validate(result, json.loads(APPLICATION_RESULT_SCHEMA.read_text(encoding="utf-8")))
    assert result["state"] == "ROLLED_BACK_VERIFICATION_FAILED"
    assert result["audit_recorded"] is True
    assert result["rollback_performed"] is True
    assert (isolated / "module.py").read_text(encoding="utf-8") == original
    assert subprocess.run(["git", "status", "--porcelain"], cwd=isolated, capture_output=True, text=True, check=True).stdout == ""


def test_audit_consumer_returns_only_review_safe_summary(tmp_path):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(mode=0o700)
    audit = audit_dir / "audit.jsonl"
    audit.write_text(
        json.dumps({
            "timestamp": "2026-01-01T00:00:00Z",
            "job_id": "safe-job-1",
            "state": "APPLIED_VERIFIED",
            "event": "safe_application_completed",
            "repository": "/tmp/isolated",
            "applied_finding_ids": ["a" * 16],
            "changed_files": ["module.py"],
            "verification_passed": True,
            "verification_exit_code": 0,
            "rollback_performed": False,
            "before_sha256": {"module.py": "a" * 64},
            "after_sha256": {"module.py": "b" * 64},
            "output": "must not be echoed",
        }) + "\n",
        encoding="utf-8",
    )
    audit.chmod(0o600)

    result = review_audit(audit, "safe-job-1")

    jsonschema.validate(result, json.loads(AUDIT_REVIEW_SCHEMA.read_text(encoding="utf-8")))
    assert result["integrity"] == "VALID"
    assert result["latest_state"] == "APPLIED_VERIFIED"
    assert result["latest_event_sha256"]
    assert result["review_required"] is True
    assert result["mutation_allowed"] is False
    assert "must not be echoed" not in json.dumps(result)
    assert "changed_files" not in result


def test_audit_consumer_marks_missing_job_incomplete(tmp_path):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(mode=0o700)
    audit = audit_dir / "audit.jsonl"
    audit.write_text(json.dumps({"job_id": "other", "event": "safe_application_completed"}) + "\n", encoding="utf-8")
    audit.chmod(0o600)

    result = review_audit(audit, "missing-job")

    assert result["integrity"] == "INCOMPLETE"
    assert result["matching_event_count"] == 0


def test_audit_consumer_rejects_inconsistent_completion_event(tmp_path):
    audit_dir = tmp_path / "audit"
    audit_dir.mkdir(mode=0o700)
    audit = audit_dir / "audit.jsonl"
    audit.write_text(
        json.dumps({
            "job_id": "bad-job",
            "event": "safe_application_completed",
            "state": "APPLIED_VERIFIED",
            "repository": "/tmp/isolated",
            "applied_finding_ids": [],
            "changed_files": [],
            "verification_passed": False,
            "verification_exit_code": 7,
            "rollback_performed": True,
            "before_sha256": {},
            "after_sha256": {},
        }) + "\n",
        encoding="utf-8",
    )
    audit.chmod(0o600)

    result = review_audit(audit, "bad-job")

    assert result["integrity"] == "INVALID"
    assert result["matching_event_count"] == 0


def test_combined_review_evidence_is_hash_bound_and_non_mutating(tmp_path):
    quality = tmp_path / "quality.json"
    plan = tmp_path / "plan.json"
    audit_review = tmp_path / "audit-review.json"
    quality.write_text(json.dumps({"schema_version": "1", "mode": "READ_ONLY", "auto_apply_enabled": False, "counts": {"SAFE": 1, "CAREFUL": 0, "RISKY": 0}, "source_files_scanned": 2, "secret": "do-not-echo"}), encoding="utf-8")
    plan.write_text(json.dumps({"schema_version": "1", "mode": "EXPLICIT_SAFE_ONLY", "mutation_allowed": False, "requires_explicit_invocation": True, "committed": False, "pushed": False, "eligible_finding_ids": ["a" * 16], "blocked_finding_ids": []}), encoding="utf-8")
    audit_review.write_text(json.dumps({
        "schema_version": "1",
        "mode": "READ_ONLY_AUDIT_REVIEW",
        "mutation_allowed": False,
        "review_required": True,
        "job_id": "safe-job-1",
        "integrity": "VALID",
        "latest_state": "APPLIED_VERIFIED",
        "latest_event_sha256": "b" * 64,
        "verification_passed": True,
        "rollback_performed": False,
    }), encoding="utf-8")

    result = build_review_evidence(quality, plan, audit_review)

    jsonschema.validate(result, json.loads(COMBINED_EVIDENCE_SCHEMA.read_text(encoding="utf-8")))
    assert result["approval_status"] == "HUMAN_REVIEW_REQUIRED"
    assert result["mutation_allowed"] is False
    assert "do-not-echo" not in json.dumps(result)
    assert result["quality_report_sha256"]
