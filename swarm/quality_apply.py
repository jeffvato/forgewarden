"""Explicit, SAFE-only transformations for isolated Git worktrees."""
from __future__ import annotations

import ast
import hashlib
import json
import os
import shlex
import subprocess
from pathlib import Path
from typing import Any, Iterable


SAFE_TRANSFORMERS = {"unused_import"}


def _assert_audit_path(audit_path: Path) -> Path:
    path = audit_path.expanduser()
    if path.is_symlink() or any(parent.is_symlink() for parent in (path.parent, *path.parent.parents)):
        raise ValueError(f"refusing symlink audit path: {path}")
    return path


def _record_audit(audit_path: Path, job_id: str, root: Path, result: dict[str, Any]) -> None:
    from .core import AuditLog, Job

    command_hash = hashlib.sha256("\0".join(result["verification"]["command"]).encode("utf-8")).hexdigest()
    AuditLog(_assert_audit_path(audit_path)).record(
        Job(job_id, "quality-apply", root, "safe application", state=result["state"]),
        "safe_application_completed",
        repository=str(root),
        applied_finding_ids=result["applied_finding_ids"],
        changed_files=result["changed_files"],
        state=result["state"],
        verification_passed=result["verification"]["passed"],
        verification_exit_code=result["verification"]["exit_code"],
        verification_command_sha256=command_hash,
        rollback_performed=result["rollback_performed"],
        before_sha256=result["before_sha256"],
        after_sha256=result["after_sha256"],
    )


def build_safe_application_plan(report: dict[str, Any]) -> dict[str, Any]:
    """Describe eligible SAFE findings without authorizing any mutation."""
    eligible = [
        item["id"]
        for item in report.get("findings", [])
        if item.get("tier") == "SAFE" and item.get("category") in SAFE_TRANSFORMERS
    ]
    blocked = [
        item["id"]
        for item in report.get("findings", [])
        if item.get("id") not in eligible
    ]
    return {
        "schema_version": "1",
        "mode": "EXPLICIT_SAFE_ONLY",
        "eligible_finding_ids": eligible,
        "blocked_finding_ids": blocked,
        "mutation_allowed": False,
        "requires_explicit_invocation": True,
        "committed": False,
        "pushed": False,
    }


def _git(root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=root, text=True, capture_output=True, check=False,
    )
    if result.returncode:
        raise ValueError(result.stderr.strip() or "git command failed")
    return result.stdout


def _assert_isolated_clean_worktree(root: Path) -> None:
    dot_git = root / ".git"
    if not dot_git.is_file():
        raise ValueError("SAFE application requires an isolated Git worktree, not a repository root")
    if _git(root, "rev-parse", "--is-inside-work-tree").strip() != "true":
        raise ValueError("path is not a Git worktree")
    if _git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("SAFE application requires a clean isolated worktree")


def _unused_import_operation(root: Path, finding: dict[str, Any]) -> tuple[Path, list[str]]:
    relative = finding.get("file")
    symbol = finding.get("symbol")
    line_number = finding.get("line")
    if not isinstance(relative, str) or not isinstance(symbol, str) or not isinstance(line_number, int):
        raise ValueError("unused_import finding has invalid location metadata")
    path = root / relative
    if path.is_symlink() or path.suffix.lower() != ".py" or root not in path.resolve().parents:
        raise ValueError(f"refusing unsafe finding path: {relative}")
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative)
    matches: list[ast.Import | ast.ImportFrom] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.Import, ast.ImportFrom)):
            continue
        if node.lineno != line_number or getattr(node, "end_lineno", node.lineno) != line_number:
            continue
        if len(node.names) != 1:
            continue
        alias = node.names[0]
        imported_name = alias.asname or alias.name.split(".")[0]
        if imported_name == symbol:
            matches.append(node)
    if len(matches) != 1:
        raise ValueError(f"unused_import finding is not an unambiguous one-line import: {relative}:{line_number}")
    lines = source.splitlines(keepends=True)
    if not 1 <= line_number <= len(lines):
        raise ValueError("unused_import finding line is outside the current file")
    return path, lines[: line_number - 1] + lines[line_number:]


def apply_safe_findings(
    repository: Path,
    report: dict[str, Any],
    finding_ids: Iterable[str],
    verification_command: list[str],
    *,
    job_id: str,
    audit_path: Path,
) -> dict[str, Any]:
    """Apply only explicit SAFE allowlisted findings in a clean Git worktree.

    This function never commits or pushes.  It refuses repository roots,
    symlinks, dirty worktrees, non-SAFE findings, ambiguous syntax, and stale
    or missing finding IDs.
    """
    root = repository.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository is not a directory: {repository}")
    if not job_id.strip():
        raise ValueError("SAFE application requires a non-empty job ID")
    audit_path = _assert_audit_path(audit_path)
    _assert_isolated_clean_worktree(root)
    if report.get("repository") != str(root):
        raise ValueError("quality report does not belong to this worktree")
    if not verification_command or any(not isinstance(item, str) or not item for item in verification_command):
        raise ValueError("SAFE application requires a deterministic verification command")
    selected = list(dict.fromkeys(str(item) for item in finding_ids if str(item).strip()))
    if not selected:
        raise ValueError("at least one explicit finding ID is required")
    by_id = {item.get("id"): item for item in report.get("findings", [])}
    operations: list[tuple[Path, list[str], dict[str, Any]]] = []
    for finding_id in selected:
        finding = by_id.get(finding_id)
        if not finding:
            raise ValueError(f"finding ID is not present in the report: {finding_id}")
        if finding.get("tier") != "SAFE" or finding.get("category") not in SAFE_TRANSFORMERS:
            raise ValueError(f"finding is not eligible for SAFE application: {finding_id}")
        if finding.get("auto_apply") is not False:
            raise ValueError(f"finding has invalid auto-apply metadata: {finding_id}")
        path, lines = _unused_import_operation(root, finding)
        operations.append((path, lines, finding))

    originals: dict[Path, bytes] = {path: path.read_bytes() for path, _, _ in operations}
    modes: dict[Path, int] = {path: path.stat().st_mode for path in originals}
    for path, lines, _ in operations:
        path.write_text("".join(lines), encoding="utf-8")
    changed = _git(root, "diff", "--name-only").splitlines()
    expected = sorted({path.relative_to(root).as_posix() for path, _, _ in operations})
    if sorted(changed) != expected:
        raise ValueError("SAFE application changed an unexpected file set")
    try:
        verification = subprocess.run(
            verification_command,
            cwd=root,
            text=True,
            capture_output=True,
            check=False,
            timeout=60,
            env={"PATH": os.environ.get("PATH", ""), "PYTHONPATH": os.environ.get("PYTHONPATH", "")},
        )
    except subprocess.TimeoutExpired:
        verification = None
    if verification is None or verification.returncode != 0:
        for path, data in originals.items():
            path.write_bytes(data)
            path.chmod(modes[path])
        if _git(root, "status", "--porcelain", "--untracked-files=all").strip():
            raise ValueError("verification failed and SAFE rollback could not restore a clean worktree")
        result = {
            "mode": "SAFE_ONLY_ISOLATED_WORKTREE",
            "state": "ROLLED_BACK_VERIFICATION_FAILED",
            "job_id": job_id,
            "repository": str(root),
            "applied_finding_ids": [],
            "changed_files": expected,
            "before_sha256": {path.relative_to(root).as_posix(): hashlib.sha256(data).hexdigest() for path, data in originals.items()},
            "after_sha256": {path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest() for path in originals},
            "verification": {"command": verification_command, "passed": False, "exit_code": None if verification is None else verification.returncode},
            "rollback_performed": True,
            "audit_recorded": False,
            "committed": False,
            "pushed": False,
        }
        _record_audit(audit_path, job_id, root, result)
        result["audit_recorded"] = True
        return result
    result = {
        "mode": "SAFE_ONLY_ISOLATED_WORKTREE",
        "state": "APPLIED_VERIFIED",
        "job_id": job_id,
        "repository": str(root),
        "applied_finding_ids": [finding["id"] for _, _, finding in operations],
        "changed_files": expected,
        "before_sha256": {path.relative_to(root).as_posix(): hashlib.sha256(data).hexdigest() for path, data in originals.items()},
        "after_sha256": {path: hashlib.sha256((root / path).read_bytes()).hexdigest() for path in expected},
        "verification": {"command": verification_command, "passed": True, "exit_code": verification.returncode},
        "rollback_performed": False,
        "audit_recorded": False,
        "committed": False,
        "pushed": False,
    }
    _record_audit(audit_path, job_id, root, result)
    result["audit_recorded"] = True
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="Apply explicit SAFE findings in an isolated Git worktree")
    parser.add_argument("repository", type=Path)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--finding-id", action="append", required=True)
    parser.add_argument("--check-command", required=True, help="shell-free command string used for deterministic verification")
    parser.add_argument("--job-id", required=True)
    parser.add_argument("--audit", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = json.loads(args.report.read_text(encoding="utf-8"))
        command = shlex.split(args.check_command)
        result = apply_safe_findings(args.repository, report, args.finding_id, command, job_id=args.job_id, audit_path=args.audit)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0 if result["state"] == "APPLIED_VERIFIED" else 1
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"FAILED: {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
