"""Read-only, evidence-backed code-quality review for isolated worktrees.

This module deliberately reports findings instead of editing files.  A later
stage may consume the structured report, but no finding is currently
auto-applied.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .core import redact


SCHEMA_VERSION = "1"
SOURCE_SUFFIXES = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".h", ".hpp", ".java", ".js",
    ".jsx", ".kt", ".php", ".py", ".rb", ".rs", ".swift", ".ts", ".tsx",
}
SKIPPED_DIRECTORIES = {
    ".git", ".hg", ".svn", ".venv", "__pycache__", ".pytest_cache",
    "node_modules", "dist", "build", "vendor", "coverage", ".tox",
}
SENSITIVE_NAMES = {
    ".env", ".env.local", ".env.production", "credentials.json",
    "secrets.json", "id_rsa", "id_ed25519",
}
AI_SLOP_RE = re.compile(
    r"\b(?:certainly|it is important to note|as an ai|delve into|seamlessly|"
    r"in today's fast-paced|robust and scalable solution)\b",
    re.IGNORECASE,
)
QUERY_CALL_RE = re.compile(
    r"(?:query|execute|executemany|fetch(?:one|many|all)?|request|retrieve|lookup|get)\b",
    re.IGNORECASE,
)
BLOCKING_ASYNC_RE = re.compile(r"\b(?:time\.sleep|requests\.|urllib\.)")
TRANSIENT_STATE_RE = re.compile(r"\b(?:QUEUED|RUNNING|IN_PROGRESS|STARTED|PENDING)\b")
TERMINAL_STATE_RE = re.compile(r"\b(?:SUCCEEDED|FAILED|COMPLETED|CANCELLED|ABANDONED|DONE)\b")

_TIER_ORDER = {"SAFE": 0, "CAREFUL": 1, "RISKY": 2}


def _line(source: str, line_number: int) -> str:
    lines = source.splitlines()
    if 1 <= line_number <= len(lines):
        return redact(lines[line_number - 1].strip())[:240]
    return ""


def _finding(
    *,
    category: str,
    tier: str,
    confidence: str,
    file: str,
    line: int,
    summary: str,
    evidence: str,
    rationale: str,
    suggested_action: str,
    symbol: str | None = None,
) -> dict[str, Any]:
    identity = "|".join((category, file, str(line), symbol or "", summary))
    finding_id = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return {
        "id": finding_id,
        "category": category,
        "tier": tier,
        "confidence": confidence,
        "file": file,
        "line": line,
        "symbol": symbol,
        "summary": summary,
        "evidence": evidence,
        "rationale": rationale,
        "suggested_action": suggested_action,
        "auto_apply": False,
    }


def _call_name(node: ast.Call) -> str:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return "call"


def _iter_calls(nodes: Iterable[ast.AST]) -> Iterable[ast.Call]:
    for node in nodes:
        yield from (child for child in ast.walk(node) if isinstance(child, ast.Call))


class _PythonReview(ast.NodeVisitor):
    def __init__(self, path: str, source: str):
        self.path = path
        self.source = source
        self.findings: list[dict[str, Any]] = []
        self.imports: list[tuple[str, int]] = []
        self.names: set[str] = set()

    def add(self, **kwargs: Any) -> None:
        self.findings.append(_finding(file=self.path, evidence=kwargs.pop("evidence", ""), **kwargs))

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self.imports.append((alias.asname or alias.name.split(".")[0], node.lineno))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name != "*":
                self.imports.append((alias.asname or alias.name, node.lineno))
        self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        self.names.add(node.id)

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._visit_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._visit_function(node)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        end = getattr(node, "end_lineno", node.lineno)
        if end - node.lineno + 1 > 80:
            self.add(
                category="structural_bloat", tier="CAREFUL", confidence="HIGH",
                line=node.lineno, symbol=node.name,
                summary=f"function {node.name} spans {end - node.lineno + 1} lines",
                evidence=_line(self.source, node.lineno),
                rationale="Large functions are difficult to review and isolate safely.",
                suggested_action="Review responsibilities and extract helpers only with test coverage.",
            )
        if len(node.body) == 1 and isinstance(node.body[0], ast.Return) and isinstance(node.body[0].value, ast.Call):
            call = node.body[0].value
            self.add(
                category="pass_through_wrapper", tier="SAFE", confidence="HIGH",
                line=node.lineno, symbol=node.name,
                summary=f"function {node.name} only forwards to {_call_name(call)}",
                evidence=_line(self.source, node.body[0].lineno),
                rationale="A wrapper with no local behavior may be redundant, but callers must be checked first.",
                suggested_action="Confirm the wrapper has no compatibility or observability contract before removing it.",
            )
        if isinstance(node, ast.AsyncFunctionDef) and any(BLOCKING_ASYNC_RE.search(self.source_line(child)) for child in ast.walk(node)):
            self.add(
                category="concurrency_risk", tier="RISKY", confidence="MEDIUM",
                line=node.lineno, symbol=node.name,
                summary=f"async function {node.name} contains a blocking call",
                evidence=_line(self.source, node.lineno),
                rationale="Blocking work inside async code can stall unrelated tasks.",
                suggested_action="Review the event-loop boundary and move blocking work to an explicit worker.",
            )
        self._unreachable(node.body)
        self.generic_visit(node)

    def source_line(self, node: ast.AST) -> str:
        return _line(self.source, getattr(node, "lineno", 0))

    def _unreachable(self, statements: list[ast.stmt]) -> None:
        terminated = False
        for statement in statements:
            if terminated:
                self.add(
                    category="unreachable_code", tier="SAFE", confidence="HIGH",
                    line=statement.lineno, symbol=None,
                    summary="statement follows an unconditional return, raise, break, or continue",
                    evidence=_line(self.source, statement.lineno),
                    rationale="Unreachable statements cannot execute and create misleading maintenance surface.",
                    suggested_action="Remove only after confirming no generated-code or debugging purpose exists.",
                )
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                terminated = True

    def visit_IfExp(self, node: ast.IfExp) -> None:
        if isinstance(node.body, ast.IfExp) or isinstance(node.orelse, ast.IfExp):
            self.add(
                category="nested_ternary", tier="CAREFUL", confidence="HIGH",
                line=node.lineno, symbol=None,
                summary="nested conditional expression reduces branch readability",
                evidence=_line(self.source, node.lineno),
                rationale="Nested ternaries are easy to misread and complicate safe edits.",
                suggested_action="Convert to an explicit conditional with tests covering each branch.",
            )
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        if any(isinstance(statement, ast.Pass) for statement in node.body) or (
            len(node.body) == 1
            and isinstance(node.body[0], ast.Return)
            and isinstance(node.body[0].value, ast.Constant)
            and node.body[0].value.value is None
        ):
            self.add(
                category="silent_failure", tier="RISKY", confidence="HIGH",
                line=node.lineno, symbol=None,
                summary="exception handler suppresses an error without a visible action",
                evidence=_line(self.source, node.lineno),
                rationale="Suppressed exceptions can hide data loss, retries, or broken state transitions.",
                suggested_action="Require an explicit policy: handle, translate, log safely, or propagate the error.",
            )
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        calls = [call for call in _iter_calls(node.body) if QUERY_CALL_RE.search(_call_name(call))]
        if calls:
            self.add(
                category="n_plus_one_query", tier="RISKY", confidence="MEDIUM",
                line=node.lineno, symbol=None,
                summary="query-like call occurs inside a loop",
                evidence=_line(self.source, calls[0].lineno),
                rationale="Per-item I/O often scales linearly with input size and may be an N+1 pattern.",
                suggested_action="Measure query count and consider batching only with behavioral and performance tests.",
            )
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        is_literal_true = isinstance(node.test, ast.Constant) and node.test.value is True
        has_break = any(isinstance(child, ast.Break) for child in ast.walk(node))
        grows_collection = any(
            isinstance(child, ast.Call)
            and _call_name(child) in {"append", "extend", "add", "put"}
            for child in ast.walk(node)
        )
        if is_literal_true and not has_break and grows_collection:
            self.add(
                category="unbounded_growth", tier="RISKY", confidence="LOW",
                line=node.lineno, symbol=None,
                summary="non-terminating loop appears to grow a collection",
                evidence=_line(self.source, node.lineno),
                rationale="This can be an intentional worker loop or an unbounded memory-growth path.",
                suggested_action="Review termination, backpressure, and collection lifetime with a runtime test.",
            )
        self.generic_visit(node)


def _scan_python(path: Path, relative: str, source: str) -> list[dict[str, Any]]:
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError as exc:
        return [_finding(
            category="parse_failure", tier="RISKY", confidence="HIGH", file=relative,
            line=exc.lineno or 1, summary="source file could not be parsed",
            evidence=redact(str(exc))[:240],
            rationale="A review that cannot parse a source file must not infer safe edits.",
            suggested_action="Repair or explicitly quarantine the syntax issue before automated review.",
        )]
    review = _PythonReview(relative, source)
    review.visit(tree)
    for name, line in review.imports:
        if name not in review.names:
            review.add(
                category="unused_import", tier="SAFE", confidence="MEDIUM",
                line=line, symbol=name,
                summary=f"import {name} is not referenced in this module",
                evidence=_line(source, line),
                rationale="Unused imports add noise and can create unnecessary import-time effects.",
                suggested_action="Confirm dynamic use and public export behavior before removal.",
            )
    return review.findings


def _python_function_signatures(relative: str, source: str) -> list[tuple[str, str, int, str]]:
    """Return hashes for non-trivial function bodies for duplicate detection."""
    try:
        tree = ast.parse(source, filename=relative)
    except SyntaxError:
        return []
    signatures: list[tuple[str, str, int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) or len(node.body) < 2:
            continue
        body = ast.Module(body=node.body, type_ignores=[])
        normalized = ast.dump(body, annotate_fields=False, include_attributes=False)
        signatures.append((hashlib.sha256(normalized.encode("utf-8")).hexdigest(), relative, node.lineno, node.name))
    return signatures


def _scan_text(relative: str, source: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for line_number, line in enumerate(source.splitlines(), start=1):
        if AI_SLOP_RE.search(line):
            findings.append(_finding(
                category="ai_slop", tier="SAFE", confidence="LOW", file=relative,
                line=line_number, summary="comment or string contains a generic AI-style phrase",
                evidence=redact(line.strip())[:240],
                rationale="Generic filler can obscure intent, but the detector is heuristic and non-authoritative.",
                suggested_action="Review for precise project-specific wording; do not rewrite behavior automatically.",
            ))
    transient = TRANSIENT_STATE_RE.search(source)
    if transient and not TERMINAL_STATE_RE.search(source):
        line_number = source.count("\n", 0, transient.start()) + 1
        findings.append(_finding(
            category="stale_state", tier="RISKY", confidence="LOW", file=relative,
            line=line_number, summary="transient state marker has no visible terminal state in this file",
            evidence=_line(source, line_number),
            rationale="A persisted transient marker without terminal reconciliation can strand work as stale.",
            suggested_action="Trace all lifecycle transitions and recovery paths before changing state handling.",
        ))
    return findings


def _source_files(root: Path) -> Iterable[tuple[Path, str]]:
    root = root.resolve()
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.is_symlink() or path.suffix.lower() not in SOURCE_SUFFIXES:
            continue
        if any(part in SKIPPED_DIRECTORIES for part in path.relative_to(root).parts):
            continue
        if path.name.lower() in SENSITIVE_NAMES or path.name.lower().startswith(".env"):
            continue
        resolved = path.resolve()
        if root not in resolved.parents:
            continue
        try:
            source = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        yield path, source


def consolidate_report(report: dict[str, Any]) -> dict[str, Any]:
    """Deduplicate findings and expose a stable, risk-tiered review order."""
    groups: dict[tuple[Any, ...], list[dict[str, Any]]] = defaultdict(list)
    for finding in report.get("findings", []):
        key = (
            finding.get("category"), finding.get("file"), finding.get("line"),
            finding.get("symbol"), finding.get("summary"),
        )
        groups[key].append(finding)
    unique: list[dict[str, Any]] = []
    for items in groups.values():
        canonical = min(items, key=lambda item: json.dumps(item, sort_keys=True))
        merged = dict(canonical)
        merged["duplicate_count"] = len(items)
        unique.append(merged)
    unique.sort(key=lambda item: (_TIER_ORDER[item["tier"]], item["file"], item["line"], item["category"], item["id"]))
    counts = {tier: sum(item["tier"] == tier for item in unique) for tier in _TIER_ORDER}
    consolidated = dict(report)
    consolidated["findings"] = unique
    consolidated["counts"] = counts
    consolidated["consolidation"] = {
        "duplicate_findings_removed": sum(len(items) - 1 for items in groups.values()),
        "application_order": [item["id"] for item in unique],
        "tier_order": ["SAFE", "CAREFUL", "RISKY"],
        "review_required": [item["id"] for item in unique if item["tier"] == "RISKY"],
    }
    decisions = {
        "SAFE": "SAFE_REVIEW_ONLY",
        "CAREFUL": "TEST_VERIFICATION_REQUIRED",
        "RISKY": "HUMAN_REVIEW_REQUIRED",
    }
    consolidated["application_policy"] = [
        {
            "finding_id": item["id"],
            "tier": item["tier"],
            "decision": decisions[item["tier"]],
            "mutation_allowed": False,
        }
        for item in unique
    ]
    return consolidated


def scan_repository(repository: Path) -> dict[str, Any]:
    """Scan source files without changing the repository or invoking tools."""
    root = repository.expanduser().resolve()
    if not root.is_dir():
        raise ValueError(f"repository is not a directory: {repository}")
    findings: list[dict[str, Any]] = []
    duplicate_candidates: dict[str, list[tuple[str, int, str]]] = defaultdict(list)
    for path, source in _source_files(root):
        relative = path.relative_to(root).as_posix()
        findings.extend(_scan_text(relative, source))
        if path.suffix.lower() == ".py":
            findings.extend(_scan_python(path, relative, source))
            for signature, file, line, name in _python_function_signatures(relative, source):
                duplicate_candidates[signature].append((file, line, name))
    for candidates in duplicate_candidates.values():
        if len(candidates) < 2:
            continue
        locations = ", ".join(f"{file}:{line}" for file, line, _ in sorted(candidates))
        for file, line, name in candidates:
            findings.append(_finding(
                category="duplicate_logic", tier="CAREFUL", confidence="MEDIUM", file=file,
                line=line, symbol=name,
                summary="non-trivial function body is duplicated in another source file",
                evidence=f"duplicate locations: {locations}"[:512],
                rationale="Deduplicating logic can change edge-case behavior and requires shared tests.",
                suggested_action="Compare contracts and extract shared behavior only after regression coverage.",
            ))
    findings.sort(key=lambda item: (_TIER_ORDER[item["tier"]], item["file"], item["line"], item["category"], item["id"]))
    report = {
        "schema_version": SCHEMA_VERSION,
        "mode": "READ_ONLY",
        "repository": str(root),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "findings": findings,
        "counts": {tier: 0 for tier in _TIER_ORDER},
        "auto_apply_enabled": False,
    }
    return consolidate_report(report)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a read-only Hermes code-quality review")
    parser.add_argument("repository", type=Path)
    parser.add_argument("--output", type=Path, help="write structured JSON to this path instead of stdout")
    args = parser.parse_args(argv)
    try:
        payload = scan_repository(args.repository)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
        args.output.chmod(0o600)
    else:
        sys.stdout.write(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
