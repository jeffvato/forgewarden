"""Deterministic architecture-drift checks for provider access boundaries."""
from __future__ import annotations
import ast
from pathlib import Path

class ArchitectureDriftError(ValueError):
    pass

_ALLOWED_PROVIDER_MODULES = {"swarm/anythingllm_adapter.py", "swarm/azure_foundry_adapter.py", "swarm/claude_adapter.py", "swarm/verification_adapters.py"}
_FORBIDDEN_ROOTS = {"openai", "anthropic", "google.generativeai", "httpx", "requests"}

def find_provider_bypasses(root: Path) -> tuple[str, ...]:
    findings=[]
    for path in sorted((root / "swarm").rglob("*.py")):
        rel=path.relative_to(root).as_posix()
        if rel in _ALLOWED_PROVIDER_MODULES:
            continue
        try:
            tree=ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, UnicodeDecodeError, SyntaxError) as exc:
            raise ArchitectureDriftError(f"cannot inspect {rel}") from exc
        for node in ast.walk(tree):
            module = node.module if isinstance(node, ast.ImportFrom) else None
            names = [alias.name for alias in node.names] if isinstance(node, (ast.Import, ast.ImportFrom)) else []
            candidates = ([module] if module else []) + names
            if any(candidate == root_name or candidate.startswith(root_name + ".") for candidate in candidates for root_name in _FORBIDDEN_ROOTS):
                findings.append(f"{rel}:{getattr(node, 'lineno', 0)}")
    return tuple(findings)

def validate_repository(root: Path) -> None:
    if not root.is_dir() or root.is_symlink():
        raise ArchitectureDriftError("repository root is invalid")
    findings=find_provider_bypasses(root)
    if findings:
        raise ArchitectureDriftError("provider bypasses detected: " + ", ".join(findings))

# CI invokes validate_repository through scripts/validate-architecture-drift.py.
