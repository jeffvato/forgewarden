from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]


def test_gitignore_excludes_runtime_audit_and_credential_artifacts():
    rules = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    required = {
        "*.jsonl",
        "*.log",
        "*.sqlite",
        "*.sqlite3",
        "*.pem",
        "*.key",
        "*.p12",
        "*.credentials*",
        ".env",
        ".env.*",
        "hermes-swarm-runtime/",
        "hermes-swarm-audit/",
        "fable-evidence/",
    }
    assert required.issubset(set(rules))


def test_runtime_and_audit_roots_are_not_tracked():
    tracked = set(subprocess.check_output(["git", "ls-files"], cwd=ROOT, text=True).splitlines())
    assert not any(path.startswith("hermes-swarm-runtime/") for path in tracked)
    assert not any(path.startswith("hermes-swarm-audit/") for path in tracked)


def test_no_private_key_block_is_tracked():
    import subprocess

    result = subprocess.run(
        ["git", "grep", "-n", "-I", "-E", "--", "-----BEGIN[[:space:]]+([^[:space:]]+[[:space:]]+)?PRIVATE[[:space:]]+KEY-----", "--", "."],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 1


def test_github_actions_dependencies_are_immutably_pinned():
    workflow = (ROOT / ".github" / "workflows" / "swarm-validation.yml").read_text(encoding="utf-8")
    refs = dict(re.findall(r"uses: (actions/(?:checkout|setup-python))@([0-9a-f]{40})", workflow))
    assert refs == {
        "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
        "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    }
