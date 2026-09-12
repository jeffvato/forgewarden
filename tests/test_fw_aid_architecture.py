from pathlib import Path

from swarm.integrity import CANONICAL_OWNERSHIP, FUNCTIONALITY_MAP


ROOT = Path(__file__).resolve().parents[1]
ARCH = ROOT / "docs/fw-aid-architecture.md"


def text(path):
    return path.read_text(encoding="utf-8")


def test_fw_aid_is_registered_as_permanent_core_with_stable_requirements():
    roadmap = text(ROOT / "ROADMAP.md")
    architecture = text(ARCH)
    decisions = text(ROOT / "DECISIONS.md")
    assert "FW-AID — AI Intrusion & Agent Defense" in roadmap
    assert "permanent ForgeWarden Core requirement family" in architecture
    assert "D-025" in decisions
    for number in range(1, 11):
        assert f"FW-AID-{number:03d}" in architecture


def test_threat_model_names_every_required_detection_class():
    architecture = text(ARCH)
    for identifier in (
        "AID-ESCAPE", "AID-EGRESS", "AID-SECRETS", "AID-PRIVILEGE",
        "AID-LATERAL", "AID-INJECTION", "AID-MISSION",
        "AID-COORDINATION", "AID-EVALUATION", "AID-TAMPER",
    ):
        assert identifier in architecture
    assert "AI provides intelligence. ForgeWarden provides authority." in architecture


def test_architecture_reuses_canonical_owners_and_keeps_response_inert():
    architecture = text(ARCH)
    for owner in (
        "TrustedSignatureCatalog", "NormalizedEventStore", "swarm.identity",
        "swarm.keys", "swarm.mcp_gateway", "swarm.model_broker",
        "swarm.policy_gate", "FW-EVID", "FW-REC", "swarm.soc",
        "swarm.mission_control", "FW-HARNESS",
    ):
        assert owner in architecture
    assert "outputs only findings and inert\ncontainment proposals" in architecture
    assert "cannot revoke, terminate, isolate, quarantine" in architecture


def test_aid_is_visible_in_endpoint_harness_mission_control_and_security_docs():
    required = {
        "docs/fw-endpoint-sensor-contract.md": "FW-AID",
        "docs/fw-harness-inventory.md": "FW-AID",
        "docs/management-console.md": "AI Security / Agent Defense",
        "docs/security-analysis.md": "FW-AID",
        "docs/fw-integrity-dependency-graph.md": "FW-AID",
        "docs/fw-integrity-functionality-map.md": "FW-AID",
    }
    for path, marker in required.items():
        assert marker in text(ROOT / path)


def test_integrity_registry_reports_implemented_ai_agent_defense_honestly():
    record = CANONICAL_OWNERSHIP["ai_agent_defense"]
    assert record["owner"] == "FW-AID"
    assert record["implementation"].startswith("swarm.ai_agent_defense")
    assert record["status"] == "IMPLEMENTED"
    item = next(item for item in FUNCTIONALITY_MAP if item["requirement_id"] == "FW-AID")
    assert item["state"] == "Proven"
    assert item["unit_tests"] == "PASS"
    assert item["integration_tests"] == "PASS"


def test_telemetry_and_adversarial_scope_are_explicit_and_privacy_minimized():
    architecture = text(ARCH)
    for marker in (
        "agent identity", "model registry identity/provider/version",
        "capability lease", "Action Ticket", "MCP server/capability",
        "process/parent/command hash", "network destination class",
        "prompt-injection indicators", "agent coordination",
        "model/tool call counts", "control-tamper fact",
    ):
        assert marker in architecture
    for attack in (
        "prompt injection", "poisoned documents", "malicious webpages",
        "credential discovery", "secret exfiltration",
        "unauthorized Internet access", "lateral movement",
        "container escape", "privilege escalation", "unauthorized MCP",
        "abnormal shell", "EDR tampering", "log deletion",
        "unapproved\ncoordination", "test manipulation", "policy bypass",
        "self-expansion",
    ):
        assert attack in architecture
    assert "Raw prompts, retrieved content, source, credentials, tokens, private keys" in architecture
