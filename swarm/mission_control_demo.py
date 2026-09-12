"""Deterministic, read-only showcase projection for ForgeWarden Mission Control."""
from __future__ import annotations
from copy import deepcopy
from typing import Any

DEMO_SCENARIO_ID = "DEMO-AI-RANSOM-001"

def mission_control_demo_snapshot() -> dict[str, Any]:
    """Return a fresh copy of the bounded flagship demo scenario."""
    snapshot: dict[str, Any] = {
        "schema_version": 1, "data_mode": "DEMO",
        "scenario": {"id": DEMO_SCENARIO_ID, "name": "Compromised AI agent + ransomware attempt", "status": "SIMULATED_INCIDENT", "organization": "Northstar Fabrication Group"},
        "provenance": {"source": "FORGEWARDEN_DETERMINISTIC_DEMO_PROVIDER", "generated_at": "2026-09-11T14:08:00Z", "live_backend_connected": False, "cryptographic_verification_performed": False},
        "safety": {"mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "ENGAGED", "mutation_allowed": False},
        "posture": {"score": 82, "label": "CONTROLLED RISK", "trend": "+6 after containment", "dimensions": [{"label": "Endpoint health", "value": 91}, {"label": "Identity risk", "value": 76}, {"label": "AI / agent risk", "value": 73}, {"label": "Recovery readiness", "value": 88}]},
        "assets": [{"label": "Endpoints", "value": 1204, "detail": "1 isolated"}, {"label": "Servers", "value": 92, "detail": "90 healthy"}, {"label": "Identities", "value": 1487, "detail": "1 token revoked"}, {"label": "AI agents", "value": 34, "detail": "1 suspended"}, {"label": "MCP servers", "value": 11, "detail": "1 access denied"}],
        "incident": {"id": "INC-DEMO-2047", "title": "Agent manipulation preceded ransomware activity", "severity": "CRITICAL", "confidence": "HIGH", "status": "CONTAINED", "summary": "A poisoned email led to token abuse and abnormal agent requests. Deterministic controls denied expansion before endpoint ransomware behavior was isolated.", "affected": ["LT-0442", "jean.ellis", "build-agent-27"], "detections": [{"source": "FW-AID", "name": "Agent authority expansion", "confidence": "HIGH"}, {"source": "RANSOMGUARD", "name": "Abnormal mass file operations", "confidence": "HIGH"}, {"source": "IDENTITY", "name": "Access token anomaly", "confidence": "MEDIUM"}], "recovery": {"state": "READY / SIMULATED", "checkpoint": "REC-DEMO-LT0442-18", "integrity": "SIMULATED VERIFICATION", "execution": "NOT EXECUTED"}, "mitre": ["T1566.001 Spearphishing Attachment", "T1078 Valid Accounts", "T1486 Data Encrypted for Impact"]},
        "attack_story": [{"time": "14:01", "domain": "EMAIL", "title": "Malicious attachment opened", "state": "DETECTED"}, {"time": "14:03", "domain": "IDENTITY", "title": "Access token used from a new session", "state": "CORRELATED"}, {"time": "14:05", "domain": "AI AGENT", "title": "Prompt-injection indicators observed", "state": "ELEVATED"}, {"time": "14:06", "domain": "FW-HARNESS", "title": "Shell and expanded MCP authority denied", "state": "DENIED"}, {"time": "14:07", "domain": "FW-AID", "title": "Agent lease revoked and session suspended", "state": "CONTAINED"}, {"time": "14:07", "domain": "RANSOMGUARD", "title": "Abnormal mass file operations stopped", "state": "CONTAINED"}, {"time": "14:08", "domain": "RECOVERY", "title": "Known-good recovery snapshot located", "state": "READY"}],
        "ai_security": {"active_agents": 33, "suspended_agents": 1, "actions_denied_today": 17, "prompt_injection_signals": 3, "risk": "ELEVATED / CONTROLLED", "events": ["build-agent-27 requested shell capability — denied", "build-agent-27 requested expanded lease — denied", "Unapproved MCP tool request raised risk threshold"]},
        "harness": {"task_id": "HARNESS-DEMO-842", "requester": "jean.ellis", "risk_tier": "T3", "model": "Approved security-critical coding model", "routing_reason": "AI security and authority-boundary scope", "phase": "ACCEPTED", "budget": {"used": 64, "limit": 100, "unit": "percent"}, "capabilities": ["repository:bounded-read", "patch:scoped-write", "tests:approved"], "lease": "REVOKED AFTER POLICY ANOMALY", "validation": "PASSED (SIMULATED)", "review": "APPROVE / LOW (SIMULATED)", "workflow": ["TASK", "CLASSIFY", "AUTHORIZE", "MODEL", "EXECUTE", "TEST", "REVIEW", "ACCEPT"]},
        "actions": [{"action": "Agent lease revoked", "target": "build-agent-27", "status": "SIMULATED"}, {"action": "Endpoint isolated", "target": "LT-0442", "status": "SIMULATED"}, {"action": "Identity token revoked", "target": "jean.ellis", "status": "SIMULATED"}, {"action": "Recovery snapshot selected", "target": "LT-0442", "status": "SIMULATED"}],
        "evidence": {"bundle_id": "EVID-DEMO-7F31", "records": 28, "chain_status": "SIMULATED / NOT CRYPTOGRAPHICALLY VERIFIED", "related_ticket": "AT-DEMO-119"},
        "implementation": {"mission_control_ui": "DEMO_AVAILABLE", "demo_scenario": "TESTED", "incident_correlation": "PARTIAL", "ai_intrusion_defense": "TESTED_FIXTURE_ONLY", "containment_execution": "PLANNED", "production_backend": "NOT_CONNECTED"},
    }
    return deepcopy(snapshot)
