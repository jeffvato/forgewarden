"""Executable current-commit ForgeWarden product Golden Path.

The proof composes accepted local DRY_RUN contracts. It does not invoke a
provider, execute a proposed response, resolve a credential, or mutate Git.
"""
from __future__ import annotations

import json
import subprocess
from dataclasses import replace
from pathlib import Path

import pytest

from swarm.action_ticket import ActionTicket, ActionTicketError, ActionTicketRegistry
from swarm.ai_agent_defense import (
    AICrossDomainCorrelator,
    AIContainmentProposalRegistry,
    AIThreatClassificationError,
    CrossDomainSecurityFact,
    DeterministicAIThreatClassifier,
    HarnessAIDMonitorAdapter,
    HarnessMonitorBinding,
)
from swarm.asoc import HMACLeaseSigner
from swarm.core import AuditLog
from swarm.evidence import CanonicalAuditEvidenceStore, EvidenceLedger
from swarm.harness_evidence import HarnessLifecycleEvidence, append_harness_evidence
from swarm.identity import IdentityContractError, IdentityRegistry, validate_identity_record
from swarm.integrity import FUNCTIONALITY_MAP, audit_completed_requirement_work
from swarm.mission_control import project_ai_security, serialize_capability_status, serialize_evidence_activity
from swarm.normalized_events import NormalizedEventStore
from swarm.policy_gate import DeterministicPolicy, PolicyContext, PolicyInvariantError, PolicyRule, validate_safety_evidence
from swarm.recovery import RecoveryCheckpoint, RecoveryContractError, ResumeAdmissionDecision, ResumeDecision, admit_interruption, recovery_checkpoint_digest


TENANT = "tenant-golden"
TASK = "FWQ-0100"
REQUIREMENT = "FW-INTEGRITY-005"


def _head(root: Path) -> str:
    result = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True,
        capture_output=True, check=True, timeout=10,
    )
    return result.stdout.strip()


def _identity(identity_id: str, kind: str, owner: str) -> dict[str, object]:
    return {
        "schema_version": "1", "identity_id": identity_id, "tenant_id": TENANT,
        "identity_kind": kind, "owner_identity_ref": owner,
        "purpose": "bounded product Golden Path", "lifecycle_state": "ACTIVE",
        "created_at_epoch": 100, "lifecycle_changed_at_epoch": 100,
        "expires_at_epoch": 500 if kind != "HUMAN" else None,
        "provider_subject_ref": None, "credential_handle_ref": None,
    }


def _lifecycle() -> HarnessLifecycleEvidence:
    return HarnessLifecycleEvidence(
        1, "task_denied", TENANT, TASK, REQUIREMENT, "harness-controller",
        "golden-agent", "openai", "approved-test-model", "a" * 64,
        ("source.write",), ("secret.read",), ("secret.read",),
        ("tests/test_product_golden_path.py",), (), (), (), "DENIED", "DENIED",
        "2026-09-13T12:00:00Z", None, (),
    )


def test_current_commit_cross_family_product_golden_path(tmp_path: Path) -> None:
    root = Path(__file__).parents[1]
    head = _head(root)
    emitted: list[tuple[str, object]] = []

    identities = IdentityRegistry(lambda event, fact: emitted.append((event, fact)))
    owner = identities.register(validate_identity_record(_identity("fw-id/golden-owner", "HUMAN", "fw-id/golden-owner")))
    agent = identities.register(validate_identity_record(_identity("fw-id/golden-agent", "AI_AGENT", owner.identity_id)))
    assert identities.get(agent.identity_id, tenant_id=TENANT) is agent
    with pytest.raises(IdentityContractError, match="tenant mismatch"):
        identities.get(agent.identity_id, tenant_id="tenant-other")

    agent_ref = f"fw-id/{TENANT}/{agent.identity_id.removeprefix('fw-id/')}"
    context = PolicyContext(TENANT, agent_ref, "endpoint.isolate.request", "endpoint/golden-1", "ISOLATE_ENDPOINT", "FW-GOLDEN-v1")
    policy = DeterministicPolicy((PolicyRule(TENANT, context.capability, context.resource, context.action_class, context.policy_version),))
    assert policy.evaluate(context).allowed
    assert not policy.evaluate(replace(context, policy_version="FW-GOLDEN-v2")).allowed
    with pytest.raises(PolicyInvariantError):
        validate_safety_evidence({"mode": "LIVE", "deployment": "DISABLED", "kill_switch": "ENGAGED", "mutation_allowed": False}, require_kill_switch=True)

    tickets = ActionTicketRegistry(HMACLeaseSigner({"fw-keys/golden-test": b"deterministic-test-only-material"}))
    ticket = tickets.issue(ActionTicket(
        "ticket-golden-1", TENANT, agent_ref, "lease-golden-1", context.capability,
        context.resource, context.action_class, "golden-owner", "approval-golden-1",
        context.policy_version, 100, 300, "fw-keys/golden-test",
    ))
    consumed = tickets.validate_and_consume(
        ticket.ticket_id, tenant_id=TENANT, subject_agent_id=agent_ref,
        lease_id=ticket.lease_id, capability=context.capability,
        resource=context.resource, action_class=context.action_class,
        policy_version=context.policy_version, now=150,
    )
    assert consumed.consumed_at == 150
    with pytest.raises(ActionTicketError, match="replay"):
        tickets.validate_and_consume(
            ticket.ticket_id, tenant_id=TENANT, subject_agent_id=agent_ref,
            lease_id=ticket.lease_id, capability=context.capability,
            resource=context.resource, action_class=context.action_class,
            policy_version=context.policy_version, now=151,
        )
    expired = tickets.issue(replace(ticket, ticket_id="ticket-golden-expired", signature="", consumed_at=None))
    with pytest.raises(ActionTicketError, match="not currently valid"):
        tickets.validate_and_consume(
            expired.ticket_id, tenant_id=TENANT, subject_agent_id=agent_ref,
            lease_id=expired.lease_id, capability=context.capability,
            resource=context.resource, action_class=context.action_class,
            policy_version=context.policy_version, now=301,
        )

    evidence_path = tmp_path / "canonical-evidence.jsonl"
    ledger = EvidenceLedger(TENANT, CanonicalAuditEvidenceStore(AuditLog(evidence_path)))
    harness_record = append_harness_evidence(
        _lifecycle(), ledger=ledger,
        correlation_id=f"fw-corr/{TENANT}/golden-path",
    )
    recovered = CanonicalAuditEvidenceStore(AuditLog(evidence_path)).recover(TENANT)
    evidence_view = serialize_evidence_activity(recovered.tenant_snapshot(TENANT))
    assert evidence_view["data_mode"] == "CANONICAL"
    assert evidence_view["view"]["chain_status"] == "DIGEST_AND_CHAIN_VALIDATED"
    assert evidence_view["view"]["signature_status"] == "NOT_PRESENT"

    event_store = NormalizedEventStore(lambda event, fact: emitted.append((event, fact)))
    event_store.admit_fixture({
        "event_id": "endpoint-golden-1", "tenant_id": TENANT,
        "device_id": "device-golden-1", "observed_at_epoch": 100,
        "event_type": "PROCESS_START", "source": "LINUX_SENSOR",
        "process": {"pid": "42"}, "evidence_ref": f"fw-evid/{TENANT}/endpoint/1",
        "process_ancestry": [], "related_indicators": ["ai-origin"],
    }, tenant_id=TENANT, device_id="device-golden-1", source="LINUX_SENSOR", now_epoch=150)
    event_store.admit_ai_endpoint_attribution({
        "schema_version": "1", "tenant_id": TENANT, "device_id": "device-golden-1",
        "endpoint_event_id": "endpoint-golden-1", "agent_ref": agent_ref,
        "session_ref": f"fw-session/{TENANT}/golden-1", "task_ref": f"fw-task/{TENANT}/{TASK.lower()}",
        "capability_lease_ref": f"fw-lease/{TENANT}/golden-1",
        "action_ticket_ref": f"fw-action/{TENANT}/golden-1", "observed_at_epoch": 100,
        "evidence_references": [f"fw-evid/{TENANT}/endpoint/1"],
        "mode": "DRY_RUN", "action": "CORRELATE_ONLY", "authority_granted": False,
    })
    binding = HarnessMonitorBinding(
        f"fw-event/{TENANT}/lifecycle-1", f"fw-session/{TENANT}/golden-1",
        f"fw-lease/{TENANT}/golden-1", f"fw-action/{TENANT}/golden-1",
        "registered-mcp", f"fw-resource/{TENANT}/repository",
        (harness_record.envelope.evidence_id,),
    )
    monitor = HarnessAIDMonitorAdapter(TENANT, event_store)
    security_event = monitor.observe(_lifecycle(), binding)
    assert security_event.agent_ref == agent_ref and security_event.decision == "DENIED"
    with pytest.raises(AIThreatClassificationError, match="admission"):
        monitor.observe(_lifecycle(), binding)
    with pytest.raises(AIThreatClassificationError, match="admission"):
        monitor.observe(_lifecycle(), replace(binding, event_id="fw-event/tenant-other/lifecycle-2"))
    finding = DeterministicAIThreatClassifier(TENANT, lambda event, fact: emitted.append((event, fact))).classify(
        security_event, finding_id=f"fw-finding/{TENANT}/secret-1",
    )
    facts = (
        CrossDomainSecurityFact(TENANT, "ENDPOINT", f"fw-fact/{TENANT}/ENDPOINT/endpoint-1", "device/golden-1", 100, f"fw-evid/{TENANT}/endpoint/1"),
        CrossDomainSecurityFact(TENANT, "IDENTITY", f"fw-fact/{TENANT}/IDENTITY/identity-1", agent_ref, 110, f"fw-evid/{TENANT}/identity/1"),
        CrossDomainSecurityFact(TENANT, "MCP", f"fw-fact/{TENANT}/MCP/mcp-1", "mcp/registered-mcp", 120, f"fw-evid/{TENANT}/mcp/1"),
    )
    story = AICrossDomainCorrelator(TENANT, lambda event, fact: emitted.append((event, fact))).correlate(
        finding, security_event, facts, story_id="story-golden-1",
        ai_incident_id="incident-ai-golden", domain_incident_id="incident-endpoint-golden",
    )
    with pytest.raises(AIThreatClassificationError, match="chronology or replay"):
        AICrossDomainCorrelator(TENANT, lambda *_args: None).correlate(
            finding, security_event, (facts[0], facts[0], facts[2]), story_id="story-golden-duplicate",
            ai_incident_id="incident-ai-duplicate", domain_incident_id="incident-endpoint-duplicate",
        )
    proposal = AIContainmentProposalRegistry(TENANT, lambda event, fact: emitted.append((event, fact))).propose(
        finding, story, proposal_id=f"fw-proposal/{TENANT}/golden-1",
        target_ref=f"fw-resource/{TENANT}/agent", blast_radius=1,
        policy_decision_ref=f"fw-policy/{TENANT}/golden-1",
        capability_lease_ref=f"fw-lease/{TENANT}/golden-1",
        action_ticket_ref=f"fw-action/{TENANT}/golden-1",
        approval_ref=f"fw-approval/{TENANT}/golden-1",
        checkpoint_ref=f"fw-checkpoint/{TENANT}/golden-1",
        rollback_ref=f"fw-rollback/{TENANT}/golden-1",
        evidence_references=(f"fw-evid/{TENANT}/story/1",),
        created_at_epoch=200, lease_expires_at_epoch=500,
    )
    with pytest.raises(AIThreatClassificationError, match="policy bounds"):
        AIContainmentProposalRegistry(TENANT, lambda *_args: None).propose(
            finding, story, proposal_id=f"fw-proposal/{TENANT}/golden-invalid",
            target_ref=f"fw-resource/{TENANT}/agent", blast_radius=0,
            policy_decision_ref=f"fw-policy/{TENANT}/golden-1",
            capability_lease_ref=f"fw-lease/{TENANT}/golden-1",
            action_ticket_ref=f"fw-action/{TENANT}/golden-1",
            approval_ref=f"fw-approval/{TENANT}/golden-1",
            checkpoint_ref=f"fw-checkpoint/{TENANT}/golden-1",
            rollback_ref=f"fw-rollback/{TENANT}/golden-1",
            evidence_references=(f"fw-evid/{TENANT}/story/1",),
            created_at_epoch=200, lease_expires_at_epoch=500,
        )
    ai_view = project_ai_security(
        tenant_id=TENANT, events=(security_event,), findings=(finding,),
        stories=(story,), proposals=(proposal,),
    )
    assert proposal.disposition == "PROPOSE_ONLY" and proposal.response_executed is False
    assert ai_view.kill_switch == "ENGAGED" and ai_view.deployment == "DISABLED" and ai_view.mutation_allowed is False

    checkpoint = RecoveryCheckpoint(
        "1", f"fw-rec/{TENANT}/golden-1", TENANT, TASK, REQUIREMENT,
        "running", "worker", head, head, "b" * 64, "NOT_RUN", "NOT_RUN",
        (f"fw-action/{TENANT}/golden-1", f"fw-lease/{TENANT}/golden-1"), True,
        1, 3, 0, 2, harness_record.record_sha256, "2026-09-13T12:01:00Z",
        "PROCESS_EXIT", ResumeDecision.RESUME, "DRY_RUN", "DISABLED", False,
    )
    resume = admit_interruption(
        checkpoint, admission_id=f"fw-rec-admission/{TENANT}/golden-1",
        checkpoint_sha256=recovery_checkpoint_digest(checkpoint), tenant_id=TENANT,
        current_commit=head, evidence_tail_sha256=harness_record.record_sha256,
        kill_switch="ENGAGED", authority_current=True,
        occurred_at="2026-09-13T12:02:00Z", evidence_sink=lambda fact: emitted.append(("FW_REC_RESUME_ADMISSION", fact)),
    )
    assert resume.decision is ResumeAdmissionDecision.RESUME and resume.authority_granted is False
    with pytest.raises(RecoveryContractError, match="cross-tenant"):
        admit_interruption(
            checkpoint, admission_id="fw-rec-admission/tenant-other/golden-1",
            checkpoint_sha256=recovery_checkpoint_digest(checkpoint), tenant_id="tenant-other",
            current_commit=head, evidence_tail_sha256=harness_record.record_sha256,
            kill_switch="ENGAGED", authority_current=True,
            occurred_at="2026-09-13T12:02:00Z", evidence_sink=lambda _fact: None,
        )

    capability = serialize_capability_status(FUNCTIONALITY_MAP, audit_completed_requirement_work(root))
    assert capability["data_mode"] == "CANONICAL"
    assert capability["view"]["operating_mode"] == "DRY_RUN"
    assert capability["view"]["live_enabled"] is False
    assert capability["view"]["production_ready"] is False
    assert capability["safety"]["mutation_allowed"] is False
    assert {
        "fw_id_registered", "endpoint_event_admitted", "ai_endpoint_attribution_admitted",
        "ai_security_event_admitted", "ai_threat_finding_admitted",
        "soc_attack_story_projected", "ai_containment_proposal_recorded",
        "FW_REC_RESUME_ADMISSION",
    }.issubset({item[0] for item in emitted})

    summary = {
        "schema_version": 1,
        "proof": "CURRENT_COMMIT_EXECUTED",
        "commit": head,
        "tenant": TENANT,
        "families": ["FW-ID", "FW-ROOT", "FW-HARNESS", "FW-ENDPOINT", "FW-AID", "FW-SOC", "FW-EVID", "FW-REC", "FW-UX", "FW-INTEGRITY"],
        "assertions": {
            "identity_tenant_bound": True, "policy_deterministic": True,
            "ticket_single_use": True, "evidence_chain_validated": True,
            "ai_response_proposal_only": True, "resume_advisory_only": True,
            "mission_control_read_only": True,
        },
        "mode": "DRY_RUN", "deployment": "DISABLED", "kill_switch": "ENGAGED",
        "live_enabled": False, "production_ready": False, "authority_granted": False,
    }
    print("FW_PRODUCT_GOLDEN_PATH=" + json.dumps(summary, sort_keys=True, separators=(",", ":")))
    assert len(json.dumps(summary)) < 2048
    assert not any(token in json.dumps(summary).lower() for token in ("password=", "api_key=", "bearer "))
