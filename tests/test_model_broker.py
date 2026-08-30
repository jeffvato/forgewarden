import pytest

from swarm.model_broker import ApprovedModel, ModelBroker, ModelBrokerError


def approval() -> ApprovedModel:
    return ApprovedModel(
        "tenant-a", "agent-a", "triage-model", "approved-provider", "triage-prod",
        "2026.08", "model-approval-1",
    )


def test_model_broker_is_tenant_bound_and_version_exact():
    broker = ModelBroker()
    broker.register(approval())
    assert broker.allows(
        tenant_id="tenant-a", subject_agent_id="agent-a", model="triage-model",
        provider="approved-provider", deployment="triage-prod", version="2026.08",
        approval_version="model-approval-1",
    )
    assert not broker.allows(
        tenant_id="tenant-b", subject_agent_id="agent-a", model="triage-model",
        provider="approved-provider", deployment="triage-prod", version="2026.08",
        approval_version="model-approval-1",
    )
    assert not broker.allows(
        tenant_id="tenant-a", subject_agent_id="agent-a", model="triage-model",
        provider="approved-provider", deployment="triage-prod", version="2026.09",
        approval_version="model-approval-1",
    )


def test_model_broker_rejects_duplicate_tenant_agent_approval():
    broker = ModelBroker()
    broker.register(approval())
    with pytest.raises(ModelBrokerError, match="already exists"):
        broker.register(approval())


def test_model_broker_revocation_is_tenant_scoped_and_fail_closed():
    broker = ModelBroker()
    broker.register(approval())
    broker.register(ApprovedModel(
        "tenant-b", "agent-b", "triage-model", "approved-provider", "triage-prod",
        "2026.08", "model-approval-1",
    ))
    assert broker.revoke_matching(tenant_id="tenant-a") == 1
    assert not broker.allows(
        tenant_id="tenant-a", subject_agent_id="agent-a", model="triage-model",
        provider="approved-provider", deployment="triage-prod", version="2026.08",
        approval_version="model-approval-1",
    )
    assert broker.allows(
        tenant_id="tenant-b", subject_agent_id="agent-b", model="triage-model",
        provider="approved-provider", deployment="triage-prod", version="2026.08",
        approval_version="model-approval-1",
    )
