import hashlib

import pytest

from swarm.quarantine import QuarantineProposalDenied, propose_quarantine


def _kwargs(audit):
    return dict(
        tenant_id="tenant-a", device_id="device-a", detection_id="det-1",
        provenance="trusted-catalog:v1", confidence="HIGH", trusted_content=True,
        policy_decision="ALLOW_QUARANTINE", audit=audit,
    )


def test_quarantine_proposal_is_bounded_evidence_first_and_non_executing():
    events = []
    proposal = propose_quarantine(b"fixture-malware", **_kwargs(lambda *args: events.append(args)))
    assert proposal.content_sha256 == hashlib.sha256(b"fixture-malware").hexdigest()
    assert proposal.content_bytes == len(b"fixture-malware")
    assert proposal.mode == "DRY_RUN"
    assert proposal.action == "DETECT_ONLY"
    assert proposal.disposition == "PROPOSED"
    assert events[0][0] == "quarantine_proposed"


@pytest.mark.parametrize("overrides", [
    {"confidence": "MEDIUM"},
    {"trusted_content": False},
    {"policy_decision": "DENY"},
])
def test_quarantine_proposal_denies_without_evidence_for_unsafe_policy(overrides):
    events = []
    values = _kwargs(lambda *args: events.append(args))
    values.update(overrides)
    with pytest.raises(QuarantineProposalDenied, match="QUARANTINE_POLICY_DENIED"):
        propose_quarantine(b"fixture", **values)
    assert events == []


def test_quarantine_proposal_fails_closed_when_evidence_is_unavailable():
    def fail(*_args):
        raise OSError("sink unavailable")
    with pytest.raises(QuarantineProposalDenied, match="EVIDENCE_WRITE_FAILED"):
        propose_quarantine(b"fixture", **_kwargs(fail))
