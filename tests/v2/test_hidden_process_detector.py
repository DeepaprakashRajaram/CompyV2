import pytest
from datetime import datetime, timezone

from fmd.v2.adapters.providers.hidden_process_detector import HiddenProcessDetector
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.evidence.nodes import ProcessNode
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.domain.contracts import ProviderId, EvidenceId, CapabilityStatus

@pytest.fixture
def test_provenance():
    return ProvenanceRecord(
        _provider_id=ProviderId("test_provider"),
        _artifact_identity="test_art_02",
        _acquisition_mode="TEST",
        acquisition_time=datetime.now(timezone.utc)
    )

def test_hidden_process_detector_clean(test_provenance):
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    p1 = ProcessNode(_id=EvidenceId("1"), pid=4, name="System", ppid=0, is_hidden=False)
    p2 = ProcessNode(_id=EvidenceId("2"), pid=1000, name="explorer.exe", ppid=4, is_hidden=False)

    ledger.append_node(p1, test_provenance)
    ledger.append_node(p2, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 0

def test_hidden_process_detector_detects_rootkit(test_provenance):
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    # Normal process
    p_normal = ProcessNode(_id=EvidenceId("1"), pid=4, name="System", ppid=0, is_hidden=False)
    # Hidden rootkit process unlinked via DKOM
    p_stealth = ProcessNode(
        _id=EvidenceId("2"), 
        pid=6666, 
        name="rootkit_stealth.exe", 
        ppid=4, 
        is_hidden=True,
        threads=8
    )

    ledger.append_node(p_normal, test_provenance)
    ledger.append_node(p_stealth, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 1
    
    obs = result.observations[0]
    assert obs.anomaly_category == "ROOTKIT_DKOM"
    assert obs.process_pid == 6666
    assert obs.thread_count == 8
    assert "STEALTH ROOTKIT" in obs.description
