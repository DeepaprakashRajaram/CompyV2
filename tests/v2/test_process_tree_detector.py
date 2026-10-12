import pytest
from datetime import datetime, timezone
import uuid

from fmd.v2.adapters.providers.process_tree_detector import ProcessTreeAnomalyDetector
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.evidence.nodes import ProcessNode
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.domain.contracts import ProviderId, EvidenceId, CapabilityStatus

@pytest.fixture
def test_provenance():
    return ProvenanceRecord(
        _provider_id=ProviderId("test_provider"),
        _artifact_identity="test_art_01",
        _acquisition_mode="TEST",
        acquisition_time=datetime.now(timezone.utc)
    )

def test_process_tree_clean_baseline(test_provenance):
    ledger = EvidenceLedger()
    detector = ProcessTreeAnomalyDetector()

    # Legitimate hierarchy: System (4) -> wininit (100) -> services (200) -> svchost (300)
    p_system = ProcessNode(_id=EvidenceId("1"), pid=4, name="System", ppid=0)
    p_wininit = ProcessNode(_id=EvidenceId("2"), pid=100, name="wininit.exe", ppid=4)
    p_services = ProcessNode(_id=EvidenceId("3"), pid=200, name="services.exe", ppid=100)
    p_svchost = ProcessNode(_id=EvidenceId("4"), pid=300, name="svchost.exe", ppid=200)

    for p in (p_system, p_wininit, p_services, p_svchost):
        ledger.append_node(p, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 0

def test_process_tree_svchost_masquerade(test_provenance):
    ledger = EvidenceLedger()
    detector = ProcessTreeAnomalyDetector()

    # Malicious: explorer (1000) spawns svchost (2000)
    p_explorer = ProcessNode(_id=EvidenceId("1"), pid=1000, name="explorer.exe", ppid=500)
    p_svchost_fake = ProcessNode(_id=EvidenceId("2"), pid=2000, name="svchost.exe", ppid=1000)

    ledger.append_node(p_explorer, test_provenance)
    ledger.append_node(p_svchost_fake, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 1  # Exactly one observation (no double-counting)
    assert result.observations[0].anomaly_category == "SYSTEM_MASQUERADE"

def test_process_tree_exploit_spawn(test_provenance):
    ledger = EvidenceLedger()
    detector = ProcessTreeAnomalyDetector()

    # Office macro exploit: winword.exe spawns powershell.exe
    p_word = ProcessNode(_id=EvidenceId("1"), pid=1500, name="winword.exe", ppid=1000)
    p_ps = ProcessNode(_id=EvidenceId("2"), pid=1600, name="powershell.exe", ppid=1500)

    ledger.append_node(p_word, test_provenance)
    ledger.append_node(p_ps, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.anomaly_category == "EXPLOIT_SPAWN"
    assert obs.process_pid == 1600
    assert "winword.exe" in obs.description
