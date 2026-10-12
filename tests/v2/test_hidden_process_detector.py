import pytest
from datetime import datetime, timezone

from fmd.v2.adapters.providers.hidden_process_detector import HiddenProcessDetector, HiddenProcessObservation
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.evidence.nodes import ProcessNode
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.domain.evidence.mapper import EvidenceMapper
from fmd.v2.adapters.providers.volatility.dtos import ProcessDTO
from fmd.v2.domain.contracts import ProviderId, EvidenceId, CapabilityStatus

@pytest.fixture
def test_provenance():
    return ProvenanceRecord(
        _provider_id=ProviderId("test_provider"),
        _artifact_identity="test_art_02",
        _acquisition_mode="TEST",
        acquisition_time=datetime.now(timezone.utc)
    )

def test_process_present_in_both_views_no_discrepancy(test_provenance):
    """A process present in both PSLIST and PSSCAN is correlated; no discrepancy is emitted."""
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    p_list = ProcessNode(_id=EvidenceId("1"), pid=1000, name="svchost.exe", ppid=4, source_view="PSLIST", is_hidden=False)
    p_scan = ProcessNode(_id=EvidenceId("2"), pid=1000, name="svchost.exe", ppid=4, source_view="PSSCAN", is_hidden=False)

    ledger.append_node(p_list, test_provenance)
    ledger.append_node(p_scan, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 0

def test_process_present_only_in_psscan_discrepancy_detected(test_provenance):
    """A process found by PSSCAN but absent from PSLIST is detected as an unlinked discrepancy."""
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    p_normal_list = ProcessNode(_id=EvidenceId("1"), pid=4, name="System", ppid=0, source_view="PSLIST", is_hidden=False)
    p_normal_scan = ProcessNode(_id=EvidenceId("2"), pid=4, name="System", ppid=0, source_view="PSSCAN", is_hidden=False)
    # Active process carved from pool, absent from PSLIST
    p_unlinked = ProcessNode(
        _id=EvidenceId("3"),
        pid=6666,
        name="rootkit_stealth.exe",
        ppid=4,
        source_view="PSSCAN",
        is_hidden=False,
        threads=8
    )

    ledger.append_node(p_normal_list, test_provenance)
    ledger.append_node(p_normal_scan, test_provenance)
    ledger.append_node(p_unlinked, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 1

    obs = result.observations[0]
    assert obs.anomaly_category == "ROOTKIT_DKOM"
    assert obs.process_pid == 6666
    assert obs.thread_count == 8
    assert "cross-view process discrepancy" in obs.description.lower()
    assert obs.target_evidence_id == EvidenceId("3")
    assert obs.source_view == "PSSCAN"
    assert obs.heuristic_severity == 0.85
    assert obs.confidence == 0.85

def test_process_present_only_in_pslist_normal(test_provenance):
    """A process present in PSLIST but absent from PSSCAN is not an unlinked discrepancy."""
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    p_list = ProcessNode(_id=EvidenceId("1"), pid=1200, name="explorer.exe", ppid=4, source_view="PSLIST", is_hidden=False)
    ledger.append_node(p_list, test_provenance)

    # Add a PSSCAN entry for another process so PSSCAN view is present
    p_sys_scan = ProcessNode(_id=EvidenceId("2"), pid=4, name="System", ppid=0, source_view="PSSCAN", is_hidden=False)
    p_sys_list = ProcessNode(_id=EvidenceId("3"), pid=4, name="System", ppid=0, source_view="PSLIST", is_hidden=False)
    ledger.append_node(p_sys_scan, test_provenance)
    ledger.append_node(p_sys_list, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 0

def test_incomplete_or_unavailable_views_conservative(test_provenance):
    """Missing or incomplete views must produce explicit UNAVAILABLE capability status with failure reason."""
    detector = HiddenProcessDetector()

    # Case A: Only PSSCAN available (PSLIST missing)
    ledger_scan_only = EvidenceLedger()
    p_scan = ProcessNode(_id=EvidenceId("1"), pid=5000, name="process.exe", source_view="PSSCAN", is_hidden=False)
    ledger_scan_only.append_node(p_scan, test_provenance)
    result_a = detector.evaluate(ledger_scan_only, ledger_scan_only)
    assert result_a.status == CapabilityStatus.UNAVAILABLE
    assert len(result_a.observations) == 0
    assert result_a.failure_reason is not None
    assert "PSLIST" in result_a.failure_reason

    # Case B: Only PSLIST available (PSSCAN missing / unexecuted)
    ledger_list_only = EvidenceLedger()
    p_list = ProcessNode(_id=EvidenceId("2"), pid=5000, name="process.exe", source_view="PSLIST", is_hidden=False)
    ledger_list_only.append_node(p_list, test_provenance)
    result_b = detector.evaluate(ledger_list_only, ledger_list_only)
    assert result_b.status == CapabilityStatus.UNAVAILABLE
    assert len(result_b.observations) == 0
    assert result_b.failure_reason is not None
    assert "PSSCAN" in result_b.failure_reason

    # Case C: Empty ledger (both missing)
    ledger_empty = EvidenceLedger()
    result_c = detector.evaluate(ledger_empty, ledger_empty)
    assert result_c.status == CapabilityStatus.UNAVAILABLE
    assert len(result_c.observations) == 0
    assert result_c.failure_reason is not None
    assert "Process evidence is unavailable" in result_c.failure_reason

def test_psscan_executed_zero_structures_distinguished_from_unexecuted(test_provenance):
    """Successfully executed PSSCAN with 0 carved structures must result in SUCCESS with 0 findings, not UNAVAILABLE."""
    from fmd.v2.domain.evidence.nodes import ScanMetadataNode
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    # PSLIST has active processes
    p_sys = ProcessNode(_id=EvidenceId("1"), pid=4, name="System", source_view="PSLIST")
    ledger.append_node(p_sys, test_provenance)
    
    # PSSCAN executed and finished with 0 carved structures
    scan_meta = ScanMetadataNode(_id=EvidenceId("scan_meta_01"), scan_name="PSSCAN", status="COMPLETED", item_count=0)
    ledger.append_node(scan_meta, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 0
    assert result.failure_reason is None

def test_pid_reuse_and_identity_ambiguity(test_provenance):
    """PID reuse with differing process names or creation times must be distinguished conservatively."""
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    t1 = datetime(2026, 10, 11, 8, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 10, 11, 9, 30, 0, tzinfo=timezone.utc)

    # PID 2000 in PSLIST is legit_service.exe created at t2
    p_list = ProcessNode(_id=EvidenceId("1"), pid=2000, name="legit_service.exe", create_time=t2, source_view="PSLIST")
    # PID 2000 in PSSCAN is old_malware.exe created at t1 (PID reuse)
    p_scan_reuse = ProcessNode(_id=EvidenceId("2"), pid=2000, name="old_malware.exe", create_time=t1, source_view="PSSCAN")
    # PID 3000 in PSSCAN has exit_time set (terminated process)
    p_scan_exited = ProcessNode(_id=EvidenceId("3"), pid=3000, name="exited_worker.exe", exit_time=t1, source_view="PSSCAN")

    ledger.append_node(p_list, test_provenance)
    ledger.append_node(p_scan_reuse, test_provenance)
    ledger.append_node(p_scan_exited, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    # Only the active unlinked process with PID reuse is flagged, exited process is ignored
    assert len(result.observations) == 1
    assert result.observations[0].process_pid == 2000
    assert result.observations[0].process_name == "old_malware.exe"
    assert "pid reuse" in result.observations[0].description.lower()

def test_absence_of_collector_generated_is_hidden_flag(test_provenance):
    """Detector operates on view correlation without reliance on is_hidden flag."""
    ledger = EvidenceLedger()
    detector = HiddenProcessDetector()

    # Both nodes have is_hidden=False explicitly
    p_list = ProcessNode(_id=EvidenceId("1"), pid=4, name="System", source_view="PSLIST", is_hidden=False)
    p_scan_normal = ProcessNode(_id=EvidenceId("2"), pid=4, name="System", source_view="PSSCAN", is_hidden=False)
    p_scan_unlinked = ProcessNode(_id=EvidenceId("3"), pid=8888, name="unlinked.exe", source_view="PSSCAN", is_hidden=False)

    ledger.append_node(p_list, test_provenance)
    ledger.append_node(p_scan_normal, test_provenance)
    ledger.append_node(p_scan_unlinked, test_provenance)

    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 1
    assert result.observations[0].process_pid == 8888

def test_duplicate_observations_and_provenance(test_provenance):
    """EvidenceMapper deduplicates duplicate raw inputs from the same origin; provenance is preserved."""
    ledger = EvidenceLedger()
    mapper = EvidenceMapper(ledger)

    # Ingest duplicate DTOs from same origin
    dto1 = ProcessDTO(pid=5000, ppid=4, image_file_name="worker.exe", offset=0x1000, source_view="PSSCAN", is_hidden=False)
    dto2 = ProcessDTO(pid=5000, ppid=4, image_file_name="worker.exe", offset=0x1000, source_view="PSSCAN", is_hidden=False)
    dto_list = ProcessDTO(pid=4, ppid=0, image_file_name="System", offset=0x2000, source_view="PSLIST", is_hidden=False)

    mapper.ingest_process_list([dto1, dto2, dto_list], test_provenance)

    all_nodes = ledger.get_all_nodes()
    proc_nodes = [n for n in all_nodes if isinstance(n, ProcessNode)]
    # 2 distinct processes should be in ledger (dto2 was deduplicated)
    assert len(proc_nodes) == 2

    detector = HiddenProcessDetector()
    result = detector.evaluate(ledger, ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 1
    obs = result.observations[0]
    assert obs.process_pid == 5000
    assert obs.source_view == "PSSCAN"
    assert obs.detector_id == ProviderId("hidden_process_rootkit_v1")
