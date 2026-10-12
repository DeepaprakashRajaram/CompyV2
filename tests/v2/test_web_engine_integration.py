"""
WHAT: Compy V2 Web Adapter ↔ Real Engine End-to-End Integration Test Suite.
WHY: Validates all Phase 6 Master Moderator acceptance criteria (Tests A through J).
COVERS:
- Test A: Demo isolation
- Test B: Real-mode input reaches the provider
- Test C: No mock fallback (honest capability reporting)
- Test D: Unsupported input format rejection
- Test E: Empty but valid results (accurate execution boundaries)
- Test F: Missing capabilities explicitly reported as NOT_RUN/UNAVAILABLE
- Test G: Evidence provenance in findings
- Test H: Report integrity (no fabricated hex dumps, C2 IPs, or named pipes)
- Test I: Error isolation (clean failure reporting)
- Test J: Deterministic execution results
"""

import os
import hashlib
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest
from fastapi.testclient import TestClient

from fmd.v2.adapters.web.app import app, JOBS_DB, REPORTS_DB
from fmd.v2.domain.contracts import (
    ICollector,
    ProviderId,
    ProviderResult,
    CapabilityStatus,
    ProviderCapability,
    IProviderResult,
    TriState
)
from fmd.v2.domain.evidence.provenance import ProvenanceRecord


@pytest.fixture(autouse=True)
def reset_web_state():
    """Ensures test isolation between test cases."""
    JOBS_DB.clear()
    REPORTS_DB.clear()
    app.state.custom_collector = None
    yield
    JOBS_DB.clear()
    REPORTS_DB.clear()
    app.state.custom_collector = None


@pytest.fixture
def client():
    return TestClient(app)


# ==============================================================================
# TEST FIXTURES / INSTRUMENTED COLLECTORS
# ==============================================================================

class RecordingCollector(ICollector):
    """Instrumented test collector that records exactly what inputs it receives."""
    def __init__(self, target_path: str, artifact_hash: str):
        self.recorded_path = target_path
        self.recorded_hash = artifact_hash

    def provider_id(self) -> ProviderId:
        return ProviderId("recording_collector_v1")

    def extract_evidence(self) -> IProviderResult:
        # Returns minimal clean processes
        processes = [
            {"pid": 4, "name": "System", "ppid": 0},
            {"pid": 100, "name": "smss.exe", "ppid": 4}
        ]
        prov = ProvenanceRecord(
            _provider_id=self.provider_id(),
            _artifact_identity=self.recorded_hash,
            _acquisition_mode="OFFLINE",
            acquisition_time=datetime.now(timezone.utc)
        )
        return ProviderResult(
            _capability_status=CapabilityStatus.SUCCESS,
            _available_capabilities=frozenset([ProviderCapability.PROCESS_LIST]),
            _extracted_dtos=(processes, []),
            _capability_failures=tuple(),
            _provenance=prov
        )


class CleanTestCollector(ICollector):
    """Provides a known clean baseline without anomalies."""
    def __init__(self, target_path: str = "test.raw", artifact_hash: str = "hash123"):
        self.target_path = target_path
        self.artifact_hash = artifact_hash

    def provider_id(self) -> ProviderId:
        return ProviderId("clean_collector_v1")

    def extract_evidence(self) -> IProviderResult:
        processes = [
            {"pid": 4, "name": "System", "ppid": 0},
            {"pid": 100, "name": "smss.exe", "ppid": 4},
            {"pid": 200, "name": "csrss.exe", "ppid": 100},
            {"pid": 300, "name": "wininit.exe", "ppid": 100},
            {"pid": 400, "name": "services.exe", "ppid": 300},
            {"pid": 500, "name": "lsass.exe", "ppid": 300},
            {"pid": 1000, "name": "explorer.exe", "ppid": 4}
        ]
        prov = ProvenanceRecord(
            _provider_id=self.provider_id(),
            _artifact_identity=self.artifact_hash,
            _acquisition_mode="OFFLINE",
            acquisition_time=datetime.now(timezone.utc)
        )
        return ProviderResult(
            _capability_status=CapabilityStatus.SUCCESS,
            _available_capabilities=frozenset([ProviderCapability.PROCESS_LIST]),
            _extracted_dtos=(processes, []),
            _capability_failures=tuple(),
            _provenance=prov
        )


class AnomalyTestCollector(ICollector):
    """Provides verifiable evidence with both PPID anomaly and DKOM unlinked PID."""
    def __init__(self, target_path: str = "anomaly.raw", artifact_hash: str = "hash_anomaly"):
        self.target_path = target_path
        self.artifact_hash = artifact_hash

    def provider_id(self) -> ProviderId:
        return ProviderId("anomaly_collector_v1")

    def extract_evidence(self) -> IProviderResult:
        # PPID anomaly: powershell.exe spawned directly by services.exe
        # DKOM unlinked anomaly: rootkit.exe appears in psscan but missing from pslist
        processes = [
            {"pid": 4, "name": "System", "ppid": 0},
            {"pid": 100, "name": "smss.exe", "ppid": 4},
            {"pid": 1000, "name": "explorer.exe", "ppid": 4},
            {"pid": 2000, "name": "winword.exe", "ppid": 1000},
            {"pid": 4820, "name": "powershell.exe", "ppid": 2000}, # Exploit spawn: winword.exe spawns powershell.exe
            {"pid": 6666, "name": "hidden_rootkit.exe", "ppid": 4, "is_hidden": True, "threads": 3} # DKOM rootkit
        ]
        prov = ProvenanceRecord(
            _provider_id=self.provider_id(),
            _artifact_identity=self.artifact_hash,
            _acquisition_mode="OFFLINE",
            acquisition_time=datetime.now(timezone.utc)
        )
        return ProviderResult(
            _capability_status=CapabilityStatus.SUCCESS,
            _available_capabilities=frozenset([ProviderCapability.PROCESS_LIST]),
            _extracted_dtos=(processes, []),
            _capability_failures=tuple(),
            _provenance=prov
        )


class FailingCollector(ICollector):
    """Simulates internal provider error."""
    def provider_id(self) -> ProviderId:
        return ProviderId("failing_collector_v1")

    def extract_evidence(self) -> IProviderResult:
        raise RuntimeError("Simulated acquisition bus fault")


# ==============================================================================
# PHASE 6 TESTS A - J
# ==============================================================================

def test_a_demo_isolation(client):
    """
    Test A — Demo isolation:
    A demo request produces explicitly labeled synthetic results.
    It does not claim to have analyzed a real input file.
    """
    resp = client.post("/api/analyze/demo", json={"sample_name": "CobaltStrike_Beacon_Sample"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "DEMO"
    assert data["is_synthetic_demo"] is True
    job_id = data["job_id"]

    # Poll status
    status_resp = client.get(f"/api/status/{job_id}")
    assert status_resp.status_code == 200
    job = status_resp.json()
    assert job["status"] == "completed"
    assert job["mode"] == "DEMO"
    assert job["is_synthetic_demo"] is True

    # Check JSON export
    inv_id = job["investigation_id"]
    json_resp = client.get(f"/report/download/json/{inv_id}")
    assert json_resp.status_code == 200
    report_json = json_resp.json()
    assert report_json["mode"] == "DEMO"
    assert report_json["is_synthetic_demo"] is True
    assert "SYNTHETIC DEMONSTRATION" in report_json["disclaimer"]


def test_b_real_mode_input_reaches_provider(client, tmp_path):
    """
    Test B — Real-mode input reaches the provider:
    Proves that the website request passes the exact input identity and computed hash
    to the configured application/provider boundary.
    """
    test_raw = tmp_path / "memory_image.raw"
    test_content = b"GENUINE_MEMORY_BYTES_TEST_PAYLOAD_999"
    test_raw.write_bytes(test_content)
    expected_hash = hashlib.sha256(test_content).hexdigest()

    recorded_instances = []
    def recording_factory(path, artifact_hash):
        instance = RecordingCollector(path, artifact_hash)
        recorded_instances.append(instance)
        return instance

    app.state.custom_collector = recording_factory

    resp = client.post("/api/analyze", json={"file_path": str(test_raw)})
    assert resp.status_code == 200
    data = resp.json()
    assert data["mode"] == "REAL"
    assert data["is_synthetic_demo"] is False
    job_id = data["job_id"]

    # Verify that the provider was called with exact path and SHA-256 hash
    assert len(recorded_instances) == 1
    assert recorded_instances[0].recorded_path == str(test_raw)
    assert recorded_instances[0].recorded_hash == expected_hash

    # Verify execution finished in real mode
    job_resp = client.get(f"/api/status/{job_id}")
    job = job_resp.json()
    assert job["status"] == "completed"
    assert job["mode"] == "REAL"
    assert job["is_synthetic_demo"] is False


def test_c_no_mock_fallback(client, tmp_path, monkeypatch):
    """
    Test C — No mock fallback:
    When the real provider or required symbols are unavailable,
    the request returns an explicit failure/capability result.
    It must NOT produce a synthetic Cobalt Strike finding.
    """
    test_raw = tmp_path / "target_memory.raw"
    test_raw.write_bytes(b"TEST_RAW_DUMP")

    # Ensure no custom test collector is registered and volatility3 is unavailable
    app.state.custom_collector = None
    import fmd.v2.adapters.web.app as web_app
    monkeypatch.setattr(
        web_app, 
        "create_real_app", 
        lambda **kwargs: (
            None, 
            "Forensic provider 'volatility3' is not installed in runtime environment. "
            "Under Compy's FAIL_IF_MISSING policy, mock analysis will not be substituted."
        )
    )

    resp = client.post("/api/analyze", json={"file_path": str(test_raw)})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    job_resp = client.get(f"/api/status/{job_id}")
    job = job_resp.json()

    # The real engine must report unavailable, NOT complete with synthetic findings
    assert job["status"] == "unavailable"
    assert "Real forensic capability unavailable" in job["message"]
    assert "volatility3" in job["message"]
    # Must NOT have created a completed report with Cobalt Strike findings
    assert job.get("investigation_id") is None
    assert "finding" not in job or job["finding"] is None


def test_d_unsupported_input(client, tmp_path):
    """
    Test D — Unsupported input:
    An unsupported file format is rejected rather than treated as a successful scan.
    """
    bad_file = tmp_path / "notes.txt"
    bad_file.write_text("not a raw memory dump")

    resp = client.post("/api/analyze", json={"file_path": str(bad_file)})
    assert resp.status_code == 400
    assert "Unsupported format" in resp.json()["detail"]


def test_e_empty_but_valid_results(client, tmp_path):
    """
    Test E — Empty but valid results:
    A valid completed analysis with zero findings reports zero only for checks that actually ran.
    It does not imply universal cleanliness.
    """
    clean_raw = tmp_path / "clean_evidence.dmp"
    clean_raw.write_bytes(b"CLEAN_MEMORY_DUMP")

    app.state.custom_collector = CleanTestCollector()

    resp = client.post("/api/analyze", json={"file_path": str(clean_raw)})
    job_id = resp.json()["job_id"]

    job_resp = client.get(f"/api/status/{job_id}")
    job = job_resp.json()
    assert job["status"] == "completed"
    assert job["ppid_count"] == 0
    assert job["rootkit_count"] == 0
    assert job["indicators"]["ppid_status"] == "Baseline Verified (Executed)"
    assert job["indicators"]["rootkit_status"] == "Zero Unlinked PIDs (Executed)"

    # Verify JSON export execution summary
    inv_id = job["investigation_id"]
    json_resp = client.get(f"/report/download/json/{inv_id}")
    report_json = json_resp.json()
    assert report_json["execution_summary"]["executed_detectors"] == [
        "process_tree_anomaly_v1", "hidden_process_rootkit_v1"
    ]
    # Explicitly declares unexecuted checks rather than implying universal verification
    assert "VAD_INJECTION_SCAN" in report_json["execution_summary"]["unexecuted_checks"]


def test_f_missing_capabilities(client, tmp_path):
    """
    Test F — Missing capabilities:
    Unavailable checks appear as unexecuted or unavailable states, not as successful zero-count checks.
    """
    clean_raw = tmp_path / "clean_evidence.vmem"
    clean_raw.write_bytes(b"VMEM_SAMPLE")

    app.state.custom_collector = CleanTestCollector()

    resp = client.post("/api/analyze", json={"file_path": str(clean_raw)})
    job_id = resp.json()["job_id"]
    inv_id = client.get(f"/api/status/{job_id}").json()["investigation_id"]

    report_json = client.get(f"/report/download/json/{inv_id}").json()
    unexecuted = report_json["execution_summary"]["unexecuted_checks"]
    assert "SSDT_HOOK_AUDIT" in unexecuted
    assert "IDT_HOOK_AUDIT" in unexecuted
    assert "IRP_HOOK_AUDIT" in unexecuted


def test_g_evidence_provenance(client, tmp_path):
    """
    Test G — Evidence provenance:
    Every real-mode report finding can be traced to an actual observation or supported derived result.
    """
    anomaly_raw = tmp_path / "anomaly.mem"
    anomaly_raw.write_bytes(b"ANOMALY_MEMORY_BYTES")

    app.state.custom_collector = AnomalyTestCollector()

    resp = client.post("/api/analyze", json={"file_path": str(anomaly_raw)})
    job_id = resp.json()["job_id"]
    inv_id = client.get(f"/api/status/{job_id}").json()["investigation_id"]

    report_json = client.get(f"/report/download/json/{inv_id}").json()
    ppid_findings = report_json["findings"]["process_tree_anomalies"]
    rootkit_findings = report_json["findings"]["hidden_rootkits"]

    # Verify PPID finding points to powershell.exe with PID 4820
    assert len(ppid_findings) == 1
    assert ppid_findings[0]["pid"] == 4820
    assert ppid_findings[0]["process_name"] == "powershell.exe"
    assert ppid_findings[0]["actual_parent"] == "winword.exe"

    # Verify Rootkit finding points to hidden_rootkit.exe with PID 6666
    assert len(rootkit_findings) == 1
    assert rootkit_findings[0]["pid"] == 6666
    assert rootkit_findings[0]["process_name"] == "hidden_rootkit.exe"


def test_h_report_integrity(client, tmp_path):
    """
    Test H — Report integrity:
    A real dossier does not generate invented processes, memory regions, IOCs,
    YARA matches, fake C2 IPs, or fake named pipes.
    """
    clean_raw = tmp_path / "clean_sys.raw"
    clean_raw.write_bytes(b"CLEAN_SYSTEM_RAW")

    app.state.custom_collector = CleanTestCollector()

    resp = client.post("/api/analyze", json={"file_path": str(clean_raw)})
    inv_id = client.get(f"/api/status/{resp.json()['job_id']}").json()["investigation_id"]

    # 1. Check HTML output
    html_resp = client.get(f"/report/view/html/{inv_id}")
    assert html_resp.status_code == 200
    html_content = html_resp.text

    # Fabricated demo values MUST NOT appear in real report
    assert "198.51.100.44" not in html_content
    assert "msupdate_pipe" not in html_content
    assert "fc e8 82 00 00 00 60 89" not in html_content
    assert "0x000001B4D2000000" not in html_content # Fake demo injected memory region address

    # 2. Check JSON data
    json_resp = client.get(f"/report/download/json/{inv_id}")
    data = json_resp.json()
    assert data["metrics"]["ppid_anomalies_count"] == 0
    assert data["metrics"]["hidden_rootkits_count"] == 0


def test_i_error_isolation(client, tmp_path):
    """
    Test I — Error isolation:
    Malformed input and provider failure do not cause a fabricated success result.
    """
    # 1. Non-existent file path returns 404
    non_existent = tmp_path / "non_existent.raw"
    resp = client.post("/api/analyze", json={"file_path": str(non_existent)})
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()

    # 2. Failing provider records failed status in background task
    corrupt_raw = tmp_path / "corrupt.raw"
    corrupt_raw.write_bytes(b"CORRUPT")
    app.state.custom_collector = FailingCollector()

    resp = client.post("/api/analyze", json={"file_path": str(corrupt_raw)})
    assert resp.status_code == 200
    job_id = resp.json()["job_id"]

    job_resp = client.get(f"/api/status/{job_id}")
    job = job_resp.json()
    assert job["status"] == "failed"
    assert "Simulated acquisition bus fault" in job["message"]


def test_j_determinism(client, tmp_path):
    """
    Test J — Determinism:
    Equivalent inputs and identical deterministic configuration produce consistent evidence
    identities and results.
    """
    sample_file = tmp_path / "det_sample.raw"
    sample_file.write_bytes(b"DETERMINISTIC_INPUT_BYTES")

    app.state.custom_collector = CleanTestCollector()

    # Run 1
    resp1 = client.post("/api/analyze", json={"file_path": str(sample_file)})
    job1 = client.get(f"/api/status/{resp1.json()['job_id']}").json()

    # Run 2
    resp2 = client.post("/api/analyze", json={"file_path": str(sample_file)})
    job2 = client.get(f"/api/status/{resp2.json()['job_id']}").json()

    assert job1["finding"] == job2["finding"]
    assert job1["ppid_count"] == job2["ppid_count"]
    assert job1["rootkit_count"] == job2["rootkit_count"]
    assert job1["indicators"] == job2["indicators"]
