import os
import tempfile
from datetime import datetime, timezone

from fmd.v2.domain.reasoning.investigation import InvestigationDossier
from fmd.v2.domain.contracts import TriState, EvidenceId, ProviderId
from fmd.v2.adapters.providers.process_tree_detector import ProcessTreeObservation
from fmd.v2.adapters.providers.hidden_process_detector import HiddenProcessObservation
from fmd.v2.domain.reasoning.corroboration import InvestigationCandidate
from fmd.v2.adapters.web.report import generate_forensic_report

def test_generate_forensic_report_with_anomalies():
    # Construct synthetic observations
    obs_ppid = ProcessTreeObservation(
        _detector_id=ProviderId("process_tree_anomaly_v1"),
        _target=EvidenceId("node_1"),
        description="CRITICAL PPID ANOMALY: svchost spawned by explorer",
        confidence=0.95,
        anomaly_category="SYSTEM_MASQUERADE",
        process_pid=3000,
        process_name="svchost.exe",
        ppid=1000,
        expected_parent="services.exe",
        actual_parent="explorer.exe"
    )

    obs_rootkit = HiddenProcessObservation(
        _detector_id=ProviderId("hidden_process_rootkit_v1"),
        _target=EvidenceId("node_2"),
        description="STEALTH ROOTKIT: unlinked process",
        confidence=0.98,
        anomaly_category="ROOTKIT_DKOM",
        process_pid=7777,
        process_name="stealth_driver.exe",
        ppid=4,
        thread_count=5
    )

    candidate = InvestigationCandidate(
        _id="CANDIDATE-01",
        hypothesis_description="Composite malware hypothesis",
        related_observations=[obs_ppid, obs_rootkit]
    )

    dossier = InvestigationDossier(
        investigation_id="INV-TEST-001",
        created_at=datetime.now(timezone.utc),
        candidates=[candidate],
        system_status=TriState.TRUE
    )

    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
        output_pdf = tmp.name

    try:
        result_path = generate_forensic_report(
            dossier=dossier,
            file_name="evidence_ram.raw",
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size="16.00 GB",
            output_path=output_pdf
        )

        assert os.path.exists(result_path)
        assert os.path.getsize(result_path) > 1000  # PDF generated with content
    finally:
        if os.path.exists(output_pdf):
            os.remove(output_pdf)
