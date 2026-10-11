import os
import json
import tempfile
import pytest
from pathlib import Path

from fmd.v2.domain.reporting.models import ForensicReportModel
from fmd.v2.adapters.reporting.html_to_pdf_renderer import HtmlToPdfRenderer
from fmd.v2.adapters.reporting.mapper import dossier_to_report_dict
from fmd.v2.domain.reasoning.investigation import InvestigationDossier
from fmd.v2.domain.contracts import TriState, EvidenceId, ProviderId
from fmd.v2.adapters.providers.process_tree_detector import ProcessTreeObservation
from fmd.v2.adapters.providers.hidden_process_detector import HiddenProcessObservation
from fmd.v2.domain.reasoning.corroboration import InvestigationCandidate

def test_html_to_pdf_renderer_with_sample_report():
    sample_json_path = Path("sample_report.json")
    assert sample_json_path.exists(), "sample_report.json must exist in repository root"
    
    data = json.loads(sample_json_path.read_text(encoding="utf-8"))
    
    # Validate against Pydantic domain model
    model = ForensicReportModel.model_validate(data)
    assert model.case.id == "CASE-2026-CYBER-884"
    assert model.summary.verdict == "DETECTED"
    assert len(model.findings) == 4
    
    renderer = HtmlToPdfRenderer()
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
        pdf_path = tmp_pdf.name
    html_path = pdf_path.replace(".pdf", ".html")
    
    try:
        result = renderer.render(
            report_data=data,
            output_pdf_path=pdf_path,
            output_html_path=html_path
        )
        assert os.path.exists(result.pdf_path)
        assert os.path.exists(result.html_path)
        assert result.page_count >= 8, f"Expected at least 8 pages, got {result.page_count}"
        assert result.file_size_bytes > 50000, "PDF artifact size should be substantive"
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)
        if os.path.exists(html_path):
            os.remove(html_path)

def test_dossier_to_report_dict_mapping():
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

    from datetime import datetime, timezone
    dossier = InvestigationDossier(
        investigation_id="INV-TEST-999",
        created_at=datetime.now(timezone.utc),
        candidates=[candidate],
        system_status=TriState.TRUE
    )

    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="memory.raw",
        file_hash="abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
        file_size="8.00 GB",
        examiner_name="Inspector Test",
        agency_name="State Cyber Unit"
    )

    # Validate schema
    validated = ForensicReportModel.model_validate(report_dict)
    assert validated.case.id == "INV-TEST-999"
    assert validated.summary.verdict == "DETECTED"
    assert len(validated.findings) >= 2
    assert len(validated.ppid_anomalies) == 1
    assert len(validated.hidden_processes) == 1
