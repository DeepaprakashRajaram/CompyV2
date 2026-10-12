import pytest
from pathlib import Path
from datetime import datetime, timezone
from jinja2 import Environment, FileSystemLoader

from fmd.v2.domain.reasoning.investigation import InvestigationDossier
from fmd.v2.domain.contracts import TriState, EvidenceId, ProviderId
from fmd.v2.domain.reporting.models import ForensicReportModel
from fmd.v2.adapters.reporting.mapper import dossier_to_report_dict
from fmd.v2.adapters.reporting.html_to_pdf_renderer import (
    generate_donut_chart,
    generate_risk_gauge,
    generate_process_tree_svg,
    generate_qr_code_svg,
)

TEMPLATES_DIR = Path(__file__).resolve().parent.parent.parent / "src" / "fmd" / "v2" / "adapters" / "reporting" / "templates"

@pytest.fixture
def jinja_env():
    return Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)), autoescape=True)

def render_report_html(jinja_env, report_data: dict) -> str:
    template = jinja_env.get_template("report.html.j2")
    counts = report_data.get("summary", {}).get("counts_by_severity", {})
    donut_svg = generate_donut_chart(counts)
    risk_score = report_data.get("summary", {}).get("risk_score", 0)
    risk_gauge_svg = generate_risk_gauge(risk_score)
    process_tree = report_data.get("process_tree", [])
    process_tree_svg = generate_process_tree_svg(process_tree)
    case_id = report_data.get("case", {}).get("id", "CASE-000")
    sha256 = report_data.get("evidence", {}).get("sha256", "UNKNOWN")
    qr_code_svg = generate_qr_code_svg(f"{case_id}:{sha256[:16]}")
    
    return template.render(
        data=report_data,
        css_content="/* test css */",
        donut_svg=donut_svg,
        risk_gauge_svg=risk_gauge_svg,
        process_tree_svg=process_tree_svg,
        qr_code_svg=qr_code_svg
    )

def test_verdict_not_detected_has_no_unconditional_compromise(jinja_env):
    """When verdict is NOT DETECTED, report must not claim system compromise or universal cleanliness."""
    dossier = InvestigationDossier(
        investigation_id="INV-CLEAN-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.FALSE
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="clean_image.raw",
        file_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        file_size="4.00 GB",
        is_synthetic_demo=False
    )
    assert report_dict["summary"]["verdict"] == "NOT DETECTED"

    html = render_report_html(jinja_env, report_dict)

    # Must NOT assert compromise
    assert "was actively compromised" not in html
    assert "conclusively demonstrates that the subject host was subjected to an advanced in-memory fileless cyber attack" not in html

    # Must accurately state no detections occurred within executed checks
    assert "no malicious indicators or structural discrepancies were detected" in html
    # Must explicitly disclaim universal cleanliness
    assert "does not claim or imply that the subject system is universally clean" in html

def test_verdict_unknown_inconclusive(jinja_env):
    """When verdict is UNKNOWN, report must state that available evidence is insufficient."""
    dossier = InvestigationDossier(
        investigation_id="INV-UNKNOWN-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.UNKNOWN
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="unknown_image.raw",
        file_hash="222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
        file_size="8.00 GB",
        is_synthetic_demo=False
    )
    assert report_dict["summary"]["verdict"] == "UNKNOWN"

    html = render_report_html(jinja_env, report_dict)

    assert "was actively compromised" not in html
    assert "inconclusive outcome" in html
    assert "insufficient to formulate a definitive finding" in html

def test_verdict_partial(jinja_env):
    """When verdict is PARTIAL, report must state analysis was only partially completed."""
    dossier = InvestigationDossier(
        investigation_id="INV-PARTIAL-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.UNKNOWN
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="partial_image.raw",
        file_hash="33334444555566667777888899990000aaaabbbbccccddddeeeeffff11112222",
        file_size="8.00 GB",
        is_synthetic_demo=False
    )
    report_dict["summary"]["verdict"] = "PARTIAL"

    html = render_report_html(jinja_env, report_dict)

    assert "was actively compromised" not in html
    assert "was only partially completed" in html
    assert "execution gap limits interpretation" in html

def test_verdict_failed_unavailable(jinja_env):
    """When verdict is FAILED or UNAVAILABLE, report must not imply successful completion."""
    dossier = InvestigationDossier(
        investigation_id="INV-FAILED-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.UNKNOWN
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="failed_image.raw",
        file_hash="4444555566667777888899990000aaaabbbbccccddddeeeeffff111122223333",
        file_size="8.00 GB",
        is_synthetic_demo=False
    )
    report_dict["summary"]["verdict"] = "FAILED"

    html = render_report_html(jinja_env, report_dict)

    assert "was actively compromised" not in html
    assert "could not be completed due to execution failure" in html
    assert "does not constitute a completed forensic examination" in html

def test_synthetic_demo_content_marked_unmistakably(jinja_env):
    """Synthetic demo content must be unmistakably marked as synthetic across the report."""
    dossier = InvestigationDossier(
        investigation_id="INV-DEMO-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.TRUE
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="demo.raw",
        file_hash="555566667777888899990000aaaabbbbccccddddeeeeffff1111222233334444",
        file_size="8.00 GB",
        is_synthetic_demo=True
    )
    html = render_report_html(jinja_env, report_dict)

    assert "DEMONSTRATION NOTICE" in html
    assert "SYNTHETIC DEMONSTRATION" in html
    assert "This document was generated using synthetic demonstration fixtures" in html
    assert "was actively compromised by fileless malware residing in unbacked executable memory" not in html

def test_report_integrity_seal_terminology(jinja_env):
    """Mapper and template must use Report Integrity Seal terminology, not claiming domain ledger."""
    dossier = InvestigationDossier(
        investigation_id="INV-SEAL-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.FALSE
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="evidence.raw",
        file_hash="66667777888899990000aaaabbbbccccddddeeeeffff11112222333344445555",
        file_size="16.00 GB",
        is_synthetic_demo=False
    )

    # Verify dictionary data
    assert "report_integrity_seal" in report_dict
    seal_entries = report_dict["report_integrity_seal"]
    assert len(seal_entries) == 3
    for entry in seal_entries:
        assert entry["seal_type"] == "Report Integrity Seal"
        assert "hashed_fields" in entry
        assert "hash" in entry and len(entry["hash"]) == 64

    # Verify template rendered terminology
    html = render_report_html(jinja_env, report_dict)
    assert "Report Integrity Seal (Cryptographic Metadata Chain)" in html
    assert "Pipeline Custody &amp; Report Integrity Seal" in html
    # Must NOT claim to be the domain evidence ledger block chain
    assert "Immutable Evidence Ledger (Cryptographic Block Chain)" not in html
    assert "It does not replace the domain Evidence Ledger" in html

def test_default_report_has_no_unsupported_credentials_or_statutory_cert(jinja_env):
    """Default report must not include hardcoded Government of India, fake signatories, or Section 65B statutory claims."""
    dossier = InvestigationDossier(
        investigation_id="INV-GENERIC-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.FALSE
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="clean.raw",
        file_hash="7777888899990000aaaabbbbccccddddeeeeffff111122223333444455556666",
        file_size="8.00 GB",
        is_synthetic_demo=False
    )
    html = render_report_html(jinja_env, report_dict)

    # Must NOT contain invented government credentials or fake officers
    assert "Government of India" not in html
    assert "Deputy Superintendent" not in html
    assert "Cyber Forensic Division" not in html
    assert "Section 65B of the Indian Evidence Act" not in html
    assert "Designated Special Court" not in html

    # Must contain generic DFIR disclaimer stating software does not independently certify admissibility
    assert "Technical Findings Declaration &amp; Evidentiary Disclaimer" in html
    assert "independently satisfy statutory chain of custody requirements" in html
    assert "legal admissibility" in html

def test_seal_verification_tamper_detection(jinja_env):
    """Report Integrity Seal must detect tampering and never claim VALID/VERIFIED when tampered."""
    from fmd.v2.adapters.reporting.mapper import verify_report_integrity_seal

    dossier = InvestigationDossier(
        investigation_id="INV-SEAL-02",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.FALSE
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="test.raw",
        file_hash="888899990000aaaabbbbccccddddeeeeffff1111222233334444555566667777",
        file_size="4.00 GB",
        is_synthetic_demo=False
    )
    
    # 1. Untampered seal must verify
    outcome = verify_report_integrity_seal(report_dict["report_integrity_seal"])
    assert outcome["status"] == "CRYPTOGRAPHICALLY_VERIFIED"
    assert outcome["is_verified"] is True
    html_valid = render_report_html(jinja_env, report_dict)
    assert "METADATA SEAL: CRYPTOGRAPHICALLY VERIFIED" in html_valid
    assert "METADATA SEAL CRYPTOGRAPHICALLY VERIFIED" in html_valid

    # 2. Tampered block hash must fail verification
    tampered_dict = dict(report_dict)
    tampered_seal = [dict(e) for e in report_dict["report_integrity_seal"]]
    tampered_seal[1]["hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    tampered_dict["report_integrity_seal"] = tampered_seal
    
    outcome_tampered = verify_report_integrity_seal(tampered_seal)
    assert outcome_tampered["status"] == "INVALID"
    assert outcome_tampered["is_verified"] is False
    
    tampered_dict["report_integrity_seal_status"] = outcome_tampered
    html_tampered = render_report_html(jinja_env, tampered_dict)
    assert "METADATA SEAL: CRYPTOGRAPHICALLY VERIFIED" not in html_tampered
    assert "INTEGRITY SEAL: VALID" not in html_tampered
    assert "SEAL INTEGRITY VERIFICATION FAILED" in html_tampered
    assert "SEAL: PAYLOAD HASH MISMATCH" in html_tampered or "SEAL: BROKEN CHAIN LINK" in html_tampered

    # 3. Tampered payload with unchanged stored hash must fail verification (DEF-05)
    payload_tampered_seal = [dict(e) for e in report_dict["report_integrity_seal"]]
    payload_tampered_seal[0]["payload"] = dict(payload_tampered_seal[0]["payload"])
    payload_tampered_seal[0]["payload"]["evidence_sha256"] = "0000000000000000000000000000000000000000000000000000000000000000"
    outcome_payload_tampered = verify_report_integrity_seal(payload_tampered_seal)
    assert outcome_payload_tampered["status"] == "INVALID"
    assert outcome_payload_tampered["is_verified"] is False
    assert "PAYLOAD HASH MISMATCH" in outcome_payload_tampered["label"]

def test_adversarial_report_integrity_seal_matrix():
    """
    Exhaustively tests all 11 adversarial cases required by Master Moderator Directive:
    1. Valid intact seal.
    2. Modified payload with unchanged stored hash.
    3. Modified stored block hash.
    4. Broken previous-hash link.
    5. Reordered, duplicated, or missing blocks.
    6. Missing or malformed required payload fields.
    7. Changed verdict, investigation ID, report/file hash, and timestamp.
    8. Altered evidence references or other protected fields.
    9. Empty seal, absent seal, and verification not executed.
    10. Malformed outer input, including non-iterable values and invalid entry types.
    11. Verification exception handling: must never claim verification on exception.
    """
    from fmd.v2.adapters.reporting.mapper import verify_report_integrity_seal, dossier_to_report_dict
    import copy

    dossier = InvestigationDossier(
        investigation_id="INV-ADV-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.FALSE
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="adversarial.raw",
        file_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        file_size="8.00 GB",
        is_synthetic_demo=False
    )
    base_seal = report_dict["report_integrity_seal"]

    # Case 1: Valid intact seal
    c1 = verify_report_integrity_seal(base_seal, expected_report_data=report_dict)
    assert c1["status"] == "CRYPTOGRAPHICALLY_VERIFIED"
    assert c1["is_verified"] is True

    # Case 2: Modified payload with unchanged stored hash
    c2_seal = copy.deepcopy(base_seal)
    c2_seal[0]["payload"]["evidence_sha256"] = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    c2 = verify_report_integrity_seal(c2_seal)
    assert c2["status"] == "INVALID"
    assert c2["is_verified"] is False
    assert "PAYLOAD HASH MISMATCH" in c2["label"]

    # Case 3: Modified stored block hash
    c3_seal = copy.deepcopy(base_seal)
    c3_seal[1]["hash"] = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    c3 = verify_report_integrity_seal(c3_seal)
    assert c3["status"] == "INVALID"
    assert c3["is_verified"] is False
    assert "PAYLOAD HASH MISMATCH" in c3["label"] or "BROKEN CHAIN LINK" in c3["label"]

    # Case 4: Broken previous-hash link
    c4_seal = copy.deepcopy(base_seal)
    c4_seal[2]["prev_hash"] = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
    c4 = verify_report_integrity_seal(c4_seal)
    assert c4["status"] == "INVALID"
    assert c4["is_verified"] is False
    assert "BROKEN CHAIN LINK" in c4["label"]

    # Case 5: Reordered, duplicated, or missing blocks
    # 5a: Reordered
    c5a = verify_report_integrity_seal([base_seal[1], base_seal[0], base_seal[2]])
    assert c5a["status"] == "INVALID"
    assert c5a["is_verified"] is False
    # 5b: Duplicated
    c5b = verify_report_integrity_seal([base_seal[0], base_seal[0], base_seal[2]])
    assert c5b["status"] == "INVALID"
    assert c5b["is_verified"] is False
    # 5c: Missing
    c5c = verify_report_integrity_seal([base_seal[0], base_seal[1]])
    assert c5c["status"] == "INVALID"
    assert c5c["is_verified"] is False
    assert "INVALID STRUCTURE" in c5c["label"]

    # Case 6: Missing or malformed required payload fields
    c6_seal = copy.deepcopy(base_seal)
    del c6_seal[1]["payload"]["verdict"]
    c6 = verify_report_integrity_seal(c6_seal)
    assert c6["status"] == "INVALID"
    assert c6["is_verified"] is False
    assert "MISSING PAYLOAD FIELDS" in c6["label"]

    # Case 7: Changed verdict, investigation ID, report/file hash, and timestamp
    # 7a: Changed verdict in expected report data
    tampered_verdict_dict = copy.deepcopy(report_dict)
    tampered_verdict_dict["summary"]["verdict"] = "DETECTED"
    c7a = verify_report_integrity_seal(base_seal, expected_report_data=tampered_verdict_dict)
    assert c7a["status"] == "INVALID"
    assert c7a["is_verified"] is False
    assert "DATA BINDING MISMATCH" in c7a["label"]

    # 7b: Changed investigation ID in expected report data
    tampered_id_dict = copy.deepcopy(report_dict)
    tampered_id_dict["case"]["id"] = "INV-TAMPERED-99"
    c7b = verify_report_integrity_seal(base_seal, expected_report_data=tampered_id_dict)
    assert c7b["status"] == "INVALID"
    assert c7b["is_verified"] is False
    assert "DATA BINDING MISMATCH" in c7b["label"]

    # 7c: Changed timestamp inside block
    c7c_seal = copy.deepcopy(base_seal)
    c7c_seal[0]["ts"] = "2020-01-01T00:00:00Z"
    c7c = verify_report_integrity_seal(c7c_seal)
    assert c7c["status"] == "INVALID"
    assert c7c["is_verified"] is False

    # Case 8: Altered evidence references
    tampered_ev_dict = copy.deepcopy(report_dict)
    tampered_ev_dict["evidence"]["sha256"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    c8 = verify_report_integrity_seal(base_seal, expected_report_data=tampered_ev_dict)
    assert c8["status"] == "INVALID"
    assert c8["is_verified"] is False
    assert "DATA BINDING MISMATCH (evidence_sha256)" in c8["label"]

    # Case 9: Empty seal, absent seal, and verification not executed
    c9a = verify_report_integrity_seal([])
    assert c9a["status"] == "INVALID"
    assert c9a["is_verified"] is False
    assert "INVALID STRUCTURE" in c9a["label"]

    c9b = verify_report_integrity_seal(None)
    assert c9b["status"] == "INVALID"
    assert c9b["is_verified"] is False
    assert "MALFORMED INPUT" in c9b["label"]

    # Unexecuted verification in dossier mapper
    unverified_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="test.raw",
        file_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        file_size="8.00 GB",
        verify_seal=False
    )
    assert unverified_dict["report_integrity_seal_status"]["status"] == "UNVERIFIED"
    assert unverified_dict["report_integrity_seal_status"]["is_verified"] is False

    # Case 10: Malformed outer input (DEF-08)
    for bad_input in [12345, 99.9, True, "not_a_seal", {"a": 1}, [1, 2, 3], ["entry1", "entry2", "entry3"]]:
        outcome = verify_report_integrity_seal(bad_input)
        assert outcome["status"] == "INVALID"
        assert outcome["is_verified"] is False
        assert "MALFORMED INPUT" in outcome["label"] or "INVALID ENTRY TYPE" in outcome["label"]

    # Case 11: Verification exception safety
    malformed_obj_seal = [{"n": 1}, {"n": 2}, {"n": 3}]
    outcome_err = verify_report_integrity_seal(malformed_obj_seal)
    assert outcome_err["status"] == "INVALID"
    assert outcome_err["is_verified"] is False

def test_heuristic_score_terminology_never_percentage_or_probability(jinja_env):
    """
    DEF-06: Heuristic severity/triage score must NEVER be rendered as a percentage
    probability (e.g. 'CONFIDENCE: 85%') or presented as calibrated statistical certainty.
    """
    from fmd.v2.domain.contracts import EvidenceId, ProviderId
    from fmd.v2.adapters.providers.hidden_process_detector import HiddenProcessObservation
    from fmd.v2.adapters.providers.process_tree_detector import ProcessTreeObservation
    from fmd.v2.domain.reasoning.corroboration import InvestigationCandidate
    from fmd.v2.adapters.web.report import generate_forensic_report
    import tempfile, os

    obs_dkom = HiddenProcessObservation(
        _detector_id=ProviderId("hidden_process_rootkit_v1"),
        _target=EvidenceId("node_1"),
        description="Cross-view process discrepancy: unlinked EPROCESS structure",
        confidence=0.85,
        heuristic_severity=0.85,
        anomaly_category="ROOTKIT_DKOM",
        process_pid=4444,
        process_name="evil_stealth.exe",
        ppid=4,
        thread_count=3
    )
    obs_ppid = ProcessTreeObservation(
        _detector_id=ProviderId("process_tree_anomaly_v1"),
        _target=EvidenceId("node_2"),
        description="PPID anomaly: explorer spawning services",
        confidence=0.92,
        anomaly_category="SYSTEM_MASQUERADE",
        process_pid=5555,
        process_name="services.exe",
        ppid=1234,
        expected_parent="wininit.exe",
        actual_parent="explorer.exe"
    )

    candidate = InvestigationCandidate(
        _id="CANDIDATE-01",
        hypothesis_description="Test Candidate",
        related_observations=[obs_dkom, obs_ppid]
    )

    dossier = InvestigationDossier(
        investigation_id="INV-TRIAGE-01",
        created_at=datetime.now(timezone.utc),
        candidates=[candidate],
        system_status=TriState.TRUE
    )

    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="triage_test.raw",
        file_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
        file_size="8.00 GB"
    )

    html = render_report_html(jinja_env, report_dict)

    # 1. Must NOT contain percentage confidence badges or labels
    assert "CONFIDENCE: 85%" not in html
    assert "CONFIDENCE: 92%" not in html
    assert "CONFIDENCE: 85" not in html
    assert "85% probability" not in html

    # 2. Must contain explicit TRIAGE SCORE or decimal formatting
    assert "TRIAGE SCORE: 0.85" in html
    assert "Triage Score" in html

    # 3. Test PDF generation report headers
    with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp_pdf:
        pdf_path = tmp_pdf.name
    try:
        generate_forensic_report(
            dossier=dossier,
            file_name="triage_test.raw",
            file_hash="1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff",
            file_size="8.00 GB",
            output_path=pdf_path
        )
        assert os.path.exists(pdf_path)
        assert os.path.getsize(pdf_path) > 1000
    finally:
        if os.path.exists(pdf_path):
            os.remove(pdf_path)

def test_absence_of_residual_statutory_and_law_enforcement_labels(jinja_env):
    """
    DEF-07: Residual statutory-certification labels (Sec 65B PDF) and invented authority
    (Law Enforcement / Police) must be entirely absent from reports and UI templates.
    """
    from pathlib import Path

    dossier = InvestigationDossier(
        investigation_id="INV-RESIDUAL-01",
        created_at=datetime.now(timezone.utc),
        candidates=[],
        system_status=TriState.FALSE
    )
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name="clean.raw",
        file_hash="222233334444555566667777888899990000aaaabbbbccccddddeeeeffff1111",
        file_size="4.00 GB",
        is_synthetic_demo=False
    )
    html = render_report_html(jinja_env, report_dict)

    # 1. HTML Report must NOT have residual 'Sec 65B PDF' or Law Enforcement watermark
    assert "Sec 65B PDF" not in html
    assert "CONFIDENTIAL // LAW ENFORCEMENT &amp; JUDICIAL PROCEEDINGS" not in html
    assert "DFIR PDF" in html
    assert "CONFIDENTIAL // DIGITAL FORENSIC INVESTIGATION RECORD" in html

    # 2. Web template index.html check
    index_html_path = Path("src/fmd/v2/adapters/web/templates/index.html")
    assert index_html_path.exists()
    index_content = index_html_path.read_text(encoding="utf-8")

    assert "Section 65B DFIR Reporting" not in index_content
    assert "Law Enforcement Forensic Engine" not in index_content
    assert "Authorized Law Enforcement & Digital Forensics Use Only" not in index_content
    assert "DFIR Forensic Reporting" in index_content

def test_page_6_and_business_impact_fallbacks_never_claim_compromise(jinja_env):
    """Neither Page 6 threat assessment nor business impact fallback may claim compromise on non-DETECTED verdicts."""
    verdicts = ["NOT DETECTED", "UNKNOWN", "PARTIAL", "FAILED"]
    for verdict in verdicts:
        dossier = InvestigationDossier(
            investigation_id=f"INV-{verdict}-01",
            created_at=datetime.now(timezone.utc),
            candidates=[],
            system_status=TriState.FALSE if verdict == "NOT DETECTED" else TriState.UNKNOWN
        )
        report_dict = dossier_to_report_dict(
            dossier=dossier,
            file_name="sample.raw",
            file_hash="99990000aaaabbbbccccddddeeeeffff11112222333344445555666677778888",
            file_size="4.00 GB",
            is_synthetic_demo=False
        )
        report_dict["summary"]["verdict"] = verdict
        html = render_report_html(jinja_env, report_dict)

        # Compromise claims must never appear
        assert "was actively compromised" not in html
        assert "active credential harvesting, internal reconnaissance" not in html
        assert "high-risk malicious anomalies discovered during analysis" not in html
