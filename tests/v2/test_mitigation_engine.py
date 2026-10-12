"""
Tests for Evidence-Backed Mitigation Engine in Compy V2.
"""

from datetime import datetime
import pytest

from fmd.v2.domain.contracts import CapabilityStatus, TriState, ProviderId, EvidenceId
from fmd.v2.domain.reasoning.investigation import InvestigationDossier
from fmd.v2.domain.reasoning.corroboration import InvestigationCandidate
from fmd.v2.domain.reasoning.mitigation import (
    MitigationEngine,
    MitigationPriority,
    MitigationActionType,
    MitigationRecommendation
)
from fmd.v2.adapters.providers.injected_code_detector import InjectedCodeObservation
from fmd.v2.adapters.providers.hidden_process_detector import HiddenProcessObservation
from fmd.v2.adapters.providers.process_tree_detector import ProcessTreeObservation
from fmd.v2.adapters.providers.yara.detector import YaraObservation
from fmd.v2.adapters.providers.mock_detector import MockDetectorResult

def test_mitigation_empty_dossier_no_fabricated_recommendations():
    dossier = InvestigationDossier(
        investigation_id="INV-001",
        created_at=datetime.now(),
        candidates=[],
        capability_failures=[]
    )
    recs = MitigationEngine.generate_recommendations(dossier)
    assert len(recs) == 0

def test_mitigation_for_injected_code_requires_human_authorization():
    obs = InjectedCodeObservation(
        _detector_id=ProviderId("malfind"),
        _target=EvidenceId("evid-inj-1"),
        description="Unbacked RWX allocation with PE MZ header",
        process_pid=4444,
        process_name="svchost.exe",
        start_address=0x7fff0000,
        end_address=0x7fff1000,
        protection="PAGE_EXECUTE_READWRITE"
    )
    candidate = InvestigationCandidate(
        _id="cand-1",
        hypothesis_description="Injected code hypothesis",
        related_observations=[obs]
    )
    dossier = InvestigationDossier(
        investigation_id="INV-002",
        created_at=datetime.now(),
        candidates=[candidate],
        capability_failures=[]
    )

    recs = MitigationEngine.generate_recommendations(dossier)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.priority == MitigationPriority.CRITICAL
    assert rec.action_type == MitigationActionType.CONTAINMENT
    assert rec.human_authorization_required is True
    assert rec.target_evidence_id == "evid-inj-1"
    assert "PID 4444" in rec.recommended_action
    assert "isolate endpoint" in rec.recommended_action.lower()

def test_mitigation_for_hidden_process_dkom():
    obs = HiddenProcessObservation(
        _detector_id=ProviderId("psdiscrepancy"),
        _target=EvidenceId("evid-proc-2"),
        description="Process in psscan but missing from pslist",
        process_pid=6666,
        process_name="rootkit.exe"
    )
    candidate = InvestigationCandidate(
        _id="cand-2",
        hypothesis_description="Hidden process hypothesis",
        related_observations=[obs]
    )
    dossier = InvestigationDossier(
        investigation_id="INV-003",
        created_at=datetime.now(),
        candidates=[candidate],
        capability_failures=[]
    )

    recs = MitigationEngine.generate_recommendations(dossier)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.priority == MitigationPriority.HIGH
    assert rec.action_type == MitigationActionType.INVESTIGATIVE
    assert "PID 6666" in rec.finding_title
    assert "Windows Security Event Logs" in rec.recommended_action

def test_mitigation_for_yara_rule_match():
    obs = YaraObservation(
        _detector_id=ProviderId("yara"),
        _target=EvidenceId("evid-yara-3"),
        description="Rule match",
        rule_name="PowerShell_Memory_Download_Cradle",
        target_identifier="PID 8888 (powershell.exe) [CMDLINE]",
        matched_strings=(("$s1", 10, "DownloadString"),)
    )
    candidate = InvestigationCandidate(
        _id="cand-3",
        hypothesis_description="YARA match hypothesis",
        related_observations=[obs]
    )
    dossier = InvestigationDossier(
        investigation_id="INV-004",
        created_at=datetime.now(),
        candidates=[candidate],
        capability_failures=[]
    )

    recs = MitigationEngine.generate_recommendations(dossier)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.priority == MitigationPriority.HIGH
    assert "PowerShell_Memory_Download_Cradle" in rec.finding_title
    assert rec.human_authorization_required is True

def test_mitigation_for_missing_symbols_capability_failure():
    fail = MockDetectorResult(
        _status=CapabilityStatus.UNAVAILABLE,
        _failure_reason="Missing Symbol: ntoskrnl.pdb required."
    )
    dossier = InvestigationDossier(
        investigation_id="INV-005",
        created_at=datetime.now(),
        candidates=[],
        capability_failures=[fail]
    )

    recs = MitigationEngine.generate_recommendations(dossier)
    assert len(recs) == 1
    rec = recs[0]
    assert rec.priority == MitigationPriority.MEDIUM
    assert rec.action_type == MitigationActionType.INVESTIGATIVE
    assert "Missing Symbols" in rec.finding_title
    assert "Download matching OS symbols" in rec.recommended_action

def test_mitigation_priority_sorting():
    inj_obs = InjectedCodeObservation(
        _detector_id=ProviderId("m1"),
        _target=EvidenceId("e1"),
        description="MZ Header found",
        process_pid=100
    )
    hide_obs = HiddenProcessObservation(
        _detector_id=ProviderId("m2"),
        _target=EvidenceId("e2"),
        description="Hidden proc",
        process_pid=200
    )
    fail = MockDetectorResult(
        _status=CapabilityStatus.UNAVAILABLE,
        _failure_reason="Symbols missing"
    )

    cand = InvestigationCandidate(
        _id="c",
        hypothesis_description="Composite",
        related_observations=[hide_obs, inj_obs]
    )
    dossier = InvestigationDossier(
        investigation_id="INV-006",
        created_at=datetime.now(),
        candidates=[cand],
        capability_failures=[fail]
    )

    recs = MitigationEngine.generate_recommendations(dossier)
    assert len(recs) == 3
    # Check strict ordering: CRITICAL -> HIGH -> MEDIUM
    assert recs[0].priority == MitigationPriority.CRITICAL
    assert recs[1].priority == MitigationPriority.HIGH
    assert recs[2].priority == MitigationPriority.MEDIUM
