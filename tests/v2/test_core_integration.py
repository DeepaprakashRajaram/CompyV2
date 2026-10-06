"""
WHAT: V2 Integration Tests.
WHY: Proves the Ports-and-Adapters structure works without modifying V1.
"""

import pytest
from datetime import datetime, timezone
from typing import List

from fmd.v2.adapters.cli.compy_cli import build_v2_app
from fmd.v2.application.use_cases import AnalyzeMemoryRequest, AnalyzeMemoryUseCase
from fmd.v2.domain.contracts import TriState, IDetector, ILedgerQuery, IGraphQuery, ProviderId, IDetectorResult, CapabilityStatus
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.adapters.providers.mock_collector import MockCollector
from fmd.v2.adapters.providers.mock_detector import MockStructuralDetector
from fmd.v2.domain.reasoning.corroboration import DeterministicCorroborator
from fmd.v2.domain.reasoning.verification import StrictVerifier
from fmd.v2.domain.governance.gate import CLIGovernanceGate
from fmd.v2.application.coordinator import SessionCoordinator


from fmd.v2.domain.contracts import ProviderCapability, IContentAccessor

class CrashingDetector(IDetector):
    def provider_id(self) -> ProviderId:
        return ProviderId("crashing_v1")
        
    def required_capabilities(self) -> set[ProviderCapability]:
        return set()
        
    def evaluate(self, ledger: ILedgerQuery, graph: IGraphQuery, content: IContentAccessor) -> IDetectorResult:
        raise RuntimeError("Synthetic detector crash")

class EmptyDetector(IDetector):
    def provider_id(self) -> ProviderId:
        return ProviderId("empty_v1")
        
    def required_capabilities(self) -> set[ProviderCapability]:
        return set()
        
    def evaluate(self, ledger: ILedgerQuery, graph: IGraphQuery, content: IContentAccessor) -> IDetectorResult:
        from fmd.v2.adapters.providers.mock_detector import MockDetectorResult
        return MockDetectorResult(_status=CapabilityStatus.SUCCESS, _observations=[])

def build_test_app(detectors: List[IDetector]) -> AnalyzeMemoryUseCase:
    """Helper to inject custom test detectors."""
    def coordinator_factory() -> SessionCoordinator:
        ledger = EvidenceLedger()
        return SessionCoordinator(
            collector=MockCollector(),
            detectors=detectors,
            ledger=ledger,
            ledger_query=ledger,
            graph_query=ledger,
            corroborator=DeterministicCorroborator(),
            verifier=StrictVerifier(),
            governance=CLIGovernanceGate()
        )
    return AnalyzeMemoryUseCase(coordinator_factory=coordinator_factory)


def test_v2_architecture_end_to_end():
    """
    Validates that the entire hexagonal pipeline runs.
    """
    app = build_v2_app()
    req = AnalyzeMemoryRequest(target_path="mock://test.raw", session_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    
    dossier = app.execute(req)
    assert dossier.investigation_id.startswith("INV-")
    # Because there is no execution evidence (ThreadNode) in the mock setup,
    # the StrictVerifier returns UNKNOWN according to the new P0-3 semantics.
    assert dossier.system_status == TriState.UNKNOWN
    assert dossier.verification_conclusion is not None
    assert dossier.verification_conclusion.status == TriState.UNKNOWN
    
def test_coordinator_internal_state():
    app = build_v2_app()
    req = AnalyzeMemoryRequest(target_path="mock://test.raw", session_timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc))
    
    # We must instantiate the coordinator exactly like execute() does to inspect it
    coordinator = app.coordinator_factory()
    dossier = coordinator.run_analysis(req.target_path, req.session_timestamp)
    
    # 1. Did ledger capture the nodes? (3 procs + 2 regions = 5 nodes)
    nodes = coordinator.ledger_query.get_all_nodes()
    assert len(nodes) == 5
    
    # 2. Did Graph capture the relationship?
    # Find the process node with PID 1000 to get its generated UUIDv5 ID
    proc_1000_id = None
    for node in nodes:
        if node.node_type == "Process" and node.pid == 1000:
            proc_1000_id = node._id
            break
            
    assert proc_1000_id is not None
    children = coordinator.graph_query.get_children(proc_1000_id, "CONTAINS")
    assert len(children) == 1
    assert children[0].node_type == "MemoryRegion"

def test_determinism():
    """
    Validates that identical requests produce identical semantic outputs.
    """
    app = build_v2_app()
    ts = datetime(2026, 5, 1, 10, 0, tzinfo=timezone.utc)
    
    req1 = AnalyzeMemoryRequest(target_path="mock://test.raw", session_timestamp=ts)
    dossier1 = app.execute(req1)
    
    req2 = AnalyzeMemoryRequest(target_path="mock://test.raw", session_timestamp=ts)
    dossier2 = app.execute(req2)
    
    assert dossier1.investigation_id == dossier2.investigation_id
    assert dossier1.created_at == dossier2.created_at
    assert len(dossier1.candidates) == len(dossier2.candidates)
    assert dossier1.candidates[0].candidate_id == dossier2.candidates[0].candidate_id

def test_failure_isolation():
    """
    Validates that a crashing detector does not crash the pipeline
    and sets the system status to UNKNOWN when no malice is otherwise proven.
    """
    app = build_test_app(detectors=[EmptyDetector(), CrashingDetector()])
    req = AnalyzeMemoryRequest(target_path="mock://test.raw", session_timestamp=datetime.now(timezone.utc))
    
    dossier = app.execute(req)
    
    # Pipeline did not crash!
    # Status should be UNKNOWN because there is a capability failure and no candidates proved malice
    assert dossier.system_status == TriState.UNKNOWN
    assert len(dossier.capability_failures) == 1
    assert dossier.capability_failures[0].status == CapabilityStatus.FAILED
    assert "Synthetic detector crash" in dossier.capability_failures[0].failure_reason
    
    # Empty detector succeeded but found nothing
    assert len(dossier.candidates) == 0

def test_missing_evidence_unknown_semantics():
    """
    Validates that if no observations are found, the status defaults to FALSE.
    (Because no capabilities failed, we just found nothing malicious).
    """
    app = build_test_app(detectors=[EmptyDetector()])
    req = AnalyzeMemoryRequest(target_path="mock://test.raw", session_timestamp=datetime.now(timezone.utc))
    
    dossier = app.execute(req)
    
    # Status should be FALSE (benign), not UNKNOWN, because all detectors succeeded but found nothing.
    assert dossier.system_status == TriState.FALSE
    assert len(dossier.candidates) == 0
    assert len(dossier.capability_failures) == 0
