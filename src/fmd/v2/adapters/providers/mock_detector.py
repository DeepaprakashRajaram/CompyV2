"""
WHAT: Mock Detector Provider.
WHY: Proves the IDetector Port works.
OWNS: Simple heuristic logic to flag RWX unbacked regions.
DOES NOT OWN: Verdicts, Mitigation, Storage.
"""

from typing import List, Optional
from dataclasses import dataclass, field

from fmd.v2.domain.contracts import IDetector, ILedgerQuery, IGraphQuery, IObservation
from fmd.v2.domain.contracts import ProviderId, EvidenceId, IDetectorResult, CapabilityStatus
from fmd.v2.domain.contracts import ProviderCapability, IContentAccessor
from fmd.v2.domain.evidence.nodes import MemoryRegionNode

@dataclass(frozen=True)
class MockObservation(IObservation):
    _detector_id: ProviderId
    _target: EvidenceId
    description: str
    confidence: float
    
    @property
    def detector_id(self) -> ProviderId:
        return self._detector_id
        
    @property
    def target_evidence_id(self) -> EvidenceId:
        return self._target


@dataclass
class MockDetectorResult(IDetectorResult):
    _status: CapabilityStatus
    _observations: List[IObservation] = field(default_factory=list)
    _failure_reason: Optional[str] = None
    
    @property
    def status(self) -> CapabilityStatus:
        return self._status
        
    @property
    def observations(self) -> List[IObservation]:
        return self._observations
        
    @property
    def failure_reason(self) -> Optional[str]:
        return self._failure_reason


class MockStructuralDetector(IDetector):
    
    def provider_id(self) -> ProviderId:
        return ProviderId("mock_structural_v1")
        
    def required_capabilities(self) -> set[ProviderCapability]:
        return {ProviderCapability.VAD_INFO}
        
    def evaluate(self, ledger: ILedgerQuery, graph: IGraphQuery, content: IContentAccessor) -> IDetectorResult:
        observations = []
        
        for node in ledger.get_all_nodes():
            if node.node_type == "MemoryRegion":
                region: MemoryRegionNode = node
                if region.protection == "PAGE_EXECUTE_READWRITE" and region.mapped_path is None:
                    # Found something suspicious
                    obs = MockObservation(
                        _detector_id=self.provider_id(),
                        _target=region.id,
                        description="RWX unbacked memory region detected.",
                        confidence=0.8
                    )
                    observations.append(obs)
                    
        return MockDetectorResult(_status=CapabilityStatus.SUCCESS, _observations=observations)

