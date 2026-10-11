"""
WHAT: Hidden Process (Rootkit / DKOM) Detector.
WHY: Detects unlinked processes hidden from active OS process lists via Direct Kernel Object Manipulation.
OWNS: Cross-referencing heuristics to verify unlinked stealth processes.
DOES NOT OWN: Raw memory carving, Volatility internals.
"""

from typing import List, Optional, Set
from dataclasses import dataclass, field

from fmd.v2.domain.contracts import (
    IDetector, 
    ILedgerQuery, 
    IGraphQuery, 
    IContentAccessor,
    IObservation, 
    IDetectorResult, 
    ProviderId, 
    EvidenceId, 
    ProviderCapability, 
    CapabilityStatus
)
from fmd.v2.domain.evidence.nodes import ProcessNode

@dataclass(frozen=True)
class HiddenProcessObservation(IObservation):
    _detector_id: ProviderId
    _target: EvidenceId
    description: str
    confidence: float
    anomaly_category: str
    process_pid: int
    process_name: str
    ppid: int
    thread_count: int

    @property
    def detector_id(self) -> ProviderId:
        return self._detector_id

    @property
    def target_evidence_id(self) -> EvidenceId:
        return self._target


@dataclass
class HiddenProcessDetectorResult(IDetectorResult):
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


class HiddenProcessDetector(IDetector):
    """
    Detects stealth rootkit processes:
    Identifies processes discovered via memory pool carving (e.g. psscan)
    that are deliberately unlinked from the active process list (pslist) to evade detection.
    """

    def provider_id(self) -> ProviderId:
        return ProviderId("hidden_process_rootkit_v1")

    def required_capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.PROCESS_LIST}

    def evaluate(self, ledger: ILedgerQuery, graph: IGraphQuery, content: Optional[IContentAccessor] = None) -> IDetectorResult:
        observations: List[IObservation] = []
        
        proc_nodes: List[ProcessNode] = [
            node for node in ledger.get_all_nodes() 
            if node.node_type == "Process"
        ]
        
        for proc in proc_nodes:
            if getattr(proc, "is_hidden", False):
                obs = HiddenProcessObservation(
                    _detector_id=self.provider_id(),
                    _target=proc.id,
                    description=(
                        f"STEALTH ROOTKIT PROCESS DETECTED: Process '{proc.name}' (PID {proc.pid}) was carved from memory pools "
                        f"but is unlinked from the operating system's ActiveProcessLinks (DKOM). "
                        f"Active Threads: {proc.threads}."
                    ),
                    confidence=0.98,
                    anomaly_category="ROOTKIT_DKOM",
                    process_pid=proc.pid,
                    process_name=proc.name,
                    ppid=proc.ppid if proc.ppid is not None else -1,
                    thread_count=proc.threads
                )
                observations.append(obs)

        return HiddenProcessDetectorResult(
            _status=CapabilityStatus.SUCCESS,
            _observations=observations
        )
