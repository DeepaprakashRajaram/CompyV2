"""
WHAT: Injected Code & Memory Tampering Detector (Malfind / VAD Analysis).
WHY: Detects unbacked executable/writable memory allocations typical of fileless malware,
     reflective DLL injection, process hollowing, and shellcode execution.
OWNS: Heuristics evaluating memory permissions and injected code indicators.
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
from fmd.v2.domain.evidence.nodes import InjectedCodeNode, MemoryRegionNode

@dataclass(frozen=True)
class InjectedCodeObservation(IObservation):
    """
    Observation of an unbacked, executable or writable-executable memory allocation
    associated with a process.
    """
    _detector_id: ProviderId
    _target: EvidenceId
    description: str
    confidence: float = 0.90
    anomaly_category: str = "CODE_INJECTION"
    process_pid: int = 0
    process_name: str = ""
    start_address: int = 0
    end_address: int = 0
    protection: str = ""
    tag: str = ""
    hexdump_preview: str = ""
    disasm_preview: str = ""
    heuristic_severity: float = 0.90

    @property
    def detector_id(self) -> ProviderId:
        return self._detector_id

    @property
    def target_evidence_id(self) -> EvidenceId:
        return self._target


@dataclass
class InjectedCodeDetectorResult(IDetectorResult):
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


class InjectedCodeDetector(IDetector):
    """
    Forensic detector for injected code and anomalous executable memory:
    Evaluates InjectedCodeNode structures (e.g. from Volatility malfind) or unbacked
    executable memory regions.
    """

    def provider_id(self) -> ProviderId:
        return ProviderId("injected_code_malfind_v1")

    def required_capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.INJECTED_CODE}

    def evaluate(
        self, 
        ledger: ILedgerQuery, 
        graph: IGraphQuery, 
        content: Optional[IContentAccessor] = None
    ) -> IDetectorResult:
        nodes = ledger.get_all_nodes()
        
        # Check scan completion status
        malfind_completed = any(
            getattr(n, "scan_name", "") == "MALFIND" and getattr(n, "status", "") == "COMPLETED"
            for n in nodes
        )

        injected_nodes: List[InjectedCodeNode] = [
            n for n in nodes 
            if getattr(n, "node_type", "") == "InjectedCode"
        ]

        # Also inspect raw MemoryRegionNode if present with suspicious permissions
        region_nodes: List[MemoryRegionNode] = [
            n for n in nodes
            if getattr(n, "node_type", "") == "MemoryRegion" and
            ("EXECUTE_READWRITE" in getattr(n, "protection", "") or "PAGE_EXECUTE_READWRITE" in getattr(n, "protection", "")) and
            getattr(n, "mapped_path", None) is None
        ]

        if not malfind_completed and not injected_nodes and not region_nodes:
            return InjectedCodeDetectorResult(
                _status=CapabilityStatus.UNAVAILABLE,
                _observations=[],
                _failure_reason="Injected code analysis (MALFIND) was not executed or is unavailable."
            )

        observations: List[IObservation] = []
        seen_targets: Set[EvidenceId] = set()

        for inj in injected_nodes:
            if inj.id in seen_targets:
                continue
            seen_targets.add(inj.id)

            has_pe_header = "4d 5a" in inj.hexdump_preview.lower() or "mz" in inj.hexdump_preview.lower()
            tag_info = f" Tag: '{inj.tag}'." if inj.tag else ""
            pe_info = " [EMBEDDED PE HEADER (MZ) DETECTED - REFLECTIVE DLL / PROCESS HOLLOWING]" if has_pe_header else ""
            
            obs = InjectedCodeObservation(
                _detector_id=self.provider_id(),
                _target=inj.id,
                description=(
                    f"EXECUTABLE MEMORY INJECTION: Process '{inj.process_name}' (PID {inj.pid}) "
                    f"contains suspicious unbacked executable memory allocation at {inj.start_address:#x}-{inj.end_address:#x} "
                    f"with protection '{inj.protection}'.{tag_info}{pe_info}"
                ),
                confidence=0.95 if has_pe_header else 0.90,
                anomaly_category="CODE_INJECTION",
                process_pid=inj.pid,
                process_name=inj.process_name,
                start_address=inj.start_address,
                end_address=inj.end_address,
                protection=inj.protection,
                tag=inj.tag,
                hexdump_preview=inj.hexdump_preview,
                disasm_preview=inj.disasm_preview,
                heuristic_severity=0.95 if has_pe_header else 0.90
            )
            observations.append(obs)

        return InjectedCodeDetectorResult(
            _status=CapabilityStatus.SUCCESS,
            _observations=observations
        )
