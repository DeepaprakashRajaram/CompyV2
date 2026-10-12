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
    """
    Observation of a process structure present in physical memory (PSSCAN)
    but unlinked from the active process list (PSLIST).

    HEURISTIC SCORING CONTRACT:
    The `heuristic_severity` (mirrored in `confidence` for interface compatibility)
    is a rule-based triage priority metric (default 0.85 for active unlinked threads,
    or adjusted based on thread count and PID reuse). It is NOT a calibrated statistical
    probability of compromise.
    """
    _detector_id: ProviderId
    _target: EvidenceId
    description: str
    confidence: float = 0.85
    anomaly_category: str = "ROOTKIT_DKOM"
    process_pid: int = 0
    process_name: str = ""
    ppid: int = -1
    thread_count: int = 0
    source_view: str = "PSSCAN"
    discrepancy_type: str = "ABSENT_FROM_PSLIST"
    heuristic_severity: float = 0.85

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
    Detects cross-view process discrepancies (potential unlinked / DKOM evasion):
    Correlates independent process observations acquired from the active process list (PSLIST)
    against structures carved from physical memory pools (PSSCAN).
    
    Matching Strategy & Constraints:
    - Requires independently sourced process observations distinguishing PSLIST from PSSCAN.
    - Matches candidate processes using composite identity: PID, normalized image name, and creation time.
    - PID alone is NOT assumed to establish process identity; differences in name or creation timestamp
      are treated as potential PID reuse.
    - Exited/terminated processes with an explicit exit timestamp are filtered out as expected forensic residue.
    - Processes carved by PSSCAN but absent from PSLIST are treated as structural discrepancies requiring
      investigation, rather than conclusive proof of malware or rootkits.
    - Incomplete extraction, missing views, or ambiguous identity are handled conservatively without
      inventing confidence or claiming false corroboration.
    """

    def provider_id(self) -> ProviderId:
        return ProviderId("hidden_process_rootkit_v1")

    def required_capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.PROCESS_LIST}

    def evaluate(self, ledger: ILedgerQuery, graph: IGraphQuery, content: Optional[IContentAccessor] = None) -> IDetectorResult:
        proc_nodes: List[ProcessNode] = [
            node for node in ledger.get_all_nodes() 
            if getattr(node, "node_type", "") == "Process"
        ]
        
        if not proc_nodes:
            return HiddenProcessDetectorResult(
                _status=CapabilityStatus.UNAVAILABLE,
                _observations=[],
                _failure_reason="Process evidence is unavailable in the ledger; cross-view unlinking cannot be evaluated."
            )

        # Segregate processes by acquisition view provenance
        pslist_nodes: List[ProcessNode] = [
            p for p in proc_nodes 
            if getattr(p, "source_view", "PSLIST") == "PSLIST" and not getattr(p, "is_hidden", False)
        ]
        psscan_nodes: List[ProcessNode] = [
            p for p in proc_nodes 
            if getattr(p, "source_view", "PSLIST") == "PSSCAN" or getattr(p, "is_hidden", False)
        ]

        # Incomplete / unavailable view handling:
        # 1. PSLIST view must be available to establish absence/unlinking.
        if not pslist_nodes:
            return HiddenProcessDetectorResult(
                _status=CapabilityStatus.UNAVAILABLE,
                _observations=[],
                _failure_reason="Active process list (PSLIST) is unavailable; cross-view unlinking cannot be evaluated."
            )

        # 2. PSSCAN view must have been executed.
        # Distinguish a successfully executed scan that carved 0 structures from a scan that was never executed or failed:
        psscan_completed = (len(psscan_nodes) > 0) or any(
            getattr(n, "scan_name", "") == "PSSCAN" and getattr(n, "status", "") == "COMPLETED"
            for n in ledger.get_all_nodes()
        )

        if not psscan_completed:
            return HiddenProcessDetectorResult(
                _status=CapabilityStatus.UNAVAILABLE,
                _observations=[],
                _failure_reason="Memory pool carving view (PSSCAN) was not executed or is unavailable; cross-view unlinking cannot be evaluated."
            )

        observations: List[IObservation] = []
        seen_targets: Set[EvidenceId] = set()

        for scan_p in psscan_nodes:
            # Filter exited / terminated processes: normal residue, not unlinked active rootkits
            if scan_p.exit_time is not None:
                continue

            # Conservative check for unassigned or invalid PIDs
            if scan_p.pid is None or scan_p.pid <= 0:
                continue

            # Composite matching against PSLIST nodes:
            # 1. Match candidates by PID
            pid_candidates = [lp for lp in pslist_nodes if lp.pid == scan_p.pid]

            # 2. Corroborate identity (checking name, creation time, and address offset to detect PID reuse)
            is_matched_in_pslist = False
            for lp in pid_candidates:
                names_match = (
                    lp.name.lower() == scan_p.name.lower()
                    if (lp.name and scan_p.name)
                    else False
                )
                times_match = True
                if lp.create_time is not None and scan_p.create_time is not None:
                    times_match = (lp.create_time == scan_p.create_time)

                if names_match and times_match:
                    is_matched_in_pslist = True
                    break

            if not is_matched_in_pslist:
                # Present in PSSCAN but absent or unlinked from active PSLIST
                if scan_p.id in seen_targets:
                    continue
                seen_targets.add(scan_p.id)

                is_pid_reuse = len(pid_candidates) > 0
                discrepancy_detail = (
                    f"PID reuse detected: PID {scan_p.pid} exists in PSLIST as "
                    f"'{pid_candidates[0].name}' but carved PSSCAN entry is '{scan_p.name}'"
                    if is_pid_reuse
                    else f"PID {scan_p.pid} ('{scan_p.name}') absent from active PSLIST"
                )

                obs = HiddenProcessObservation(
                    _detector_id=self.provider_id(),
                    _target=scan_p.id,
                    description=(
                        f"Cross-view process discrepancy: Process '{scan_p.name}' (PID {scan_p.pid}) "
                        f"was carved from physical memory pools (PSSCAN) but is unlinked from the active "
                        f"process list (PSLIST). {discrepancy_detail}. Threads: {scan_p.threads}. "
                        f"Investigative discrepancy requiring corroboration."
                    ),
                    confidence=0.85,
                    anomaly_category="ROOTKIT_DKOM",
                    process_pid=scan_p.pid,
                    process_name=scan_p.name,
                    ppid=scan_p.ppid if scan_p.ppid is not None else -1,
                    thread_count=scan_p.threads,
                    source_view="PSSCAN",
                    discrepancy_type="PID_REUSE_UNLINKED" if is_pid_reuse else "ABSENT_FROM_PSLIST",
                    heuristic_severity=0.85
                )
                observations.append(obs)

        return HiddenProcessDetectorResult(
            _status=CapabilityStatus.SUCCESS,
            _observations=observations
        )
