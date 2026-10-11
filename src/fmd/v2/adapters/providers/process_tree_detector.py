"""
WHAT: Process Tree Anomaly & PPID Spoofing Detector.
WHY: Detects abnormal process lineage, parent-child discrepancies, and exploit spawns in memory.
OWNS: Forensic heuristics for Windows process hierarchy validation.
DOES NOT OWN: Raw collection, memory carving, final verification.
"""

from typing import List, Optional, Set, Dict
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
class ProcessTreeObservation(IObservation):
    _detector_id: ProviderId
    _target: EvidenceId
    description: str
    confidence: float
    anomaly_category: str
    process_pid: int
    process_name: str
    ppid: int
    expected_parent: str
    actual_parent: str

    @property
    def detector_id(self) -> ProviderId:
        return self._detector_id

    @property
    def target_evidence_id(self) -> EvidenceId:
        return self._target


@dataclass
class ProcessTreeDetectorResult(IDetectorResult):
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


class ProcessTreeAnomalyDetector(IDetector):
    """
    Forensic Detector that validates Windows process hierarchy:
    1. System Critical Hierarchy (lsass, svchost, smss, services, wininit)
    2. Living-Off-The-Land & Exploit Spawns (Office, Browsers, Spooler spawning shells)
    3. Invalid / Spoofed PPID references
    """

    # Expected parent process rules: child_name.lower() -> set of allowed parent_names.lower()
    EXPECTED_PARENTS: Dict[str, Set[str]] = {
        "smss.exe": {"system"},
        "services.exe": {"wininit.exe"},
        "lsass.exe": {"wininit.exe"},
        "svchost.exe": {"services.exe"},
        "wininit.exe": {"smss.exe", "system"},
        "lsm.exe": {"wininit.exe"},
        "spoolsv.exe": {"services.exe"},
    }

    # High-risk spawn targets (shells and script engines)
    SUSPICIOUS_CHILDREN: Set[str] = {
        "cmd.exe",
        "powershell.exe",
        "pwsh.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "certutil.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "bitsadmin.exe"
    }

    # Unauthorized parents for shells (indicating macro exploit, web shell, or print exploit)
    EXPLOIT_PARENT_FAMILIES: Dict[str, str] = {
        "winword.exe": "Office Document Macro / Exploit",
        "excel.exe": "Office Document Macro / Exploit",
        "powerpnt.exe": "Office Document Macro / Exploit",
        "outlook.exe": "Mail Client Exploit",
        "chrome.exe": "Web Browser Sandbox Escape / Exploit",
        "msedge.exe": "Web Browser Sandbox Escape / Exploit",
        "firefox.exe": "Web Browser Sandbox Escape / Exploit",
        "acrobat.exe": "PDF Reader Exploit",
        "acrord32.exe": "PDF Reader Exploit",
        "spoolsv.exe": "Print Spooler Remote Code Execution (e.g., PrintNightmare)",
        "sqlservr.exe": "Database Service Shell Injection",
        "w3wp.exe": "IIS Web Server Remote Code Execution / Webshell",
        "httpd.exe": "Apache Web Server Remote Code Execution / Webshell",
        "nginx.exe": "Nginx Web Server Remote Code Execution / Webshell",
    }

    def provider_id(self) -> ProviderId:
        return ProviderId("process_tree_anomaly_v1")

    def required_capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.PROCESS_LIST}

    def evaluate(self, ledger: ILedgerQuery, graph: IGraphQuery, content: Optional[IContentAccessor] = None) -> IDetectorResult:
        observations: List[IObservation] = []
        
        # 1. Index all processes by PID for fast lookup
        proc_nodes: List[ProcessNode] = [
            node for node in ledger.get_all_nodes() 
            if node.node_type == "Process"
        ]
        
        pid_map: Dict[int, ProcessNode] = {p.pid: p for p in proc_nodes}
        
        for proc in proc_nodes:
            proc_name = proc.name.lower()
            ppid = proc.ppid
            parent = pid_map.get(ppid) if ppid is not None else None
            parent_name = parent.name.lower() if parent else "UNKNOWN_OR_EXITED"

            # Check 1: Critical System Hierarchy Validation
            if proc_name in self.EXPECTED_PARENTS:
                allowed_parents = self.EXPECTED_PARENTS[proc_name]
                # If parent exists in dump and is not in allowed parents, flag anomaly
                if parent and parent_name not in allowed_parents:
                    obs = ProcessTreeObservation(
                        _detector_id=self.provider_id(),
                        _target=proc.id,
                        description=(
                            f"CRITICAL PPID ANOMALY: Process '{proc.name}' (PID {proc.pid}) was spawned by "
                            f"unexpected parent '{parent.name}' (PID {ppid}). Expected parent: {', '.join(allowed_parents)}."
                        ),
                        confidence=0.95,
                        anomaly_category="SYSTEM_MASQUERADE",
                        process_pid=proc.pid,
                        process_name=proc.name,
                        ppid=ppid if ppid is not None else -1,
                        expected_parent=next(iter(allowed_parents)),
                        actual_parent=parent.name
                    )
                    observations.append(obs)

            # Check 2: Exploit Spawn (Office, Browsers, Spooler, Web Servers spawning shells)
            if proc_name in self.SUSPICIOUS_CHILDREN and parent:
                if parent_name in self.EXPLOIT_PARENT_FAMILIES:
                    exploit_type = self.EXPLOIT_PARENT_FAMILIES[parent_name]
                    obs = ProcessTreeObservation(
                        _detector_id=self.provider_id(),
                        _target=proc.id,
                        description=(
                            f"EXPLOIT EXECUTION DETECTED: Shell/script engine '{proc.name}' (PID {proc.pid}) was spawned by "
                            f"'{parent.name}' (PID {ppid}). Forensic indicator of {exploit_type}."
                        ),
                        confidence=0.92,
                        anomaly_category="EXPLOIT_SPAWN",
                        process_pid=proc.pid,
                        process_name=proc.name,
                        ppid=ppid if ppid is not None else -1,
                        expected_parent="Standard User Shell / Services",
                        actual_parent=parent.name
                    )
                    observations.append(obs)

            # Check 3: svchost.exe masquerading
            if proc_name == "svchost.exe" and parent:
                if parent_name not in {"services.exe"}:
                    obs = ProcessTreeObservation(
                        _detector_id=self.provider_id(),
                        _target=proc.id,
                        description=(
                            f"SVCHOST MASQUERADE: 'svchost.exe' (PID {proc.pid}) spawned by '{parent.name}' (PID {ppid}) "
                            f"instead of 'services.exe'. High probability of stealth malware execution."
                        ),
                        confidence=0.90,
                        anomaly_category="PPID_SPOOFING",
                        process_pid=proc.pid,
                        process_name=proc.name,
                        ppid=ppid if ppid is not None else -1,
                        expected_parent="services.exe",
                        actual_parent=parent.name
                    )
                    observations.append(obs)

        return ProcessTreeDetectorResult(
            _status=CapabilityStatus.SUCCESS,
            _observations=observations
        )
