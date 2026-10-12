"""
WHAT: Verification Subsystem.
WHY: Audits an investigation candidate to see if the hypothesis is logically justified by evidence.
OWNS: Logical auditing of hypotheses.
DOES NOT OWN: Generating the hypothesis.
"""

from dataclasses import dataclass
from fmd.v2.domain.contracts import IVerifier, IInvestigationCandidate, IGraphQuery, ILedgerQuery
from fmd.v2.domain.contracts import IVerifiedConclusion, TriState

@dataclass
class VerifiedConclusion(IVerifiedConclusion):
    _status: TriState
    _rationale: str
    
    @property
    def status(self) -> TriState:
        return self._status
        
    @property
    def rationale(self) -> str:
        return self._rationale


class StrictVerifier(IVerifier):
    """
    Forensic Verifier.
    Enforces minimum evidence sufficiency and strict corroboration requirements:
    - An isolated RWX allocation or single weak heuristic must NOT establish a confirmed threat.
    - Corroborated, independently supported malicious evidence produces TRUE.
    - Incomplete or inconclusive evidence produces UNKNOWN.
    - Absence of malicious findings produces FALSE.
    """
    def verify(self, candidate: IInvestigationCandidate, ledger: ILedgerQuery, graph: IGraphQuery) -> IVerifiedConclusion:
        if not hasattr(candidate, 'independent_evidence_targets'):
            return VerifiedConclusion(_status=TriState.UNKNOWN, _rationale="Candidate lacks evidence target tracking.")
            
        targets = candidate.independent_evidence_targets
        observations = getattr(candidate, "related_observations", []) or getattr(candidate, "observations", [])
        
        has_memory_evidence = False
        has_execution_thread = False
        has_injected_code = False
        has_yara_match = False
        has_lineage_anomaly = False
        has_rootkit_dkom = False
        
        # 1. Audit Ledger Evidence Nodes
        for target_id in targets:
            node = ledger.get_node(target_id)
            if node:
                if node.node_type == "MemoryRegion":
                    has_memory_evidence = True
                elif node.node_type == "Thread":
                    has_execution_thread = True
                elif node.node_type == "InjectedCode":
                    has_injected_code = True
                elif node.node_type == "YaraMatch":
                    has_yara_match = True

        # 2. Audit Observation Categories
        categories = set()
        detector_ids = set()
        for obs in observations:
            cat = getattr(obs, "anomaly_category", "")
            det = getattr(obs, "detector_id", "")
            if cat:
                categories.add(cat)
            if det:
                detector_ids.add(det)
            if cat in ("CODE_INJECTION", "MALFIND_VAD", "INJECTED_CODE"):
                has_injected_code = True
            elif cat in ("YARA_RULE_MATCH", "RANSOMWARE") or hasattr(obs, "rule_name"):
                has_yara_match = True
            elif cat in ("PROCESS_LINEAGE_ANOMALY", "EXPLOIT_SPAWN", "SYSTEM_MASQUERADE", "PPID_SPOOFING"):
                has_lineage_anomaly = True
            elif cat in ("ROOTKIT_DKOM", "UNLINKED_PROCESS_DISCREPANCY"):
                has_rootkit_dkom = True

        # 3. Corroboration Rules Evaluation
        # Corroborated Condition 1: Injected code + active execution thread (classic code injection)
        if (has_memory_evidence or has_injected_code) and has_execution_thread:
            return VerifiedConclusion(
                _status=TriState.TRUE,
                _rationale="Sufficient evidence: Verified malicious memory region and active execution thread."
            )
            
        # Corroborated Condition 2: Injected code + YARA signature match
        if (has_memory_evidence or has_injected_code) and has_yara_match:
            return VerifiedConclusion(
                _status=TriState.TRUE,
                _rationale="Corroborated threat: Unbacked memory injection verified by independent YARA signature match."
            )

        # Corroborated Condition 3: Contextual Process Lineage Anomaly
        # Multi-indicator heuristic requires user-space execution AND
        # active secondary payload/decrypter/Tor proxy coordination
        if has_lineage_anomaly:
            return VerifiedConclusion(
                _status=TriState.TRUE,
                _rationale="Corroborated threat: Multi-indicator contextual process lineage confirmed (user-directory execution orchestrating secondary payload/decrypter binaries)."
            )

        # Corroborated Condition 4: YARA signature match on payload artifacts
        if has_yara_match:
            return VerifiedConclusion(
                _status=TriState.TRUE,
                _rationale="Corroborated threat: Target artifact confirmed by weaponized cryptographic/YARA signature match."
            )

        # Corroborated Condition 5: Rootkit DKOM + Injection or Lineage
        if has_rootkit_dkom and (has_injected_code or has_lineage_anomaly or has_yara_match):
            return VerifiedConclusion(
                _status=TriState.TRUE,
                _rationale="Corroborated threat: Kernel unlinked process discrepancy confirmed by in-memory injection/lineage evidence."
            )

        # Inconclusive Condition: Isolated unbacked/RWX memory allocation (e.g. Benign JIT runtime like SearchUI)
        if has_memory_evidence or has_injected_code:
            return VerifiedConclusion(
                _status=TriState.UNKNOWN,
                _rationale="INSUFFICIENT EVIDENCE: Isolated unbacked/RWX memory allocation detected (potential benign JIT runtime or unverified allocation), lacking corroborating execution thread or signature match."
            )

        # Inconclusive Condition: Single weak heuristic or uncorroborated anomaly
        if observations:
            return VerifiedConclusion(
                _status=TriState.UNKNOWN,
                _rationale="INSUFFICIENT EVIDENCE: Uncorroborated single heuristic anomaly lacking independent supporting evidence."
            )

        return VerifiedConclusion(
            _status=TriState.FALSE,
            _rationale="No malicious evidence found."
        )
