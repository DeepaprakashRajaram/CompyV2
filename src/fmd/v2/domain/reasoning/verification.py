"""
WHAT: Verification Subsystem.
WHY: Audits an investigation candidate to see if the hypothesis is logically justified by evidence.
OWNS: Logical auditing of hypotheses.
DOES NOT OWN: Generating the hypothesis.
"""

from dataclasses import dataclass
from fmd.v2.domain.contracts import IVerifier, IInvestigationCandidate, IGraphQuery
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
    Phase 1 Verifier.
    Enforces minimum evidence sufficiency.
    """
    def verify(self, candidate: IInvestigationCandidate, ledger: ILedgerQuery, graph: IGraphQuery) -> IVerifiedConclusion:
        if not hasattr(candidate, 'independent_evidence_targets'):
            return VerifiedConclusion(_status=TriState.UNKNOWN, _rationale="Candidate lacks evidence target tracking.")
            
        targets = candidate.independent_evidence_targets
        
        has_memory_evidence = False
        has_execution_evidence = False
        
        for target_id in targets:
            node = ledger.get_node(target_id)
            if node:
                if node.node_type == "MemoryRegion":
                    has_memory_evidence = True
                elif node.node_type == "Thread":
                    has_execution_evidence = True

        if has_memory_evidence and has_execution_evidence:
            return VerifiedConclusion(
                _status=TriState.TRUE,
                _rationale="Sufficient evidence: Verified malicious memory region and active execution thread."
            )
        elif has_memory_evidence:
            return VerifiedConclusion(
                _status=TriState.UNKNOWN,
                _rationale="INSUFFICIENT EVIDENCE: Suspicious memory region found, but missing execution evidence (Thread)."
            )
        else:
            return VerifiedConclusion(
                _status=TriState.FALSE,
                _rationale="No malicious evidence found."
            )
