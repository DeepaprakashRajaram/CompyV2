"""
WHAT: Corroboration Subsystem.
WHY: Groups independent observations into a single coherent hypothesis (Investigation Candidate).
OWNS: Reasoning logic over multiple observations.
DOES NOT OWN: Raw evidence, final verification, mitigation.
"""

from typing import List, Dict
import uuid

from fmd.v2.domain.contracts import ICorroborator, IObservation, IGraphQuery
from fmd.v2.domain.contracts import IInvestigationCandidate, EvidenceId

class InvestigationCandidate(IInvestigationCandidate):
    def __init__(self, _id: str, hypothesis_description: str, related_observations: List[IObservation]):
        self._id = _id
        self.hypothesis_description = hypothesis_description
        self.related_observations = related_observations
        
    @property
    def candidate_id(self) -> str:
        return self._id
        
    @property
    def independent_evidence_targets(self) -> set[EvidenceId]:
        return {obs.target_evidence_id for obs in self.related_observations}

class DeterministicCorroborator(ICorroborator):
    """
    Phase 1 Corroborator. Groups observations by target process to form hypotheses.
    """
    def evaluate(self, observations: List[IObservation], graph: IGraphQuery) -> List[IInvestigationCandidate]:
        # Sort observations to guarantee deterministic output order
        # (Assuming observation target IDs are string comparable)
        sorted_obs = sorted(observations, key=lambda o: o.target_evidence_id)
        
        candidates = []
        # Group by the parent process of the target memory region.
        # This demonstrates querying the Graph from reasoning logic.
        groups: Dict[EvidenceId, List[IObservation]] = {}
        
        for obs in sorted_obs:
            parent = graph.get_parent(obs.target_evidence_id, relation_type="CONTAINS")
            group_key = parent.id if parent else obs.target_evidence_id
            
            if group_key not in groups:
                groups[group_key] = []
            groups[group_key].append(obs)
            
        for group_key, group_obs in groups.items():
            candidate = InvestigationCandidate(
                _id=f"CANDIDATE-{uuid.uuid5(uuid.NAMESPACE_DNS, group_key)}",
                hypothesis_description=f"Multiple anomalies detected relating to entity {group_key}",
                related_observations=group_obs
            )
            candidates.append(candidate)
            
        return sorted(candidates, key=lambda c: c.candidate_id)
