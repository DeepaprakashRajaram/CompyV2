"""
WHAT: Investigation Dossier.
WHY: Groups candidates, evidence, and verification states into a serializable case file.
OWNS: The aggregate view of an investigation.
DOES NOT OWN: Initial detection.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Any
from datetime import datetime

from fmd.v2.domain.contracts import IInvestigationCandidate, IVerifiedConclusion, TriState, IDetectorResult

@dataclass
class InvestigationDossier:
    """The master case file."""
    investigation_id: str
    created_at: datetime
    schema_version: str = "2.0.0"
    candidates: List[IInvestigationCandidate] = field(default_factory=list)
    capability_failures: List[IDetectorResult] = field(default_factory=list)
    verification_conclusion: Optional[IVerifiedConclusion] = None
    system_status: TriState = TriState.UNKNOWN

    @property
    def all_observations(self) -> List[Any]:
        obs = []
        for c in self.candidates:
            if hasattr(c, "related_observations"):
                obs.extend(c.related_observations)
        return obs

    @property
    def process_tree_anomalies(self) -> List[Any]:
        return [
            o for o in self.all_observations 
            if getattr(o, "anomaly_category", "") in (
                "PPID_SPOOFING", "EXPLOIT_SPAWN", "SYSTEM_MASQUERADE",
                "SUSPICIOUS_COMMAND_LINE", "PROCESS_LINEAGE_ANOMALY"
            )
        ]

    @property
    def hidden_process_anomalies(self) -> List[Any]:
        return [
            o for o in self.all_observations 
            if getattr(o, "anomaly_category", "") in ("ROOTKIT_DKOM", "UNLINKED_PROCESS_DISCREPANCY")
        ]

    @property
    def injected_code_anomalies(self) -> List[Any]:
        return [
            o for o in self.all_observations 
            if getattr(o, "anomaly_category", "") in ("CODE_INJECTION", "MALFIND_VAD", "INJECTED_CODE")
        ]

    @property
    def yara_anomalies(self) -> List[Any]:
        return [
            o for o in self.all_observations 
            if getattr(o, "anomaly_category", "") == "YARA_RULE_MATCH" or hasattr(o, "rule_name")
        ]

    @property
    def mitigation_recommendations(self) -> List[Any]:
        from fmd.v2.domain.reasoning.mitigation import MitigationEngine
        return MitigationEngine.generate_recommendations(self)

