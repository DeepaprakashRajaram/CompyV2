"""
WHAT: Provenance and Lineage tracking for Compy V2.
WHY: Evidence must preserve its origin to ensure forensic defensibility and deduplication.
OWNS: The record of WHO created the evidence and WHEN.
DOES NOT OWN: Confidence scoring or detector hypotheses.
INVARIANTS: Distinct from Confidence. Evidence identity must not be double-counted.
"""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from fmd.v2.domain.contracts import IProvenanceRecord, ProviderId

@dataclass(frozen=True)
class ProvenanceRecord(IProvenanceRecord):
    """
    Immutable record of where evidence came from.
    """
    _provider_id: ProviderId
    _artifact_identity: str
    _acquisition_mode: str
    acquisition_time: datetime
    
    @property
    def provider_id(self) -> ProviderId:
        return self._provider_id
        
    @property
    def artifact_identity(self) -> str:
        return self._artifact_identity
        
    @property
    def acquisition_mode(self) -> str:
        return self._acquisition_mode
