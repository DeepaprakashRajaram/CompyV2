"""
WHAT: Evidence Nodes for Compy V2.
WHY: Strongly typed representation of raw facts.
OWNS: The data structure of evidence.
DOES NOT OWN: Interpretation, relationships, or storage logic.
INVARIANTS: Nodes are immutable once created.
"""

from dataclasses import dataclass
from typing import Optional
from fmd.v2.domain.contracts import IEvidenceNode, EvidenceId

from datetime import datetime

@dataclass(frozen=True)
class ProcessNode(IEvidenceNode):
    """Factual evidence of a process existing."""
    _id: EvidenceId
    pid: int
    name: str
    ppid: Optional[int] = None
    create_time: Optional[datetime] = None
    exit_time: Optional[datetime] = None
    
    @property
    def id(self) -> EvidenceId:
        return self._id
        
    @property
    def node_type(self) -> str:
        return "Process"

@dataclass(frozen=True)
class MemoryRegionNode(IEvidenceNode):
    """Factual evidence of a memory region."""
    _id: EvidenceId
    start_address: int
    end_address: int
    protection: str
    mapped_path: Optional[str] = None
    
    @property
    def id(self) -> EvidenceId:
        return self._id
        
    @property
    def node_type(self) -> str:
        return "MemoryRegion"

@dataclass(frozen=True)
class ThreadNode(IEvidenceNode):
    """Factual evidence of a thread."""
    _id: EvidenceId
    tid: int
    start_address: int
    
    @property
    def id(self) -> EvidenceId:
        return self._id
        
    @property
    def node_type(self) -> str:
        return "Thread"
