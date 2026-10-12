"""
WHAT: Evidence Nodes for Compy V2.
WHY: Strongly typed representation of raw facts.
OWNS: The data structure of evidence.
DOES NOT OWN: Interpretation, relationships, or storage logic.
INVARIANTS: Nodes are immutable once created.
"""

from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple
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
    is_hidden: bool = False
    source_view: str = "PSLIST"
    offset: Optional[int] = None
    threads: int = 0
    handles: int = 0
    cmdline: Optional[str] = None
    
    @property
    def id(self) -> EvidenceId:
        return self._id
        
    @property
    def node_type(self) -> str:
        return "Process"

@dataclass(frozen=True)
class InjectedCodeNode(IEvidenceNode):
    """Factual evidence of an unbacked/injected executable memory region (e.g. from Malfind)."""
    _id: EvidenceId
    pid: int
    process_name: str
    start_address: int
    end_address: int
    protection: str
    tag: str = ""
    hexdump_preview: str = ""
    disasm_preview: str = ""

    @property
    def id(self) -> EvidenceId:
        return self._id

    @property
    def node_type(self) -> str:
        return "InjectedCode"

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

@dataclass(frozen=True)
class ScanMetadataNode(IEvidenceNode):
    """Factual evidence of an acquisition scan having completed."""
    _id: EvidenceId
    scan_name: str
    status: str = "COMPLETED"
    item_count: int = 0

    @property
    def id(self) -> EvidenceId:
        return self._id

    @property
    def node_type(self) -> str:
        return "ScanMetadata"

@dataclass(frozen=True)
class YaraMatchNode(IEvidenceNode):
    """Factual evidence of a genuine YARA rule match against memory/artifact."""
    _id: EvidenceId
    rule_name: str
    namespace: str = "default"
    tags: Tuple[str, ...] = ()
    matched_strings: Tuple[Tuple[str, int, str], ...] = () # (identifier, offset, preview)
    target_type: str = "PROCESS_MEMORY" # PROCESS_MEMORY, INJECTED_REGION, COMMAND_LINE, BUFFER
    target_identifier: str = ""
    meta: Dict[str, Any] = None

    @property
    def id(self) -> EvidenceId:
        return self._id

    @property
    def node_type(self) -> str:
        return "YaraMatch"
