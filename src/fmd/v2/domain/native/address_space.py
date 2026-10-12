"""
WHAT: Phase 2E-A Address Space and Translation Contracts
WHY: Provide explicit semantics for memory reading, including partial reads and specific failure reasons, without zero-filling or truncating silently.
OWNS: IAddressSpace, MemoryReadResult, FailureReason, ReadGap, MappedSegment.
DOES NOT OWN: x64 paging, PDBs, _EPROCESS, OS discovery.
"""

from enum import Enum
from typing import List, Protocol

class FailureReason(Enum):
    # Core Semantics
    UNKNOWN = "UNKNOWN"
    UNAVAILABLE = "UNAVAILABLE"
    UNSUPPORTED = "UNSUPPORTED"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    
    # Translation Specific
    PAGE_NOT_PRESENT = "PAGE_NOT_PRESENT"
    INVALID_PAGE_TABLE_ENTRY = "INVALID_PAGE_TABLE_ENTRY"
    PHYSICAL_OUT_OF_BOUNDS = "PHYSICAL_OUT_OF_BOUNDS"
    UNSUPPORTED_PAGING_MODE = "UNSUPPORTED_PAGING_MODE"
    INVALID_ADDRESS = "INVALID_ADDRESS"
    MISSING_ARTIFACT_DATA = "MISSING_ARTIFACT_DATA"

class ReadGap:
    """Represents a region of a requested read that could not be satisfied."""
    def __init__(self, requested_offset: int, length: int, reason: FailureReason):
        self.requested_offset = requested_offset
        self.length = length
        self.reason = reason

    def __eq__(self, other):
        if not isinstance(other, ReadGap):
            return False
        return (self.requested_offset == other.requested_offset and 
                self.length == other.length and 
                self.reason == other.reason)

class MappedSegment:
    """Represents a successfully read region of a requested read."""
    def __init__(self, requested_offset: int, data: bytes):
        self.requested_offset = requested_offset
        self.data = data

    def __eq__(self, other):
        if not isinstance(other, MappedSegment):
            return False
        return (self.requested_offset == other.requested_offset and 
                self.data == other.data)
                
    @property
    def length(self) -> int:
        return len(self.data)

class MemoryReadResult:
    """
    Explicit structured result for a memory read. 
    Preserves exact offsets of mapped vs unmapped data.
    Never silently zero-fills missing bytes.
    """
    def __init__(self, segments: List[MappedSegment], gaps: List[ReadGap]):
        self.segments = segments
        self.gaps = gaps

    @property
    def is_complete(self) -> bool:
        """Returns True if the entire requested range was successfully read (no gaps)."""
        return len(self.gaps) == 0
        
    @property
    def total_bytes_read(self) -> int:
        return sum(seg.length for seg in self.segments)

    def get_data_if_complete(self) -> bytes:
        """
        Convenience method if the caller requires the full contiguous read.
        Raises ValueError if there are gaps, preventing silent corruption.
        """
        if not self.is_complete:
            raise ValueError(f"Cannot return complete data: Result has {len(self.gaps)} gaps.")
        
        # If it's complete, the segments must logically be contiguous.
        # However, they might be fragmented depending on the layer's internal logic.
        # We sort them and concatenate.
        sorted_segments = sorted(self.segments, key=lambda s: s.requested_offset)
        return b"".join(s.data for s in sorted_segments)

class IAddressSpace(Protocol):
    """
    Contract for an addressable memory context.
    Does not assume physical vs virtual.
    """
    @property
    def identity(self) -> str:
        """A string uniquely identifying this address space context (e.g., 'Physical', or 'Virtual:CR3=0x1a2b')."""
        ...
    
    def read(self, address: int, length: int) -> MemoryReadResult:
        """
        Attempt to read `length` bytes from `address`.
        Returns a structured MemoryReadResult.
        """
        ...
