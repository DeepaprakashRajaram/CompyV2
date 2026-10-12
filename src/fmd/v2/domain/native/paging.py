"""
WHAT: Phase 2E-B x64 Page Walker and Virtual Address Space
WHY: Translates virtual addresses to physical addresses deterministically.
OWNS: TranslationContext, X64VirtualAddressSpace, Bounded Cache.
DOES NOT OWN: OS-specific structures, DTB discovery, Object Instantiation.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple
import struct

from .layer import IRawMemoryLayer, OutOfBoundsError
from .address_space import (
    IAddressSpace, MemoryReadResult, MappedSegment, ReadGap, FailureReason
)

@dataclass(frozen=True)
class TranslationContext:
    paging_mode: str # "4-level" or "5-level"
    dtb: int # Directory Table Base (CR3) physical address

class X64VirtualAddressSpace(IAddressSpace):
    """
    Implements x64 virtual memory translation supporting 4-level and 5-level paging,
    as well as 4KiB, 2MiB, and 1GiB pages. Includes a bounded deterministic translation cache.
    """
    def __init__(self, physical_layer: IRawMemoryLayer, context: TranslationContext, cache_size: int = 1024):
        self._layer = physical_layer
        self._context = context
        self._cache_size = cache_size
        
        # Bounded deterministic translation cache
        # Key: Virtual Page Number (VPN). Value: (Physical Frame Base, Page Size)
        self._cache: Dict[int, Tuple[int, int]] = {}
        self._cache_keys: List[int] = [] # For deterministic LRU eviction
        
        if self._context.paging_mode not in ["4-level", "5-level"]:
            raise ValueError(f"Unsupported paging mode: {self._context.paging_mode}")

    @property
    def identity(self) -> str:
        return f"x64_{self._context.paging_mode}_dtb_{hex(self._context.dtb)}"

    def _is_valid_canonical(self, va: int) -> bool:
        """Validates canonical address form."""
        if va < 0 or va > 0xFFFFFFFFFFFFFFFF:
            return False
            
        shift = 56 if self._context.paging_mode == "5-level" else 47
        bit = (va >> shift) & 1
        
        mask = ~((1 << (shift + 1)) - 1) & 0xFFFFFFFFFFFFFFFF
        
        if bit == 0:
            return (va & mask) == 0
        else:
            return (va & mask) == mask

    def _read_physical_entry(self, phys_addr: int) -> Tuple[Optional[int], Optional[FailureReason]]:
        try:
            data = self._layer.read(phys_addr, 8)
            return struct.unpack("<Q", data)[0], None
        except OutOfBoundsError:
            return None, FailureReason.PHYSICAL_OUT_OF_BOUNDS

    def _translate_va(self, va: int) -> Tuple[Optional[int], Optional[FailureReason]]:
        """
        Translates a virtual address to a physical address.
        Returns (physical_address, None) on success.
        Returns (None, FailureReason) on failure.
        """
        if not self._is_valid_canonical(va):
            return None, FailureReason.INVALID_ADDRESS
            
        vpn = va >> 12
        offset_4k = va & 0xFFF
        
        # 1. Check bounded cache for 4K match
        if vpn in self._cache:
            phys_frame, page_size = self._cache[vpn]
            if page_size == 4096:
                self._update_lru(vpn)
                return phys_frame + offset_4k, None

        # Check for large page matches in cache
        vpn_2m = va >> 21
        if vpn_2m in self._cache:
            phys_frame, page_size = self._cache[vpn_2m]
            if page_size == 2 * 1024 * 1024:
                self._update_lru(vpn_2m)
                return phys_frame + (va & 0x1FFFFF), None
                
        vpn_1g = va >> 30
        if vpn_1g in self._cache:
            phys_frame, page_size = self._cache[vpn_1g]
            if page_size == 1024 * 1024 * 1024:
                self._update_lru(vpn_1g)
                return phys_frame + (va & 0x3FFFFFFF), None

        # 2. Walk the page tables
        pml5_index = (va >> 48) & 0x1FF
        pml4_index = (va >> 39) & 0x1FF
        pdpt_index = (va >> 30) & 0x1FF
        pd_index =   (va >> 21) & 0x1FF
        pt_index =   (va >> 12) & 0x1FF
        
        current_table_base = self._context.dtb & 0x000FFFFFFFFFF000
        
        if self._context.paging_mode == "5-level":
            entry, reason = self._read_physical_entry(current_table_base + (pml5_index * 8))
            if reason: return None, reason
            if not (entry & 1): return None, FailureReason.PAGE_NOT_PRESENT
            current_table_base = entry & 0x000FFFFFFFFFF000

        # PML4
        entry, reason = self._read_physical_entry(current_table_base + (pml4_index * 8))
        if reason: return None, reason
        if not (entry & 1): return None, FailureReason.PAGE_NOT_PRESENT
        current_table_base = entry & 0x000FFFFFFFFFF000
        
        # PDPT
        entry, reason = self._read_physical_entry(current_table_base + (pdpt_index * 8))
        if reason: return None, reason
        if not (entry & 1): return None, FailureReason.PAGE_NOT_PRESENT
        
        if entry & 0x80: # 1 GiB Large Page
            phys_frame = entry & 0x000FFFFFC0000000
            self._add_to_cache(vpn_1g, phys_frame, 1024 * 1024 * 1024)
            return phys_frame + (va & 0x3FFFFFFF), None
            
        current_table_base = entry & 0x000FFFFFFFFFF000
        
        # PD
        entry, reason = self._read_physical_entry(current_table_base + (pd_index * 8))
        if reason: return None, reason
        if not (entry & 1): return None, FailureReason.PAGE_NOT_PRESENT
        
        if entry & 0x80: # 2 MiB Large Page
            phys_frame = entry & 0x000FFFFFFFE00000
            self._add_to_cache(vpn_2m, phys_frame, 2 * 1024 * 1024)
            return phys_frame + (va & 0x1FFFFF), None
            
        current_table_base = entry & 0x000FFFFFFFFFF000
        
        # PT
        entry, reason = self._read_physical_entry(current_table_base + (pt_index * 8))
        if reason: return None, reason
        if not (entry & 1): return None, FailureReason.PAGE_NOT_PRESENT
        
        phys_frame = entry & 0x000FFFFFFFFFF000
        self._add_to_cache(vpn, phys_frame, 4096)
        
        return phys_frame + offset_4k, None

    def _update_lru(self, key: int):
        if key in self._cache_keys:
            self._cache_keys.remove(key)
        self._cache_keys.append(key)

    def _add_to_cache(self, key: int, phys_frame: int, page_size: int):
        if key in self._cache:
            self._update_lru(key)
            self._cache[key] = (phys_frame, page_size)
            return
            
        if len(self._cache_keys) >= self._cache_size:
            # Evict oldest
            oldest = self._cache_keys.pop(0)
            del self._cache[oldest]
            
        self._cache_keys.append(key)
        self._cache[key] = (phys_frame, page_size)

    def read(self, address: int, length: int) -> MemoryReadResult:
        """
        Reads length bytes starting from virtual address.
        Correctly handles cross-page boundaries and partial reads.
        """
        segments = []
        gaps = []
        
        if length < 0:
            gaps.append(ReadGap(address, length, FailureReason.INVALID_ADDRESS))
            return MemoryReadResult(segments, gaps)
            
        if length == 0:
            return MemoryReadResult(segments, gaps)

        bytes_remaining = length
        current_va = address
        
        while bytes_remaining > 0:
            # Calculate bytes until page boundary
            offset_in_page = current_va & 0xFFF
            bytes_to_read = min(bytes_remaining, 4096 - offset_in_page)
            
            phys_addr, reason = self._translate_va(current_va)
            
            if reason:
                gaps.append(ReadGap(current_va, bytes_to_read, reason))
            else:
                try:
                    data = self._layer.read(phys_addr, bytes_to_read)
                    segments.append(MappedSegment(current_va, data))
                except OutOfBoundsError:
                    gaps.append(ReadGap(current_va, bytes_to_read, FailureReason.PHYSICAL_OUT_OF_BOUNDS))
                    
            current_va += bytes_to_read
            bytes_remaining -= bytes_to_read
            
        return MemoryReadResult(segments, gaps)
