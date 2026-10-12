"""
WHAT: Phase 2E-F Windows DTB Candidate Discovery and Validation
WHY: Implement structural discovery and validation of Windows DTB candidates without conflating them with verified OS identities.
OWNS: WindowsDtbScanner, WindowsDtbValidator.
DOES NOT OWN: Complete Windows identity, exact build extraction, symbols.
"""
import struct
from typing import List, Tuple, Dict, Any, Optional

from .layer import IRawMemoryLayer, OutOfBoundsError
from .environment import (
    ScannerObservation, ObservationProvenance, EnvironmentStatus,
    IScanner, CandidateEnvironment, VerifiedEnvironment, EnvironmentIdentity
)
from .address_space import FailureReason, IAddressSpace, MemoryReadResult
from .paging import TranslationContext, X64VirtualAddressSpace

class WindowsDtbScanner(IScanner):
    """
    Scans bounded physical memory for DTB candidates based on basic structure.
    Does not perform validation.
    """
    def __init__(self, start_physical: int, end_physical: int, stride: int = 4096, paging_mode: str = "4-level"):
        self.start_physical = start_physical
        self.end_physical = end_physical
        self.stride = stride
        self.paging_mode = paging_mode
        self.scanner_identity = "WindowsDtbScanner_1.0"

    def inspect(self, address_space: IAddressSpace) -> List[ScannerObservation]:
        observations = []
        current = self.start_physical
        
        while current < self.end_physical:
            result = address_space.read(current, 4096)
            if not result.is_complete:
                current += self.stride
                continue
                
            data = result.get_data_if_complete()
            entries = struct.unpack("<512Q", data)
            
            # Heuristic: self-referencing PML4 entry
            for index, entry in enumerate(entries):
                if (entry & 1) and ((entry & 0x000FFFFFFFFFF000) == current):
                    prov = ObservationProvenance(
                        scanner_identity=self.scanner_identity,
                        target_artifact="memory",
                        target_address_space=address_space.identity,
                        observed_address=current,
                        evidence_references=(f"Self-referential entry at index {index}",)
                    )
                    obs = ScannerObservation(
                        identity=f"WIN_DTB_CAND_{hex(current)}",
                        evidence_type="WINDOWS_DTB_CANDIDATE",
                        extracted_properties=(
                            ("dtb", current),
                            ("os_family", "Windows"),
                            ("paging_mode", self.paging_mode),
                            ("self_ref_index", index)
                        ),
                        provenance=prov
                    )
                    observations.append(obs)
            
            current += self.stride
            
        return observations


class WindowsDtbValidator:
    """
    Performs structural validation on a DTB candidate by constructing an address space
    and attempting Windows-specific structural reads (e.g., KUSER_SHARED_DATA).
    """
    def __init__(self, physical_layer: IRawMemoryLayer):
        self.physical_layer = physical_layer

    def validate(self, candidate_env: CandidateEnvironment) -> Tuple[EnvironmentStatus, Tuple[str, ...]]:
        """
        Validates the given CandidateEnvironment's DTB observation.
        Returns (Status, Evidence)
        """
        # Find the DTB observation
        dtb_obs = None
        for obs in candidate_env.supporting_observations:
            if obs.evidence_type == "WINDOWS_DTB_CANDIDATE":
                dtb_obs = obs
                break
                
        if not dtb_obs:
            return EnvironmentStatus.INSUFFICIENT_EVIDENCE, ("No Windows DTB candidate observation found",)
            
        props = dict(dtb_obs.extracted_properties)
        dtb = props.get("dtb")
        paging_mode = props.get("paging_mode")
        
        if dtb is None or paging_mode is None:
            return EnvironmentStatus.INVALID, ("Missing DTB or paging mode property",)
            
        if paging_mode not in ["4-level", "5-level"]:
            return EnvironmentStatus.UNSUPPORTED, (f"Unsupported paging mode: {paging_mode}",)
            
        context = TranslationContext(paging_mode=paging_mode, dtb=dtb)
        
        try:
            addr_space = X64VirtualAddressSpace(self.physical_layer, context)
        except ValueError as e:
            return EnvironmentStatus.INVALID, (f"Failed to construct address space: {str(e)}",)
            
        # Structural read on KUSER_SHARED_DATA
        kuser_shared_data = 0xFFFFF78000000000
        result = addr_space.read(kuser_shared_data, 4096)
        
        if any(gap.reason == FailureReason.PHYSICAL_OUT_OF_BOUNDS for gap in result.gaps):
            return EnvironmentStatus.UNAVAILABLE, ("Physical memory truncated during page walk",)
            
        if not result.is_complete:
            return EnvironmentStatus.INVALID, ("Failed structural read (KUSER_SHARED_DATA unmapped)",)
            
        return EnvironmentStatus.VERIFIED, ("Structural translation to KUSER_SHARED_DATA succeeded",)
