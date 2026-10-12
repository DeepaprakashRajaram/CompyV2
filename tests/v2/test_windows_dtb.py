import pytest
import struct

from fmd.v2.domain.native.layer import IRawMemoryLayer, OutOfBoundsError
from fmd.v2.domain.native.address_space import FailureReason
from fmd.v2.domain.native.objects import PhysicalAddressSpaceAdapter
from fmd.v2.domain.native.environment import (
    CandidateEnvironment, EnvironmentIdentity, EnvironmentStatus,
    ScannerObservation, ObservationProvenance
)
from fmd.v2.domain.native.windows_dtb import WindowsDtbScanner, WindowsDtbValidator

class MockRawMemoryLayer(IRawMemoryLayer):
    def __init__(self, size: int):
        self.memory = bytearray(size)
    
    def read(self, address: int, length: int) -> bytes:
        if address < 0 or address + length > len(self.memory):
            raise OutOfBoundsError(address)
        return bytes(self.memory[address:address+length])
        
    def write(self, address: int, data: bytes):
        if address < 0 or address + len(data) > len(self.memory):
            raise OutOfBoundsError(address)
        self.memory[address:address+len(data)] = data

def setup_valid_4level_windows_dtb(layer: MockRawMemoryLayer, dtb_addr: int):
    # KUSER_SHARED_DATA is at 0xFFFFF78000000000
    # Let's map it to physical page 0x3000
    # VA: 0xFFFFF78000000000
    # PML4 Index: 510 (0x1FE)
    # PDPT Index: 0
    # PD Index: 0
    # PT Index: 0
    
    pdpt_addr = dtb_addr + 0x1000
    pd_addr = pdpt_addr + 0x1000
    pt_addr = pd_addr + 0x1000
    target_addr = pt_addr + 0x1000
    
    # 1. Self reference in PML4 at index 0x1ED (493)
    pml4_self_ref = dtb_addr | 3 # Present + RW
    layer.write(dtb_addr + 493 * 8, struct.pack("<Q", pml4_self_ref))
    
    # 2. Map KUSER_SHARED_DATA
    layer.write(dtb_addr + 495 * 8, struct.pack("<Q", pdpt_addr | 3))
    layer.write(pdpt_addr + 0 * 8, struct.pack("<Q", pd_addr | 3))
    layer.write(pd_addr + 0 * 8, struct.pack("<Q", pt_addr | 3))
    layer.write(pt_addr + 0 * 8, struct.pack("<Q", target_addr | 3))
    
    return target_addr

def test_valid_4level_candidate():
    layer = MockRawMemoryLayer(0x10000)
    dtb_addr = 0x2000
    setup_valid_4level_windows_dtb(layer, dtb_addr)
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsDtbScanner(0x0, 0x10000, 4096, "4-level")
    
    # A. Valid 4-level DTB candidate discovery
    observations = scanner.inspect(adapter)
    assert len(observations) == 1
    obs = observations[0]
    
    # I. Candidate provenance
    assert obs.provenance.scanner_identity == "WindowsDtbScanner_1.0"
    assert obs.provenance.observed_address == dtb_addr
    
    # Validation
    validator = WindowsDtbValidator(layer)
    candidate_env = CandidateEnvironment(EnvironmentIdentity(os_family="Windows"), [obs])
    status, evidence = validator.validate(candidate_env)
    
    assert status == EnvironmentStatus.VERIFIED
    assert "KUSER_SHARED_DATA" in evidence[0]

def test_invalid_unmapped_dtb():
    # C. Invalid/unmapped DTB.
    layer = MockRawMemoryLayer(0x5000)
    dtb_addr = 0x1000
    # Write self-reference so scanner finds it
    layer.write(dtb_addr + 493 * 8, struct.pack("<Q", dtb_addr | 3))
    
    # Do NOT map KUSER_SHARED_DATA
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsDtbScanner(0x0, 0x5000)
    observations = scanner.inspect(adapter)
    
    assert len(observations) == 1
    
    candidate_env = CandidateEnvironment(EnvironmentIdentity(os_family="Windows"), observations)
    validator = WindowsDtbValidator(layer)
    status, evidence = validator.validate(candidate_env)
    
    assert status == EnvironmentStatus.INVALID
    assert "unmapped" in evidence[0].lower()

def test_truncated_physical_page_tables():
    # D. DTB pointing to truncated physical page tables.
    layer = MockRawMemoryLayer(0x3000)
    dtb_addr = 0x1000
    
    # Setup PML4 pointing to out-of-bounds PDPT
    layer.write(dtb_addr + 493 * 8, struct.pack("<Q", dtb_addr | 3))
    layer.write(dtb_addr + 495 * 8, struct.pack("<Q", 0x10000 | 3)) # Out of bounds
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsDtbScanner(0x0, 0x3000)
    obs = scanner.inspect(adapter)
    
    candidate_env = CandidateEnvironment(EnvironmentIdentity(os_family="Windows"), obs)
    validator = WindowsDtbValidator(layer)
    status, evidence = validator.validate(candidate_env)
    
    assert status == EnvironmentStatus.UNAVAILABLE
    assert "truncated" in evidence[0].lower()

def test_multiple_candidates_only_one_valid():
    # F. Multiple candidates where only one is structurally valid.
    layer = MockRawMemoryLayer(0x20000)
    
    # Candidate 1: Invalid
    dtb1 = 0x1000
    layer.write(dtb1 + 493 * 8, struct.pack("<Q", dtb1 | 3))
    
    # Candidate 2: Valid
    dtb2 = 0xA000
    setup_valid_4level_windows_dtb(layer, dtb2)
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsDtbScanner(0x0, 0x20000)
    observations = scanner.inspect(adapter)
    
    assert len(observations) == 2
    
    validator = WindowsDtbValidator(layer)
    
    cand1 = CandidateEnvironment(EnvironmentIdentity(os_family="Windows"), [observations[0]])
    status1, _ = validator.validate(cand1)
    assert status1 == EnvironmentStatus.INVALID
    
    cand2 = CandidateEnvironment(EnvironmentIdentity(os_family="Windows"), [observations[1]])
    status2, _ = validator.validate(cand2)
    assert status2 == EnvironmentStatus.VERIFIED

def test_deterministic_repeated_scanning():
    # H. Deterministic repeated scanning.
    # J. Candidate identity determinism.
    layer = MockRawMemoryLayer(0x10000)
    setup_valid_4level_windows_dtb(layer, 0x2000)
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsDtbScanner(0x0, 0x10000)
    
    run1 = scanner.inspect(adapter)
    run2 = scanner.inspect(adapter)
    
    assert len(run1) == 1
    assert len(run2) == 1
    assert run1[0].identity == run2[0].identity
    assert run1[0].extracted_properties == run2[0].extracted_properties
    assert run1[0].provenance == run2[0].provenance

def test_invalid_paging_mode():
    layer = MockRawMemoryLayer(0x10000)
    setup_valid_4level_windows_dtb(layer, 0x2000)
    adapter = PhysicalAddressSpaceAdapter(layer)
    
    # E. Candidate producing invalid page-table structures.
    # Passing '3-level' or arbitrary strings to test unsupported validation
    scanner = WindowsDtbScanner(0x0, 0x10000, paging_mode="3-level")
    obs = scanner.inspect(adapter)
    
    validator = WindowsDtbValidator(layer)
    status, evidence = validator.validate(CandidateEnvironment(EnvironmentIdentity(), obs))
    
    assert status == EnvironmentStatus.UNSUPPORTED
    
def test_no_nearest_environment_selection():
    # M. No nearest-environment selection.
    layer = MockRawMemoryLayer(0x10000)
    dtb_addr = 0x2000
    setup_valid_4level_windows_dtb(layer, dtb_addr)
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsDtbScanner(0x0, 0x10000)
    observations = scanner.inspect(adapter)
    
    # We only set os_family="Windows". We don't guess "Windows 10" or "Windows 7"
    props = dict(observations[0].extracted_properties)
    assert props["os_family"] == "Windows"
    assert "version" not in props
    assert "build" not in props
