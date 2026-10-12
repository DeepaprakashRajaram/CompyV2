import pytest
from typing import List

from fmd.v2.domain.native.layer import BufferMemoryLayer, OutOfBoundsError
from fmd.v2.domain.native.symbols import TypeDefinition, FieldDefinition, EnvironmentIdentity
from fmd.v2.domain.native.objects import TypedObject, ReadStatus, FieldValue, ObjectError
from fmd.v2.domain.native.address_space import (
    MemoryReadResult, MappedSegment, ReadGap, FailureReason, IAddressSpace
)

class MockVirtualAddressSpace(IAddressSpace):
    """
    A deterministic address space that lets us mock explicitly mapped segments
    and explicitly unmapped gaps for testing object partial reads.
    """
    def __init__(self, segments: List[MappedSegment], gaps: List[ReadGap]):
        self.segments = segments
        self.gaps = gaps

    @property
    def identity(self) -> str:
        return "Virtual:MockTest"

    def read(self, address: int, length: int) -> MemoryReadResult:
        # Find which segments/gaps overlap the requested range
        result_segments = []
        result_gaps = []
        
        req_end = address + length
        
        for seg in self.segments:
            seg_start = seg.requested_offset
            seg_end = seg_start + len(seg.data)
            if seg_start < req_end and seg_end > address:
                # Overlap!
                overlap_start = max(address, seg_start)
                overlap_end = min(req_end, seg_end)
                data_start = overlap_start - seg_start
                data_end = data_start + (overlap_end - overlap_start)
                result_segments.append(MappedSegment(overlap_start, seg.data[data_start:data_end]))
                
        for gap in self.gaps:
            gap_start = gap.requested_offset
            gap_end = gap_start + gap.length
            if gap_start < req_end and gap_end > address:
                overlap_start = max(address, gap_start)
                overlap_end = min(req_end, gap_end)
                result_gaps.append(ReadGap(overlap_start, overlap_end - overlap_start, gap.reason))
                
        return MemoryReadResult(result_segments, result_gaps)

@pytest.fixture
def type_fixture():
    # 0x200 (512 bytes) size object
    # Field A at offset 0 (4 bytes)
    # Field B at offset 4000 (4 bytes) -> Wait, size is 0x200 so max offset is 511.
    # Let's make an object of size 8192 (2 pages)
    return TypeDefinition(
        name="LargeObject",
        size=8192,
        fields={
            "FieldA": FieldDefinition("FieldA", 0, "uint32"),        # Page 1
            "FieldB": FieldDefinition("FieldB", 4094, "uint32"),     # Crosses Page 1 & 2
            "FieldC": FieldDefinition("FieldC", 4100, "uint32"),     # Page 2
            "FieldD": FieldDefinition("FieldD", 8000, "uint32"),     # Page 2
        }
    )

@pytest.fixture
def environment():
    return EnvironmentIdentity(os_family="Windows")

# A. Single-page complete object
def test_single_page_complete_object(type_fixture, environment):
    # Object is 8192 bytes, so two pages, but let's assume it's fully mapped
    data = (1).to_bytes(4, "little") + b"\x00" * 8188
    space = MockVirtualAddressSpace(
        segments=[MappedSegment(0x1000, data)], gaps=[]
    )
    obj = TypedObject(0x1000, type_fixture, space, environment)
    assert obj.get_object_status() == ReadStatus.COMPLETE
    
    val = obj.read_field_explicit("FieldA")
    assert val.status == ReadStatus.COMPLETE
    assert val.value == 1

# B. Multi-page complete object
def test_multi_page_complete_object(type_fixture, environment):
    data1 = (2).to_bytes(4, "little") + b"\x00" * 4092
    data2 = b"\x00\x00\x00\x00" * 1024 # 4096 bytes
    space = MockVirtualAddressSpace(
        segments=[MappedSegment(0x1000, data1), MappedSegment(0x2000, data2)],
        gaps=[]
    )
    obj = TypedObject(0x1000, type_fixture, space, environment)
    assert obj.get_object_status() == ReadStatus.COMPLETE
    assert obj.read_field("FieldA") == 2

# C, M. Multi-page object with missing second page -> Object PARTIAL, FieldC UNAVAILABLE
def test_multi_page_missing_second_page(type_fixture, environment):
    data1 = (3).to_bytes(4, "little") + b"\x00" * 4092
    space = MockVirtualAddressSpace(
        segments=[MappedSegment(0x1000, data1)],
        gaps=[ReadGap(0x2000, 4096, FailureReason.PAGE_NOT_PRESENT)]
    )
    obj = TypedObject(0x1000, type_fixture, space, environment)
    assert obj.get_object_status() == ReadStatus.PARTIAL
    
    # FieldA is fully in Page 1 -> COMPLETE
    val_a = obj.read_field_explicit("FieldA")
    assert val_a.status == ReadStatus.COMPLETE
    assert val_a.value == 3
    
    # FieldC is fully in Page 2 -> UNAVAILABLE
    val_c = obj.read_field_explicit("FieldC")
    assert val_c.status == ReadStatus.UNAVAILABLE
    assert val_c.value is None

# E. Object where a field crosses a page boundary -> PARTIAL field if second page missing
def test_field_crosses_page_boundary(type_fixture, environment):
    data1 = b"\x00" * 4094 + (4).to_bytes(2, "little") # 4096 bytes total
    space = MockVirtualAddressSpace(
        segments=[MappedSegment(0x1000, data1)],
        gaps=[ReadGap(0x2000, 4096, FailureReason.PAGE_NOT_PRESENT)]
    )
    obj = TypedObject(0x1000, type_fixture, space, environment)
    
    # FieldB is at 4094 (2 bytes in page 1, 2 bytes in page 2)
    val_b = obj.read_field_explicit("FieldB")
    assert val_b.status == ReadStatus.PARTIAL
    assert val_b.value is None
    assert len(val_b.segments) == 1
    assert len(val_b.gaps) == 1

# K. No silent truncation behavior
def test_no_silent_truncation(type_fixture, environment):
    # Only 2 bytes mapped for FieldA
    data1 = (5).to_bytes(2, "little")
    space = MockVirtualAddressSpace(
        segments=[MappedSegment(0x1000, data1)],
        gaps=[ReadGap(0x1002, 4094, FailureReason.PAGE_NOT_PRESENT)]
    )
    obj = TypedObject(0x1000, type_fixture, space, environment)
    
    val_a = obj.read_field_explicit("FieldA")
    assert val_a.status == ReadStatus.PARTIAL
    # Legacy read_field should raise
    with pytest.raises(ObjectError):
        obj.read_field("FieldA")

# O. Provenance contains virtual/address-space/read completeness information
def test_provenance_information(type_fixture, environment):
    data1 = (6).to_bytes(4, "little") + b"\x00" * 4092
    space = MockVirtualAddressSpace(
        segments=[MappedSegment(0x1000, data1)],
        gaps=[ReadGap(0x2000, 4096, FailureReason.PAGE_NOT_PRESENT)]
    )
    obj = TypedObject(0x1000, type_fixture, space, environment)
    
    prov = obj.get_provenance()
    assert prov["address"] == hex(0x1000)
    assert prov["address_space"] == "Virtual:MockTest"
    assert prov["object_status"] == "PARTIAL"
    assert prov["requested_size"] == 8192
    assert (0x1000, 4096) in prov["mapped_segments"]
    assert (0x2000, 4096, "PAGE_NOT_PRESENT") in prov["unavailable_gaps"]

# G. Object with multiple mapped segments and multiple gaps
def test_fragmented_object_reads(type_fixture, environment):
    data1 = (7).to_bytes(4, "little") + b"\x00" * 2000
    data2 = b"\x00\x00\x00\x00" + (8).to_bytes(4, "little") + b"\x00" * 2000
    space = MockVirtualAddressSpace(
        segments=[MappedSegment(0x1000, data1), MappedSegment(0x2000, data2)],
        gaps=[ReadGap(0x1000 + 2004, 2092, FailureReason.PAGE_NOT_PRESENT)] # Gap in the middle
    )
    # 0x1000-0x17D4 (Mapped)
    # 0x17D4-0x2000 (Gap)
    # 0x2000-0x27D4 (Mapped)
    obj = TypedObject(0x1000, type_fixture, space, environment)
    
    val_a = obj.read_field_explicit("FieldA") # at 0x1000
    assert val_a.status == ReadStatus.COMPLETE
    assert val_a.value == 7
    
    val_c = obj.read_field_explicit("FieldC") # at 0x1000 + 4100 = 0x2004
    assert val_c.status == ReadStatus.COMPLETE
    assert val_c.value == 8

    assert obj.get_object_status() == ReadStatus.PARTIAL
