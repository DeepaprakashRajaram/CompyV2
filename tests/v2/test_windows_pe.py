import struct
import pytest

from fmd.v2.domain.native.layer import IRawMemoryLayer, OutOfBoundsError
from fmd.v2.domain.native.objects import PhysicalAddressSpaceAdapter
from fmd.v2.domain.native.windows_pe import PeIdentityParser, WindowsKernelScanner, MalformedPeError

class MockRawMemoryLayer(IRawMemoryLayer):
    def __init__(self, size):
        self.memory = bytearray(size)
    def read(self, address, length):
        if address < 0 or address + length > len(self.memory):
            raise OutOfBoundsError(address)
        return bytes(self.memory[address:address+length])
    def write(self, address, data):
        self.memory[address:address+len(data)] = data

def build_valid_pe(layer: MockRawMemoryLayer, base_addr: int, pe_magic: int = 0x20B, pdb_name: bytes = b"ntoskrnl.pdb\0"):
    # DOS Header
    layer.write(base_addr, b'MZ')
    layer.write(base_addr + 0x3C, struct.pack('<I', 0x40)) # e_lfanew
    
    # NT Headers
    e_lfanew = 0x40
    layer.write(base_addr + e_lfanew, b'PE\0\0')
    
    # Optional Header
    layer.write(base_addr + e_lfanew + 24, struct.pack('<H', pe_magic))
    
    if pe_magic == 0x20B:
        num_rva_offset = e_lfanew + 24 + 108
        data_dir_offset = e_lfanew + 24 + 112
    else:
        num_rva_offset = e_lfanew + 24 + 92
        data_dir_offset = e_lfanew + 24 + 96
        
    layer.write(base_addr + num_rva_offset, struct.pack('<I', 16)) # 16 data directories
    
    # Debug Directory at index 6
    debug_dir_rva = 0x200
    debug_dir_size = 28
    layer.write(base_addr + data_dir_offset + 6 * 8, struct.pack('<II', debug_dir_rva, debug_dir_size))
    
    # Debug Directory Entry
    cv_data_rva = 0x300
    cv_data_size = 24 + len(pdb_name)
    # 12: type, 16: size, 20: addressOfRawData
    layer.write(base_addr + debug_dir_rva + 12, struct.pack('<III', 2, cv_data_size, cv_data_rva))
    
    # CodeView RSDS Data
    layer.write(base_addr + cv_data_rva, b'RSDS')
    guid_bytes = bytes.fromhex("112233445566778899AABBCCDDEEFF00") 
    layer.write(base_addr + cv_data_rva + 4, guid_bytes)
    layer.write(base_addr + cv_data_rva + 20, struct.pack('<I', 1)) # Age
    layer.write(base_addr + cv_data_rva + 24, pdb_name)

def test_valid_pe_identity_extraction():
    layer = MockRawMemoryLayer(0x1000)
    build_valid_pe(layer, 0x0)
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    parser = PeIdentityParser(adapter, 0x0)
    identity = parser.parse_pdb_identity()
    
    assert identity is not None
    assert identity.pdb_name == "ntoskrnl.pdb"
    assert identity.age == 1
    # Check GUID format: Data1 (LE), Data2 (LE), Data3 (LE), Data4 (BE)
    # 44332211-6655-8877-99AA-BBCCDDEEFF00
    assert identity.guid == "44332211-6655-8877-99AA-BBCCDDEEFF00"

def test_kernel_scanner_discovery():
    layer = MockRawMemoryLayer(0x2000)
    build_valid_pe(layer, 0x1000, pdb_name=b"ntkrnlmp.pdb\0")
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsKernelScanner(0x0, 0x2000, stride=0x1000)
    observations = scanner.inspect(adapter)
    
    assert len(observations) == 1
    obs = observations[0]
    assert obs.evidence_type == "KERNEL_IDENTITY"
    
    props = dict(obs.extracted_properties)
    assert props["base_address"] == 0x1000
    assert props["pdb_name"] == "ntkrnlmp.pdb"
    
    # Check provenance
    assert obs.provenance.scanner_identity == "WindowsKernelScanner"
    assert obs.provenance.observed_address == 0x1000

def test_ignore_non_kernel_pdb():
    layer = MockRawMemoryLayer(0x1000)
    build_valid_pe(layer, 0x0, pdb_name=b"hal.pdb\0")
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    scanner = WindowsKernelScanner(0x0, 0x1000, stride=0x1000)
    observations = scanner.inspect(adapter)
    
    # It parses successfully but ignores since it's not a kernel
    assert len(observations) == 0

def test_malformed_pe_rejection():
    layer = MockRawMemoryLayer(0x1000)
    build_valid_pe(layer, 0x0)
    # Corrupt magic
    layer.write(0x40, b'XX\0\0')
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    parser = PeIdentityParser(adapter, 0x0)
    identity = parser.parse_pdb_identity()
    
    assert identity is None

def test_out_of_bounds_debug_directory():
    layer = MockRawMemoryLayer(0x1000)
    build_valid_pe(layer, 0x0)
    # Change debug dir size to be too large
    layer.write(0x40 + 24 + 112 + 6 * 8 + 4, struct.pack('<I', 0x2000))
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    parser = PeIdentityParser(adapter, 0x0)
    identity = parser.parse_pdb_identity()
    
    assert identity is None

def test_missing_debug_info():
    layer = MockRawMemoryLayer(0x1000)
    build_valid_pe(layer, 0x0)
    # Change debug directory size to 0
    layer.write(0x40 + 24 + 112 + 6 * 8 + 4, struct.pack('<I', 0))
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    parser = PeIdentityParser(adapter, 0x0)
    assert parser.parse_pdb_identity() is None

def test_invalid_rsds_signature():
    layer = MockRawMemoryLayer(0x1000)
    build_valid_pe(layer, 0x0)
    # Corrupt RSDS signature
    layer.write(0x300, b'NB10')
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    parser = PeIdentityParser(adapter, 0x0)
    assert parser.parse_pdb_identity() is None

def test_incomplete_memory_while_reading():
    layer = MockRawMemoryLayer(0x250) # Cut off before debug data
    build_valid_pe(layer, 0x0)
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    parser = PeIdentityParser(adapter, 0x0)
    assert parser.parse_pdb_identity() is None

def test_isf_repository_integration():
    from fmd.v2.domain.native.symbols import LocalIsfRepository, SymbolTable, SymbolUnavailableError, PdbIdentity
    from fmd.v2.domain.native.environment import EnvironmentIdentity
    
    layer = MockRawMemoryLayer(0x2000)
    build_valid_pe(layer, 0x1000) # builds ntoskrnl.pdb with GUID 443322116655887799AABBCCDDEEFF00
    
    adapter = PhysicalAddressSpaceAdapter(layer)
    parser = PeIdentityParser(adapter, 0x1000)
    pdb_identity = parser.parse_pdb_identity()
    
    env_identity = EnvironmentIdentity(symbol_identity=pdb_identity)
    
    repo = LocalIsfRepository()
    mock_table = SymbolTable("ntoskrnl.exe", {})
    repo.register_fixture(pdb_identity, mock_table)
    
    # Exact match succeeds
    table = repo.get_symbol_table(env_identity)
    assert table is mock_table
    
    # Missing/wrong identity fails
    wrong_pdb = PdbIdentity(guid="WRONG", age=1, pdb_name="ntoskrnl.pdb")
    wrong_env = EnvironmentIdentity(symbol_identity=wrong_pdb)
    with pytest.raises(SymbolUnavailableError):
        repo.get_symbol_table(wrong_env)
