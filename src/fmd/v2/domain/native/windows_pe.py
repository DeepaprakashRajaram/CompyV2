"""
WHAT: Phase 2E-G Windows PE / Kernel Identity Extraction
WHY: Establish exact exact symbol identity (PDB) from Windows PE images in memory.
OWNS: PeIdentityParser, WindowsKernelScanner
DOES NOT OWN: Actual symbol resolution or network acquisition.
"""

import struct
from typing import Optional, List
from .address_space import IAddressSpace
from .symbols import PdbIdentity
from .environment import ScannerObservation, ObservationProvenance, IScanner

class MalformedPeError(Exception):
    """Raised when PE structures are invalid or out of bounds."""
    pass

class PeIdentityParser:
    """
    Forensic, bounded parser for extracting PDB identity from a PE image in memory.
    """
    def __init__(self, address_space: IAddressSpace, base_address: int):
        self.address_space = address_space
        self.base_address = base_address

    def _read_struct(self, rva: int, size: int, fmt: str) -> tuple:
        result = self.address_space.read(self.base_address + rva, size)
        if not result.is_complete:
            raise MalformedPeError(f"Memory incomplete at RVA {hex(rva)}")
        data = result.get_data_if_complete()
        try:
            return struct.unpack(fmt, data)
        except struct.error as e:
            raise MalformedPeError(f"Struct unpack failed: {e}")

    def _read_bytes(self, rva: int, size: int) -> bytes:
        result = self.address_space.read(self.base_address + rva, size)
        if not result.is_complete:
            raise MalformedPeError(f"Memory incomplete at RVA {hex(rva)}")
        return result.get_data_if_complete()

    def parse_pdb_identity(self) -> Optional[PdbIdentity]:
        try:
            # 1. DOS Header
            magic = self._read_bytes(0, 2)
            if magic != b'MZ':
                return None
            
            e_lfanew_tuple = self._read_struct(0x3C, 4, '<I')
            e_lfanew = e_lfanew_tuple[0]
            if e_lfanew < 0x40 or e_lfanew > 0x1000:
                raise MalformedPeError("e_lfanew out of bounds")

            # 2. NT Headers
            nt_sig = self._read_bytes(e_lfanew, 4)
            if nt_sig != b'PE\0\0':
                return None

            # 3. Optional Header Magic
            magic_tuple = self._read_struct(e_lfanew + 24, 2, '<H')
            pe_magic = magic_tuple[0]

            if pe_magic == 0x20B:  # PE32+
                data_dir_offset = e_lfanew + 24 + 112
                num_rva_tuple = self._read_struct(e_lfanew + 24 + 108, 4, '<I')
            elif pe_magic == 0x10B: # PE32
                data_dir_offset = e_lfanew + 24 + 96
                num_rva_tuple = self._read_struct(e_lfanew + 24 + 92, 4, '<I')
            else:
                raise MalformedPeError("Unknown PE magic")

            num_rva = num_rva_tuple[0]
            if num_rva <= 6:
                return None # No debug directory

            # 4. Debug Directory (Index 6)
            debug_dir_rva_tuple = self._read_struct(data_dir_offset + 6 * 8, 8, '<II')
            debug_rva = debug_dir_rva_tuple[0]
            debug_size = debug_dir_rva_tuple[1]

            if debug_rva == 0 or debug_size == 0:
                return None
                
            if debug_size > 0x1000: # sanity bound
                raise MalformedPeError("Debug directory suspiciously large")

            # 5. Parse Debug Directory entries
            # Each entry is 28 bytes
            num_entries = debug_size // 28
            for i in range(num_entries):
                entry_offset = debug_rva + (i * 28)
                # Type is at offset 12, AddressOfRawData is at offset 20
                entry_tuple = self._read_struct(entry_offset + 12, 12, '<III')
                dbg_type = entry_tuple[0]
                dbg_size = entry_tuple[1]
                dbg_rva = entry_tuple[2]

                if dbg_type == 2: # IMAGE_DEBUG_TYPE_CODEVIEW
                    if dbg_rva == 0 or dbg_size < 24:
                        continue
                    
                    if dbg_size > 0x1000: # bounded read
                        raise MalformedPeError("CodeView data size suspiciously large")

                    cv_data = self._read_bytes(dbg_rva, dbg_size)
                    if cv_data[:4] == b'RSDS':
                        guid_bytes = cv_data[4:20]
                        # Format GUID standard Windows way: Mixed endian
                        # Data1 (LE 4), Data2 (LE 2), Data3 (LE 2), Data4 (BE 8)
                        g1, g2, g3 = struct.unpack('<IHH', guid_bytes[:8])
                        g4 = guid_bytes[8:10].hex().upper()
                        g5 = guid_bytes[10:].hex().upper()
                        guid = f"{g1:08X}-{g2:04X}-{g3:04X}-{g4}-{g5}"
                        
                        age = struct.unpack('<I', cv_data[20:24])[0]
                        
                        # PdbName is null terminated
                        pdb_name_bytes = cv_data[24:].split(b'\0')[0]
                        try:
                            pdb_name = pdb_name_bytes.decode('utf-8')
                        except UnicodeDecodeError:
                            continue
                            
                        return PdbIdentity(guid=guid, age=age, pdb_name=pdb_name)

            return None
        except MalformedPeError:
            return None

class WindowsKernelScanner(IScanner):
    """
    Scans a bounded virtual address range for a valid Windows Kernel PE.
    Extracts explicit PDB Identity evidence.
    """
    def __init__(self, start_virtual: int, end_virtual: int, stride: int = 4096):
        self.start_virtual = start_virtual
        self.end_virtual = end_virtual
        self.stride = stride

    def inspect(self, address_space: IAddressSpace) -> List[ScannerObservation]:
        observations = []
        current_addr = self.start_virtual
        
        while current_addr < self.end_virtual:
            result = address_space.read(current_addr, 2)
            if result.is_complete and result.get_data_if_complete() == b'MZ':
                parser = PeIdentityParser(address_space, current_addr)
                pdb_identity = parser.parse_pdb_identity()
                
                if pdb_identity:
                    # Is it a kernel?
                    name_lower = pdb_identity.pdb_name.lower()
                    if "ntoskrnl" in name_lower or "ntkrnlmp" in name_lower:
                        prov = ObservationProvenance(
                            scanner_identity="WindowsKernelScanner",
                            target_artifact="Windows Kernel PE",
                            target_address_space=None,
                            observed_address=current_addr,
                            evidence_references=(
                                f"MZ signature at {hex(current_addr)}",
                                f"RSDS debug record found with PDB: {pdb_identity.pdb_name}"
                            )
                        )
                        obs = ScannerObservation(
                            identity="WINDOWS_KERNEL_IMAGE",
                            evidence_type="KERNEL_IDENTITY",
                            extracted_properties=(
                                ("base_address", current_addr),
                                ("pdb_name", pdb_identity.pdb_name),
                                ("pdb_guid", pdb_identity.guid),
                                ("pdb_age", pdb_identity.age)
                            ),
                            provenance=prov
                        )
                        observations.append(obs)
            
            current_addr += self.stride
            
        return observations
