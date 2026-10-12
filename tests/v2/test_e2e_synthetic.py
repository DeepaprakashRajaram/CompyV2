import unittest
import struct
from typing import Optional, Dict, Any

from fmd.v2.domain.native.layer import IRawMemoryLayer, OutOfBoundsError
from fmd.v2.domain.native.address_space import FailureReason
from fmd.v2.domain.native.windows_dtb import WindowsDtbScanner, WindowsDtbValidator
from fmd.v2.domain.native.environment import (
    CandidateEnvironment, EnvironmentStatus, EnvironmentIdentity, VerifiedEnvironment
)
from fmd.v2.domain.native.paging import TranslationContext, X64VirtualAddressSpace
from fmd.v2.domain.native.windows_pe import WindowsKernelScanner, PeIdentityParser, MalformedPeError
from fmd.v2.domain.native.symbols import (
    PdbIdentity, LocalIsfRepository, SymbolTable, TypeDefinition, FieldDefinition
)
from fmd.v2.domain.native.objects import TypedObject, ReadStatus, PhysicalAddressSpaceAdapter

class MockRawMemoryLayer(IRawMemoryLayer):
    def __init__(self, memory_dict: Dict[int, bytes]):
        self.memory = memory_dict
        
    @property
    def artifact_identity(self) -> str:
        return "synthetic_e2e_memory"
        
    def read(self, address: int, length: int) -> bytes:
        result = bytearray()
        for i in range(length):
            if address + i not in self.memory:
                raise OutOfBoundsError(f"Address {hex(address + i)} not mapped")
            result.extend(self.memory[address + i])
        return bytes(result)

class SyntheticEnvironmentBuilder:
    def __init__(self):
        self.memory = {}
        self.layer = MockRawMemoryLayer(self.memory)

    def write_phys(self, address: int, data: bytes):
        for i, b in enumerate(data):
            self.memory[address + i] = bytes([b])

    def setup_dtb(self, dtb: int = 0x1000, valid: bool = True, self_ref: bool = True):
        # Clear/Create PML4 at dtb
        pml4 = bytearray(4096)
        if self_ref:
            # Self ref at index 0 for WindowsDtbScanner heuristic
            pml4[0:8] = struct.pack("<Q", dtb | 3)
            
        if valid:
            # Map KUSER_SHARED_DATA (0xFFFFF78000000000)
            # PML4 = 495, PDPT = 0, PD = 0, PT = 0
            pml4[495 * 8 : 495 * 8 + 8] = struct.pack("<Q", 0x2000 | 3)
            pdpt1 = bytearray(4096)
            pdpt1[0 : 8] = struct.pack("<Q", 0x3000 | 3)
            pd1 = bytearray(4096)
            pd1[0 : 8] = struct.pack("<Q", 0x4000 | 3)
            pt1 = bytearray(4096)
            pt1[0 : 8] = struct.pack("<Q", 0x5000 | 3)
            
            # Write physical pages
            self.write_phys(0x2000, pdpt1)
            self.write_phys(0x3000, pd1)
            self.write_phys(0x4000, pt1)
            kuser_page = bytearray(4096)
            kuser_page[0:5] = b"KUSER"
            self.write_phys(0x5000, kuser_page) # Physical page for KUSER_SHARED_DATA

            # Map Kernel Base (0xFFFFF80000000000)
            # PML4 = 496, PDPT = 0, PD = 0, PT = 0
            pml4[496 * 8 : 496 * 8 + 8] = struct.pack("<Q", 0x6000 | 3)
            pdpt2 = bytearray(4096)
            pdpt2[0 : 8] = struct.pack("<Q", 0x7000 | 3)
            pd2 = bytearray(4096)
            pd2[0 : 8] = struct.pack("<Q", 0x8000 | 3)
            pt2 = bytearray(4096)
            # Map 4 pages for Kernel
            for i in range(4):
                pt2[i * 8 : i * 8 + 8] = struct.pack("<Q", (0x9000 + i * 4096) | 3)
            
            self.write_phys(0x6000, pdpt2)
            self.write_phys(0x7000, pd2)
            self.write_phys(0x8000, pt2)

        self.write_phys(dtb, pml4)

    def write_kernel_pe(
        self, 
        base_phys: int = 0x9000, 
        malformed: bool = False, 
        no_debug: bool = False, 
        invalid_rsds: bool = False,
        guid_bytes: bytes = b'\x11'*16,
        age: int = 1,
        pdb_name: bytes = b"ntoskrnl.pdb\x00"
    ):
        header = bytearray(4096)
        
        if malformed:
            header[0:2] = b"XX"
        else:
            # MZ
            header[0:2] = b"MZ"
            # e_lfanew
            struct.pack_into("<I", header, 0x3C, 0x100)
            
            # NT Headers
            header[0x100:0x104] = b"PE\0\0"
            # FileHeader SizeOfOptionalHeader
            struct.pack_into("<H", header, 0x114, 0xF0)
            # OptionalHeader Magic
            struct.pack_into("<H", header, 0x118, 0x20B)
            # NumberOfRvaAndSizes
            struct.pack_into("<I", header, 0x184, 16)
            
            if not no_debug:
                # Debug Directory offset and size (Index 6)
                debug_dir_vaddr = 0x1000
                debug_dir_size = 28
                
                # PE32+ DataDirectory is at 0x118 + 0x70 = 0x188
                struct.pack_into("<I", header, 0x188 + 6*8, debug_dir_vaddr)
                struct.pack_into("<I", header, 0x188 + 6*8 + 4, debug_dir_size)
                
                # Write Debug Directory (virtually at +0x1000, physically at +0x1000)
                debug_dir = bytearray(4096)
                # Type = 2 (CodeView)
                struct.pack_into("<I", debug_dir, 12, 2)
                
                cv_vaddr = 0x2000
                cv_size = 4 + 16 + 4 + len(pdb_name)
                # SizeOfData
                struct.pack_into("<I", debug_dir, 16, cv_size)
                # AddressOfRawData
                struct.pack_into("<I", debug_dir, 20, cv_vaddr)
                
                # Write CodeView (virtually at +0x2000, physically at +0x2000)
                cv = bytearray(4096)
                if not invalid_rsds:
                    cv[0:4] = b"RSDS"
                else:
                    cv[0:4] = b"BAD0"
                cv[4:20] = guid_bytes
                struct.pack_into("<I", cv, 20, age)
                cv[24:24+len(pdb_name)] = pdb_name
                
                self.write_phys(base_phys + 0x1000, debug_dir)
                self.write_phys(base_phys + 0x2000, cv)
                
        self.write_phys(base_phys, header)
        
    def write_typed_object(self, base_phys: int = 0xC000):
        # We mapped 4 pages (0x9000, 0xA000, 0xB000, 0xC000) for kernel.
        # base_phys is 0xC000, corresponding to 0xFFFFF80000003000
        obj_data = bytearray(4096)
        struct.pack_into("<I", obj_data, 0, 0xDEADBEEF) # uint32 field at offset 0
        obj_data[4:20] = b"SyntheticProcess"
        self.write_phys(base_phys, obj_data)


class EndToEndPipeline:
    def __init__(self, layer: MockRawMemoryLayer):
        self.layer = layer
        self.dtb_scanner = WindowsDtbScanner(0x0, 0x5000, stride=0x1000)
        self.dtb_validator = WindowsDtbValidator(self.layer)
        self.isf_repo = LocalIsfRepository()
        
    def run(self) -> Dict[str, Any]:
        results = {
            "dtb_found": False,
            "dtb_valid": False,
            "kernel_pe_found": False,
            "pdb_identity": None,
            "symbol_resolved": False,
            "typed_object_val": None,
            "provenance": []
        }
        
        # 1. Physical address space
        phys_as = PhysicalAddressSpaceAdapter(self.layer)
        
        # 2. Windows DTB Scanner
        observations = self.dtb_scanner.inspect(phys_as)
        if not observations:
            return results
            
        results["dtb_found"] = True
        results["provenance"].append(observations[0])
        
        # Candidate 
        candidate = CandidateEnvironment(
            identity=EnvironmentIdentity(os_family="Windows"),
            supporting_observations=observations,
            status=EnvironmentStatus.CANDIDATE
        )
        
        # 3. DTB Validator
        status, evidence = self.dtb_validator.validate(candidate)
        if status != EnvironmentStatus.VERIFIED:
            return results
            
        results["dtb_valid"] = True
        dtb = dict(observations[0].extracted_properties)["dtb"]
        ctx = TranslationContext("4-level", dtb)
        virt_as = X64VirtualAddressSpace(self.layer, ctx)
        
        # 4. Kernel Scanner
        kernel_scanner = WindowsKernelScanner(0xFFFFF80000000000, 0xFFFFF80000004000, 0x1000)
        kernel_obs = kernel_scanner.inspect(virt_as)
        if not kernel_obs:
            return results
            
        results["kernel_pe_found"] = True
        results["provenance"].extend(kernel_obs)
        
        props = dict(kernel_obs[0].extracted_properties)
        pdb_identity = PdbIdentity(props["pdb_guid"], props["pdb_age"], props["pdb_name"])
        results["pdb_identity"] = pdb_identity
        
        # 5. Exact Local ISF Resolution
        try:
            # We must pass an EnvironmentIdentity containing the pdb_identity
            env_identity = EnvironmentIdentity(os_family="Windows", symbol_identity=pdb_identity)
            sym_table = self.isf_repo.get_symbol_table(env_identity)
            results["symbol_resolved"] = True
        except Exception:
            return results
            
        # 6. Typed Object
        type_def = sym_table.get_type("_EPROCESS")
        
        # Object is mapped at base + 0x3000
        obj_addr = 0xFFFFF80000003000
        typed_obj = TypedObject(
            address=obj_addr,
            type_def=type_def,
            layer=virt_as,
            environment=env_identity
        )
        
        val = typed_obj.read_field("UniqueProcessId")
        name = typed_obj.read_field("ImageFileName")
        results["typed_object_val"] = (val, name)
        results["provenance"].append(typed_obj.get_provenance())
        
        return results

class TestEndToEndSynthetic(unittest.TestCase):
    def setUp(self):
        self.builder = SyntheticEnvironmentBuilder()
        # Common valid ISF registration
        self.valid_guid_bytes = b'\x11\x22\x33\x44\x55\x66\x77\x88\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00'
        # mixed-endian string for the above guid:
        # Data1 LE (11223344) -> 44332211
        # Data2 LE (5566)     -> 6655
        # Data3 LE (7788)     -> 8877
        # Data4 BE (99AABBCCDDEEFF00) -> 99AABBCCDDEEFF00
        self.expected_guid_str = "44332211-6655-8877-99AA-BBCCDDEEFF00"
        self.expected_pdb_name = "ntoskrnl.pdb"
        self.expected_age = 1
        
        self.expected_pdb_identity = PdbIdentity(self.expected_guid_str, self.expected_age, self.expected_pdb_name)

    def _register_isf(self, pipeline: EndToEndPipeline, pdb_identity: PdbIdentity):
        fields = {
            "UniqueProcessId": FieldDefinition("UniqueProcessId", 0, "uint32"),
            "ImageFileName": FieldDefinition("ImageFileName", 4, "string_16")
        }
        type_def = TypeDefinition("_EPROCESS", 20, fields)
        table = SymbolTable(pdb_identity, {"_EPROCESS": type_def})
        pipeline.isf_repo.register_fixture(pdb_identity, table)

    def test_e2e_success(self):
        # A. K. L. M. N. (Successful path, determinism, exact resolution, provenance, typed object)
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        self.builder.write_kernel_pe(0x9000, guid_bytes=self.valid_guid_bytes)
        self.builder.write_typed_object(0xC000)
        
        pipeline = EndToEndPipeline(self.builder.layer)
        self._register_isf(pipeline, self.expected_pdb_identity)
        
        res = pipeline.run()
        self.assertTrue(res["dtb_found"])
        self.assertTrue(res["dtb_valid"])
        self.assertTrue(res["kernel_pe_found"])
        self.assertEqual(res["pdb_identity"], self.expected_pdb_identity)
        self.assertTrue(res["symbol_resolved"])
        self.assertEqual(res["typed_object_val"], (0xDEADBEEF, "SyntheticProcess"))
        
        # N. Determinism check
        res2 = pipeline.run()
        self.assertEqual(res, res2)

    def test_e2e_failure_no_dtb(self):
        # A. No DTB candidate
        self.builder.setup_dtb(0x1000, valid=True, self_ref=False) # No self ref = not found
        pipeline = EndToEndPipeline(self.builder.layer)
        res = pipeline.run()
        
        self.assertFalse(res["dtb_found"])
        self.assertFalse(res["dtb_valid"])

    def test_e2e_failure_invalid_dtb(self):
        # B. DTB candidate but structurally invalid (e.g. no KUSER_SHARED_DATA)
        self.builder.setup_dtb(0x1000, valid=False, self_ref=True)
        pipeline = EndToEndPipeline(self.builder.layer)
        res = pipeline.run()
        
        self.assertTrue(res["dtb_found"])
        self.assertFalse(res["dtb_valid"]) # Validation fails

    def test_e2e_failure_unavailable_physical_memory(self):
        # C. Structurally valid DTB but physical memory truncated during KUSER access
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        # Erase the physical page for KUSER
        for i in range(4096):
            if 0x5000 + i in self.builder.memory:
                del self.builder.memory[0x5000 + i]
                
        pipeline = EndToEndPipeline(self.builder.layer)
        res = pipeline.run()
        
        self.assertTrue(res["dtb_found"])
        self.assertFalse(res["dtb_valid"])

    def test_e2e_failure_kernel_pe_unavailable(self):
        # D. DTB succeeds but kernel PE unavailable
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        # Erase kernel PE page
        for i in range(4096):
            if 0x9000 + i in self.builder.memory:
                del self.builder.memory[0x9000 + i]
                
        pipeline = EndToEndPipeline(self.builder.layer)
        res = pipeline.run()
        
        self.assertTrue(res["dtb_found"])
        self.assertTrue(res["dtb_valid"])
        self.assertFalse(res["kernel_pe_found"])

    def test_e2e_failure_malformed_pe(self):
        # E. Malformed PE
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        self.builder.write_kernel_pe(0x9000, malformed=True)
        
        pipeline = EndToEndPipeline(self.builder.layer)
        res = pipeline.run()
        
        self.assertTrue(res["dtb_found"])
        self.assertTrue(res["dtb_valid"])
        self.assertFalse(res["kernel_pe_found"])

    def test_e2e_failure_missing_debug_directory(self):
        # F. Missing Debug Directory
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        self.builder.write_kernel_pe(0x9000, no_debug=True)
        
        pipeline = EndToEndPipeline(self.builder.layer)
        res = pipeline.run()
        
        self.assertTrue(res["dtb_found"])
        self.assertTrue(res["dtb_valid"])
        self.assertFalse(res["kernel_pe_found"])

    def test_e2e_failure_invalid_rsds(self):
        # G. Invalid RSDS
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        self.builder.write_kernel_pe(0x9000, invalid_rsds=True)
        
        pipeline = EndToEndPipeline(self.builder.layer)
        res = pipeline.run()
        
        self.assertTrue(res["dtb_found"])
        self.assertTrue(res["dtb_valid"])
        self.assertFalse(res["kernel_pe_found"])

    def test_e2e_failure_no_exact_isf(self):
        # H. PDB identity extracted but no ISF exists
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        self.builder.write_kernel_pe(0x9000, guid_bytes=self.valid_guid_bytes)
        
        pipeline = EndToEndPipeline(self.builder.layer)
        # Deliberately NOT registering ISF
        
        res = pipeline.run()
        self.assertTrue(res["kernel_pe_found"])
        self.assertFalse(res["symbol_resolved"])

    def test_e2e_failure_pdb_guid_mismatch(self):
        # I. PDB GUID mismatch
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        self.builder.write_kernel_pe(0x9000, guid_bytes=self.valid_guid_bytes)
        
        pipeline = EndToEndPipeline(self.builder.layer)
        # Register ISF with different GUID
        wrong_pdb = PdbIdentity("11111111-2222-3333-4444-555555555555", self.expected_age, self.expected_pdb_name)
        self._register_isf(pipeline, wrong_pdb)
        
        res = pipeline.run()
        self.assertTrue(res["kernel_pe_found"])
        self.assertFalse(res["symbol_resolved"])

    def test_e2e_failure_pdb_age_mismatch(self):
        # J. PDB Age mismatch
        self.builder.setup_dtb(0x1000, valid=True, self_ref=True)
        self.builder.write_kernel_pe(0x9000, guid_bytes=self.valid_guid_bytes, age=1)
        
        pipeline = EndToEndPipeline(self.builder.layer)
        # Register ISF with different Age
        wrong_pdb = PdbIdentity(self.expected_guid_str, 999, self.expected_pdb_name)
        self._register_isf(pipeline, wrong_pdb)
        
        res = pipeline.run()
        self.assertTrue(res["kernel_pe_found"])
        self.assertFalse(res["symbol_resolved"])
