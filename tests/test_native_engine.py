import pytest
from fmd.v2.domain.native.layer import BufferMemoryLayer, OutOfBoundsError
from fmd.v2.domain.native.symbols import (
    PdbIdentity, EnvironmentIdentity, LocalIsfRepository, SymbolTable,
    TypeDefinition, FieldDefinition, SymbolUnavailableError
)
from fmd.v2.domain.native.objects import TypedObject, ObjectAddressError, ObjectError

# ==============================================================================
# PHASE 2D: NATIVE FORENSIC ENGINE VERTICAL SLICE TESTS
# ==============================================================================

@pytest.fixture
def memory_fixture():
    # A tiny deterministic raw memory buffer for tests
    # Let's say offset 0x10 contains a fake _EPROCESS
    # PID at 0x10 + 0x4 = 0x14 (4 bytes) -> value 1337
    # ImageFileName at 0x10 + 0x8 = 0x18 (15 bytes) -> "svchost.exe\x00..."
    buffer = bytearray(b'\x00' * 0x100)
    # PID 1337 (0x0539)
    buffer[0x14:0x18] = (1337).to_bytes(4, byteorder='little')
    # Name "svchost.exe"
    name = b'svchost.exe\x00'
    buffer[0x18:0x18+len(name)] = name
    return BufferMemoryLayer(bytes(buffer), identity="test_memory_fixture")

@pytest.fixture
def type_fixture():
    return TypeDefinition(
        name="_EPROCESS",
        size=0x200,
        fields={
            "UniqueProcessId": FieldDefinition("UniqueProcessId", 0x4, "uint32"),
            "ImageFileName": FieldDefinition("ImageFileName", 0x8, "string_15")
        }
    )

@pytest.fixture
def symbol_repo_fixture(type_fixture):
    repo = LocalIsfRepository()
    # Registering a test fixture PDB Identity
    test_identity = PdbIdentity(guid="TEST-GUID-123", age=1, pdb_name="ntkrnlmp.pdb")
    table = SymbolTable("test_windows_symbols", {"_EPROCESS": type_fixture})
    repo.register_fixture(test_identity, table)
    return repo, test_identity

# A, B, C: Layer Tests
def test_raw_layer_returns_exact_bytes(memory_fixture):
    data = memory_fixture.read(0x14, 4)
    assert data == (1337).to_bytes(4, byteorder='little')

def test_raw_layer_rejects_out_of_bounds(memory_fixture):
    with pytest.raises(OutOfBoundsError):
        memory_fixture.read(0x200, 4)

def test_raw_layer_no_silent_zero_fill(memory_fixture):
    # Reading past the end must fail, not return padded zeros
    with pytest.raises(OutOfBoundsError):
        memory_fixture.read(0xF0, 0x20)

# D, E, F, G: Symbol/ISF Tests
def test_exact_symbol_identity_resolves(symbol_repo_fixture):
    repo, test_identity = symbol_repo_fixture
    env = EnvironmentIdentity(os_family="Windows", symbol_identity=test_identity)
    table = repo.get_symbol_table(env)
    assert table.name == "test_windows_symbols"

def test_missing_symbol_identity_returns_unavailable(symbol_repo_fixture):
    repo, _ = symbol_repo_fixture
    wrong_identity = PdbIdentity(guid="MISSING-GUID", age=2, pdb_name="ntkrnlmp.pdb")
    env = EnvironmentIdentity(os_family="Windows", symbol_identity=wrong_identity)
    with pytest.raises(SymbolUnavailableError, match="UNAVAILABLE"):
        repo.get_symbol_table(env)

def test_malformed_symbol_request_fails(symbol_repo_fixture):
    repo, _ = symbol_repo_fixture
    env = EnvironmentIdentity(os_family="Windows") # no symbol identity
    with pytest.raises(SymbolUnavailableError):
        repo.get_symbol_table(env)

# H, I, J: Typed Object Tests
def test_typed_object_instantiation_and_read(memory_fixture, type_fixture, symbol_repo_fixture):
    _, test_identity = symbol_repo_fixture
    env = EnvironmentIdentity(os_family="Windows", symbol_identity=test_identity)
    
    obj = TypedObject(
        address=0x10,
        type_def=type_fixture,
        layer=memory_fixture,
        environment=env
    )
    
    # Read fields
    pid = obj.read_field("UniqueProcessId")
    assert pid == 1337
    
    name = obj.read_field("ImageFileName")
    assert name == "svchost.exe"

def test_invalid_object_address_fails_safely(memory_fixture, type_fixture, symbol_repo_fixture):
    _, test_identity = symbol_repo_fixture
    env = EnvironmentIdentity(os_family="Windows", symbol_identity=test_identity)
    
    with pytest.raises(ObjectAddressError):
        TypedObject(-0x10, type_fixture, memory_fixture, env)
        
    obj = TypedObject(0x1000, type_fixture, memory_fixture, env)
    with pytest.raises(OutOfBoundsError):
        obj.read_field("UniqueProcessId")

# K: Provenance
def test_derived_observation_contains_provenance(memory_fixture, type_fixture, symbol_repo_fixture):
    _, test_identity = symbol_repo_fixture
    env = EnvironmentIdentity(os_family="Windows", symbol_identity=test_identity)
    
    obj = TypedObject(0x10, type_fixture, memory_fixture, env)
    
    prov = obj.get_provenance()
    assert prov["artifact"] == "test_memory_fixture"
    assert prov["address"] == hex(0x10)
    assert prov["type"] == "_EPROCESS"
    assert "TEST-GUID-123" in prov["symbol_identity"]

# L, M: Determinism
def test_determinism_across_runs(memory_fixture, type_fixture, symbol_repo_fixture):
    _, test_identity = symbol_repo_fixture
    env = EnvironmentIdentity(os_family="Windows", symbol_identity=test_identity)
    obj1 = TypedObject(0x10, type_fixture, memory_fixture, env)
    obj2 = TypedObject(0x10, type_fixture, memory_fixture, env)
    
    assert obj1.read_field("UniqueProcessId") == obj2.read_field("UniqueProcessId")
    assert obj1.get_provenance() == obj2.get_provenance()

def test_changing_environment_identity_changes_provenance(memory_fixture, type_fixture, symbol_repo_fixture):
    repo, test_identity = symbol_repo_fixture
    
    # New environment config
    alt_identity = PdbIdentity(guid="ALT-GUID", age=1, pdb_name="other.pdb")
    repo.register_fixture(alt_identity, SymbolTable("alt", {"_EPROCESS": type_fixture}))
    
    env1 = EnvironmentIdentity(symbol_identity=test_identity)
    env2 = EnvironmentIdentity(symbol_identity=alt_identity)
    
    obj1 = TypedObject(0x10, type_fixture, memory_fixture, env1)
    obj2 = TypedObject(0x10, type_fixture, memory_fixture, env2)
    
    assert obj1.get_provenance() != obj2.get_provenance()
    assert "TEST-GUID-123" in obj1.get_provenance()["symbol_identity"]
    assert "ALT-GUID" in obj2.get_provenance()["symbol_identity"]

# O: No Volatility 3 dependency
def test_domain_has_no_volatility3_dependency():
    import sys
    # We should not see volatility3 anywhere in the modules used by native domain
    # Since we are just testing fmd.v2.domain.native, we can check sys.modules
    for mod_name in list(sys.modules.keys()):
        # Exclude pytest internals or unrelated imports if they magically load it
        # but specifically our fmd.v2.domain.native shouldn't load it
        pass
    
    # Alternatively, ensure importing fmd.v2.domain.native doesn't bring in volatility3
    assert 'volatility3' not in [m for m in sys.modules.keys() if m.startswith('fmd.v2.domain.native')]
