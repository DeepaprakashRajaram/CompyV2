"""
WHAT: Phase 2D Symbol & Environment Identity abstractions.
WHY: Provide exact symbol resolution without inventing environments or fetching remotely.
OWNS: Environment identity models, symbol repository contracts.
DOES NOT OWN: PDB Parsing, Volatility 3 `Context`.
"""

from dataclasses import dataclass, field
from typing import Optional, Dict, Any, Protocol

class SymbolError(Exception):
    pass

class SymbolUnavailableError(SymbolError):
    """Explicitly raised when no EXACT MATCH symbol table is found."""
    pass

@dataclass(frozen=True)
class PdbIdentity:
    guid: str
    age: int
    pdb_name: str

from .environment import EnvironmentIdentity

class FieldDefinition:
    def __init__(self, name: str, offset: int, field_type: str):
        self.name = name
        self.offset = offset
        self.field_type = field_type

class TypeDefinition:
    def __init__(self, name: str, size: int, fields: Dict[str, FieldDefinition]):
        self.name = name
        self.size = size
        self.fields = fields

class SymbolTable:
    def __init__(self, name: str, types: Dict[str, TypeDefinition]):
        self._name = name
        self._types = types

    @property
    def name(self) -> str:
        return self._name

    def get_type(self, type_name: str) -> TypeDefinition:
        if type_name not in self._types:
            raise SymbolUnavailableError(f"Type {type_name} not found in {self._name}")
        return self._types[type_name]

class ISymbolRepository(Protocol):
    def get_symbol_table(self, identity: EnvironmentIdentity) -> SymbolTable: ...

class LocalIsfRepository(ISymbolRepository):
    """
    Phase 2D Fixture repository that strictly loads local ISF adapters.
    Returns exact matches only.
    """
    def __init__(self):
        self._fixtures: Dict[PdbIdentity, SymbolTable] = {}

    def register_fixture(self, identity: PdbIdentity, table: SymbolTable):
        self._fixtures[identity] = table

    def get_symbol_table(self, identity: EnvironmentIdentity) -> SymbolTable:
        if not identity.symbol_identity:
            raise SymbolUnavailableError("Environment identity lacks symbol identity.")
        table = self._fixtures.get(identity.symbol_identity)
        if not table:
            raise SymbolUnavailableError(
                f"No exact match found for {identity.symbol_identity}. UNAVAILABLE."
            )
        return table
