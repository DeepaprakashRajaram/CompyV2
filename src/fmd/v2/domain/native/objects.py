"""
WHAT: Phase 2D/2E-D Object/Type System
WHY: Provide structured interpretation of memory (bounded read) through an address space.
OWNS: Object instantiation, field extraction, read semantics, provenance tracking.
DOES NOT OWN: Interpretation into evidence, Map-Reduce scanners.
"""

from typing import Any, Dict, Union, List
from enum import Enum
import struct
from .layer import IRawMemoryLayer, OutOfBoundsError
from .symbols import TypeDefinition, EnvironmentIdentity
from .address_space import IAddressSpace, MemoryReadResult, FailureReason, ReadGap, MappedSegment

class ObjectError(Exception):
    pass

class ObjectAddressError(ObjectError):
    pass

class ReadStatus(Enum):
    COMPLETE = "COMPLETE"
    PARTIAL = "PARTIAL"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"

class FieldValue:
    """Explicit semantic result for a field read."""
    def __init__(self, name: str, value: Any, status: ReadStatus, gaps: List[ReadGap] = None, segments: List[MappedSegment] = None):
        self.name = name
        self.value = value
        self.status = status
        self.gaps = gaps or []
        self.segments = segments or []

class PhysicalAddressSpaceAdapter(IAddressSpace):
    """Adapter to treat an IRawMemoryLayer as an IAddressSpace for backward compatibility."""
    def __init__(self, layer: IRawMemoryLayer):
        self._layer = layer
        
    @property
    def identity(self) -> str:
        return f"Physical:{self._layer.artifact_identity}"
        
    def read(self, address: int, length: int) -> MemoryReadResult:
        try:
            data = self._layer.read(address, length)
            return MemoryReadResult(segments=[MappedSegment(address, data)], gaps=[])
        except OutOfBoundsError:
            return MemoryReadResult(
                segments=[], 
                gaps=[ReadGap(address, length, FailureReason.PHYSICAL_OUT_OF_BOUNDS)]
            )
        except Exception:
            return MemoryReadResult(
                segments=[], 
                gaps=[ReadGap(address, length, FailureReason.UNKNOWN)]
            )

class TypedObject:
    def __init__(
        self,
        address: int,
        type_def: TypeDefinition,
        layer: Union[IRawMemoryLayer, IAddressSpace],
        environment: EnvironmentIdentity
    ):
        if address < 0:
            raise ObjectAddressError("Address cannot be negative.")
            
        self.address = address
        self.type_def = type_def
        self.environment = environment
        
        if hasattr(layer, "read") and hasattr(layer, "identity") and not hasattr(layer, "artifact_identity"):
            # It's an IAddressSpace
            self.address_space = layer
            self.legacy_layer = None
        else:
            # It's an IRawMemoryLayer
            self.address_space = PhysicalAddressSpaceAdapter(layer)
            self.legacy_layer = layer

    def get_object_status(self) -> ReadStatus:
        """Determines the complete availability status of the object's required memory."""
        res = self.address_space.read(self.address, self.type_def.size)
        if res.is_complete:
            return ReadStatus.COMPLETE
        elif len(res.segments) > 0:
            return ReadStatus.PARTIAL
        else:
            return ReadStatus.UNAVAILABLE

    def read_field_explicit(self, field_name: str) -> FieldValue:
        """Reads a field and returns a semantically rich FieldValue, preserving gaps and partial states."""
        if field_name not in self.type_def.fields:
            raise ObjectError(f"Field '{field_name}' not found in {self.type_def.name}")
            
        field_def = self.type_def.fields[field_name]
        
        # Determine size (in Phase 2D we hardcoded simple type sizes, we can extend this)
        if field_def.field_type == "uint32":
            size = 4
        elif field_def.field_type.startswith("string_"):
            size = int(field_def.field_type.split("_")[1])
        else:
            raise ObjectError(f"Unsupported type {field_def.field_type} in Phase 2D/2E-D fixture")
            
        res = self.address_space.read(self.address + field_def.offset, size)
        
        if res.is_complete:
            data = res.get_data_if_complete()
            if field_def.field_type == "uint32":
                val = struct.unpack("<I", data)[0]
            else:
                val = data.split(b'\x00')[0].decode('utf-8', errors='ignore')
            return FieldValue(field_name, val, ReadStatus.COMPLETE, gaps=[], segments=res.segments)
            
        elif len(res.segments) > 0:
            return FieldValue(field_name, None, ReadStatus.PARTIAL, gaps=res.gaps, segments=res.segments)
        else:
            return FieldValue(field_name, None, ReadStatus.UNAVAILABLE, gaps=res.gaps, segments=res.segments)

    def read_field(self, field_name: str) -> Any:
        """Backward compatible read_field. Returns primitive or raises exception."""
        field_val = self.read_field_explicit(field_name)
        if field_val.status == ReadStatus.COMPLETE:
            return field_val.value
            
        # Legacy error handling to satisfy Phase 2D raw layer tests
        if any(g.reason == FailureReason.PHYSICAL_OUT_OF_BOUNDS for g in field_val.gaps):
            raise OutOfBoundsError(f"Out of bounds reading field {field_name}")
            
        raise ObjectError(f"Field {field_name} is {field_val.status.name}")
            
    def get_provenance(self) -> Dict[str, Any]:
        """Returns explicitly deterministic provenance for this object."""
        prov = {
            "address": hex(self.address),
            "type": self.type_def.name,
            "symbol_identity": str(self.environment.symbol_identity),
            "address_space": self.address_space.identity,
            "object_status": self.get_object_status().name,
            "requested_size": self.type_def.size
        }
        if self.legacy_layer:
            prov["artifact"] = self.legacy_layer.artifact_identity
        else:
            prov["artifact"] = self.address_space.identity
            
        # Retrieve mapped segments and gaps for the whole object to establish clear provenance
        res = self.address_space.read(self.address, self.type_def.size)
        prov["mapped_segments"] = [(s.requested_offset, s.length) for s in res.segments]
        prov["unavailable_gaps"] = [(g.requested_offset, g.length, g.reason.name) for g in res.gaps]
        
        return prov
