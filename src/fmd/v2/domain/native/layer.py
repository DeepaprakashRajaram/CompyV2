"""
WHAT: Phase 2D Raw Memory Layer Abstraction
WHY: To provide bounded, deterministic access to memory artifacts without inventing features.
OWNS: Raw file access, bounds checking.
DOES NOT OWN: Translation, object instantiation.
"""

from typing import Protocol, Union
import os

class LayerError(Exception):
    """Base exception for layer operations."""
    pass

class OutOfBoundsError(LayerError):
    """Explicitly raised when a read falls outside mapped/available memory bounds."""
    pass

class IRawMemoryLayer(Protocol):
    """
    Contract for raw memory access.
    Must return exact bytes or raise an explicit error. No silent zero-filling.
    """
    @property
    def artifact_identity(self) -> str: ...
    
    @property
    def size(self) -> int: ...

    def read(self, offset: int, length: int) -> bytes: ...


class FileMemoryLayer(IRawMemoryLayer):
    """
    Minimal implementation for a physical file layer (Phase 2D Fixture).
    """
    def __init__(self, file_path: str):
        self._file_path = file_path
        self._size = os.path.getsize(file_path)
        self._fd = open(file_path, 'rb')

    @property
    def artifact_identity(self) -> str:
        return self._file_path
        
    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise OutOfBoundsError(f"Invalid offset/length: {offset}/{length}")
        
        if offset + length > self._size:
            raise OutOfBoundsError(f"Read at offset {offset} (length {length}) exceeds layer size {self._size}")
            
        self._fd.seek(offset)
        data = self._fd.read(length)
        
        if len(data) != length:
            raise OutOfBoundsError(f"Truncated read at offset {offset}. Expected {length}, got {len(data)}")
            
        return data

    def close(self):
        self._fd.close()

class BufferMemoryLayer(IRawMemoryLayer):
    """
    Minimal implementation for a buffer layer (Phase 2D Fixture).
    Used for tiny deterministic tests without external raw files.
    """
    def __init__(self, data: bytes, identity: str = "test_buffer"):
        self._data = data
        self._identity = identity
        self._size = len(data)

    @property
    def artifact_identity(self) -> str:
        return self._identity

    @property
    def size(self) -> int:
        return self._size

    def read(self, offset: int, length: int) -> bytes:
        if offset < 0 or length < 0:
            raise OutOfBoundsError(f"Invalid offset/length: {offset}/{length}")
        
        if offset + length > self._size:
            raise OutOfBoundsError(f"Read at offset {offset} (length {length}) exceeds layer size {self._size}")
            
        return self._data[offset:offset+length]

