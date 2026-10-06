# Forensic Engine

Compy's forensic engine operates entirely offline and mathematically models malware behavior.

## Evidence Model
Evidence is represented as nodes in an `EvidenceLedger`.
- **ProcessNode:** Represents a running process (PID, PPID, Image).
- **MemoryRegionNode:** Represents a mapped block of memory.

Nodes are connected via edges (e.g., `ALLOCATED_BY`, `SPAWNED`).

## Tri-State Logic
Forensic answers are never just `True` or `False`. 
Because memory dumps may be corrupt, paged out, or lacking symbols, Compy uses Tri-State logic:
- `SUCCESS`: Evidence was found or definitively ruled out.
- `FAILED`: An internal crash occurred.
- `UNAVAILABLE`: The necessary data (e.g., symbols, specific OS structures) could not be read.

## Volatility 3 Safety Boundary
All memory analysis runs through the Volatility 3 Provider.
This provider is explicitly sandboxed to prevent network requests (`constants.OFFLINE = True`).
No execution of recovered memory or dynamic downloads are permitted.
