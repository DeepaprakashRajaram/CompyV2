"""
WHAT: YARA DTOs for Compy V2.
WHY: Normalized transfer objects representing raw YARA scan matches.
OWNS: Data structures for YARA rule hits and match context.
DOES NOT OWN: Scanning logic, domain evidence nodes.
"""

from dataclasses import dataclass, field
from typing import Tuple, Dict, Any, Optional

@dataclass(frozen=True)
class YaraMatchDTO:
    """Normalized DTO representing a single YARA rule match."""
    rule_name: str
    namespace: str = "default"
    tags: Tuple[str, ...] = ()
    matched_strings: Tuple[Tuple[str, int, str], ...] = () # (identifier, offset, preview)
    target_type: str = "PROCESS_MEMORY" # PROCESS_MEMORY, INJECTED_REGION, COMMAND_LINE, BUFFER
    target_identifier: str = ""
    meta: Dict[str, Any] = field(default_factory=dict)
