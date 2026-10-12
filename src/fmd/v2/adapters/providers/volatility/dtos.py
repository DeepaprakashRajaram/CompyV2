from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass(frozen=True)
class ProcessDTO:
    pid: int
    ppid: int
    image_file_name: str
    offset: int
    create_time: Optional[datetime] = None
    exit_time: Optional[datetime] = None
    threads: int = 0
    handles: int = 0
    source_view: str = "PSLIST"
    is_hidden: bool = False
    cmdline: Optional[str] = None

@dataclass(frozen=True)
class InjectedCodeDTO:
    pid: int
    process_name: str
    start_vpn: int
    end_vpn: int
    tag: str = ""
    protection: str = ""
    commit_charge: int = 0
    hexdump_preview: str = ""
    disasm_preview: str = ""
