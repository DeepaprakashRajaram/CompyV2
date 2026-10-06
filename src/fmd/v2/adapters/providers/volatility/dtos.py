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
