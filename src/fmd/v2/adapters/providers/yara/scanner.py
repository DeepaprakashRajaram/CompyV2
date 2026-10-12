"""
WHAT: YARA Scanner Provider for Compy V2.
WHY: Orchestrates YARA scanning across acquired forensic artifacts and buffers.
OWNS: Invocation of YaraEngine against process cmdlines, injected VAD regions, and buffers.
DOES NOT OWN: Volatility plugin logic, ledger persistence.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple
import binascii

from fmd.v2.domain.contracts import CapabilityStatus, ProviderCapability
from fmd.v2.adapters.providers.yara.dtos import YaraMatchDTO
from fmd.v2.adapters.providers.yara.engine import YaraEngine, YaraCompilationError, YaraRuntimeUnavailableError

class YaraScannerProvider:
    """
    Forensic provider for YARA signature scanning.
    Scans process memory artifacts, injected VAD allocations, and command line strings.
    """

    def __init__(self, rules_dir: Optional[str] = None, enabled: bool = True):
        self.rules_dir = rules_dir or "rules/yara"
        self.enabled = enabled
        self._engine: Optional[YaraEngine] = None
        self._status: CapabilityStatus = CapabilityStatus.UNAVAILABLE
        self._failure_reason: Optional[str] = None
        self.backend: str = "NONE"
        self.rules_count: int = 0

        self.scanned_targets_count: int = 0
        self.scanned_bytes_count: int = 0
        self.applicable_limitations: str = (
            "Targeted scanning of extracted process command lines, image identities, and "
            "unbacked memory allocation buffers; whole-RAM physical memory scanning was not performed."
        )

        if self.enabled:
            self._initialize()

    def _initialize(self) -> None:
        try:
            self._engine = YaraEngine(rules_dir=self.rules_dir)
            self._status = CapabilityStatus.SUCCESS
            self.backend = self._engine.backend
            self.rules_count = self._engine.loaded_rules_count
        except YaraCompilationError as e:
            self._status = CapabilityStatus.FAILED
            self._failure_reason = f"YARA compilation failed: {e}"
        except Exception as e:
            self._status = CapabilityStatus.FAILED
            self._failure_reason = f"YARA initialization failed: {e}"

    @property
    def status(self) -> CapabilityStatus:
        return self._status

    @property
    def failure_reason(self) -> Optional[str]:
        return self._failure_reason

    def _enrich_matches(self, matches: List[YaraMatchDTO], byte_count: int, target_type: str, target_id: str) -> List[YaraMatchDTO]:
        enriched = []
        for m in matches:
            meta = dict(m.meta or {})
            meta["scanned_bytes"] = byte_count
            meta["scan_scope"] = "EXTRACTED_ARTIFACT_BUFFER"
            meta["limitations"] = self.applicable_limitations
            enriched.append(YaraMatchDTO(
                rule_name=m.rule_name,
                namespace=m.namespace,
                tags=m.tags,
                matched_strings=m.matched_strings,
                target_type=target_type,
                target_identifier=target_id,
                meta=meta
            ))
        return enriched

    def scan_raw_buffer(
        self,
        data: bytes,
        target_type: str = "BUFFER",
        target_identifier: str = ""
    ) -> List[YaraMatchDTO]:
        """Scans arbitrary byte buffer."""
        if not self.enabled or self._status != CapabilityStatus.SUCCESS or self._engine is None:
            return []
        self.scanned_targets_count += 1
        self.scanned_bytes_count += len(data)
        matches = self._engine.scan_data(data, target_type=target_type, target_identifier=target_identifier)
        return self._enrich_matches(matches, len(data), target_type, target_identifier)

    def scan_injected_artifact(
        self,
        pid: int,
        process_name: str,
        start_addr: int,
        hexdump_preview: str,
        disasm_preview: str = ""
    ) -> List[YaraMatchDTO]:
        """
        Scans an injected code region / VAD dump extracted by Volatility malfind.
        Converts hex previews into raw bytes for binary signature matching.
        """
        if not self.enabled or self._status != CapabilityStatus.SUCCESS or self._engine is None:
            return []

        target_id = f"PID {pid} ({process_name}) @ 0x{start_addr:x}"
        buffer = bytearray()

        # Parse hexdump preview if present
        if hexdump_preview:
            cleaned = hexdump_preview.replace("\n", " ").replace("\r", " ")
            tokens = cleaned.split()
            for tok in tokens:
                if len(tok) == 2:
                    try:
                        buffer.append(int(tok, 16))
                    except ValueError:
                        pass
        
        # If hexdump wasn't hex-formatted or was short, also scan ascii/utf-8 representation
        if not buffer and disasm_preview:
            buffer.extend(disasm_preview.encode("utf-8", errors="replace"))

        if not buffer:
            return []

        data_bytes = bytes(buffer)
        self.scanned_targets_count += 1
        self.scanned_bytes_count += len(data_bytes)
        matches = self._engine.scan_data(
            data_bytes,
            target_type="INJECTED_REGION",
            target_identifier=target_id
        )
        return self._enrich_matches(matches, len(data_bytes), "INJECTED_REGION", target_id)

    def scan_cmdline(self, pid: int, process_name: str, cmdline: str) -> List[YaraMatchDTO]:
        """
        Scans a process command line string for encoded cradles and evasion patterns.
        """
        if not self.enabled or self._status != CapabilityStatus.SUCCESS or self._engine is None or not cmdline:
            return []

        target_id = f"PID {pid} ({process_name}) [CMDLINE]"
        data = cmdline.encode("utf-8", errors="replace")
        self.scanned_targets_count += 1
        self.scanned_bytes_count += len(data)
        matches = self._engine.scan_data(
            data,
            target_type="COMMAND_LINE",
            target_identifier=target_id
        )
        return self._enrich_matches(matches, len(data), "COMMAND_LINE", target_id)

    def scan_process_identity(self, pid: int, process_name: str, image_path: Optional[str] = None) -> List[YaraMatchDTO]:
        """
        Scans process name and image path string for targeted malware signatures.
        """
        if not self.enabled or self._status != CapabilityStatus.SUCCESS or self._engine is None:
            return []

        combined = f"{process_name} {image_path or ''}".strip()
        if not combined:
            return []

        target_id = f"PID {pid} ({process_name}) [IMAGE]"
        data = combined.encode("utf-8", errors="replace")
        self.scanned_targets_count += 1
        self.scanned_bytes_count += len(data)
        matches = self._engine.scan_data(
            data,
            target_type="PROCESS_IMAGE",
            target_identifier=target_id
        )
        return self._enrich_matches(matches, len(data), "PROCESS_IMAGE", target_id)
