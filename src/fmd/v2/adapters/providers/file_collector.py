"""
WHAT: Static File Artifact Collector for Executables and Scripts.
WHY: Allows analyzing static binaries (.exe, .dll, .sys) and scripts (.ps1, .bat)
     via YARA scanning and static properties without invoking memory-only Volatility 3 plugins.
OWNS: File hashing, magic signature extraction, PE/script properties, YARA invocation.
DOES NOT OWN: Volatility 3 plugins or kernel memory extraction.
"""

import os
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from fmd.v2.domain.contracts import (
    ICollector,
    ProviderId,
    ProviderResult,
    CapabilityStatus,
    ProviderCapability,
    IProviderResult,
)
from fmd.v2.domain.evidence.provenance import ProvenanceRecord
from fmd.v2.adapters.providers.volatility.dtos import CapabilityFailureDTO
from fmd.v2.adapters.providers.yara.scanner import YaraScannerProvider
from fmd.v2.adapters.providers.yara.dtos import YaraMatchDTO

class FileArtifactCollector(ICollector):
    """
    Forensic collector for static file artifacts (Executables, DLLs, Scripts).
    Performs static property extraction and YARA signature scanning.
    Explicity marks memory-only capabilities (process tree, DKOM rootkit, VAD injection)
    as UNAVAILABLE to prevent misleading claims of whole-memory scanning.
    """

    def __init__(self, file_path: str, artifact_hash: str, yara_rules_dir: Optional[str] = None):
        self.file_path = str(file_path)
        self.artifact_hash = artifact_hash
        self.yara_rules_dir = yara_rules_dir or "rules/yara"
        self._provider_id = ProviderId("file_artifact_collector_v1")

    def provider_id(self) -> ProviderId:
        return self._provider_id

    def extract_evidence(self) -> IProviderResult:
        p = Path(self.file_path)
        file_bytes = b""
        if p.exists():
            try:
                with open(self.file_path, "rb") as f:
                    file_bytes = f.read()
            except Exception:
                file_bytes = b""

        file_size = len(file_bytes)
        sha256 = hashlib.sha256(file_bytes).hexdigest() if file_bytes else self.artifact_hash
        md5 = hashlib.md5(file_bytes).hexdigest() if file_bytes else ""
        sha1 = hashlib.sha1(file_bytes).hexdigest() if file_bytes else ""

        # Inspect headers
        is_pe = file_bytes.startswith(b"MZ")
        artifact_type = "EXECUTABLE_PE" if is_pe else ("SCRIPT" if p.suffix.lower() in {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py"} else "FILE")

        # Run YARA scanner against file bytes
        yara_scanner = YaraScannerProvider(rules_dir=self.yara_rules_dir)
        yara_matches: List[YaraMatchDTO] = []
        if yara_scanner.status == CapabilityStatus.SUCCESS:
            matches = yara_scanner.scan_buffer(
                buffer=file_bytes,
                target_identifier=p.name,
                target_type="STATIC_FILE"
            )
            yara_matches.extend(matches)

        # Build simulated single process record representing the executable target
        processes = [
            {
                "pid": 1,
                "name": p.name,
                "ppid": 0,
                "path": str(self.file_path),
                "threads": 1,
                "handles": 0,
                "session": 1,
                "wow64": False,
                "create_time": datetime.now(timezone.utc).isoformat(),
                "exit_time": None
            }
        ]

        # Explicitly declare capability failures for memory-specific checks
        cap_failures = (
            CapabilityFailureDTO(
                provider_id=ProviderId("process_tree_anomaly_v1"),
                status=CapabilityStatus.UNAVAILABLE,
                failure_reason="Process tree hierarchy analysis is not applicable to static file artifacts."
            ),
            CapabilityFailureDTO(
                provider_id=ProviderId("hidden_process_rootkit_v1"),
                status=CapabilityStatus.UNAVAILABLE,
                failure_reason="DKOM kernel rootkit scanning is not applicable to static file artifacts."
            ),
            CapabilityFailureDTO(
                provider_id=ProviderId("injected_code_v1"),
                status=CapabilityStatus.UNAVAILABLE,
                failure_reason="VAD memory injection scanning is not applicable to static file artifacts."
            ),
        )

        dtos = (processes, [], yara_matches)

        prov = ProvenanceRecord(
            _provider_id=self.provider_id(),
            _artifact_identity=sha256,
            _acquisition_mode="STATIC_FILE_INGESTION",
            acquisition_time=datetime.now(timezone.utc)
        )

        return ProviderResult(
            _capability_status=CapabilityStatus.SUCCESS,
            _available_capabilities=frozenset([ProviderCapability.FILE_METADATA, ProviderCapability.YARA_SCAN]),
            _extracted_dtos=dtos,
            _capability_failures=cap_failures,
            _provenance=prov
        )
