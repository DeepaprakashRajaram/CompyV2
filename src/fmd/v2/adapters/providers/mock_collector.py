"""
WHAT: Mock Collector Provider.
WHY: Proves the ICollector Port contract works without dependency on Volatility.
OWNS: Hardcoded raw test data generation.
DOES NOT OWN: Malware detection, Normalization.
"""

from typing import List, Dict, Any, Tuple
from datetime import datetime
from fmd.v2.domain.contracts import (
    ICollector, 
    ProviderId, 
    ProviderResult, 
    CapabilityStatus, 
    ProviderCapability,
    IProviderResult
)
from fmd.v2.domain.evidence.provenance import ProvenanceRecord

class MockCollector(ICollector):
    
    def provider_id(self) -> ProviderId:
        return ProviderId("mock_collector_v1")
        
    def extract_evidence(self) -> IProviderResult:
        processes = [
            {"pid": 4, "name": "System", "ppid": 0},
            {"pid": 1000, "name": "explorer.exe", "ppid": 4},
            {"pid": 2000, "name": "malicious.exe", "ppid": 1000}
        ]
        
        regions = [
            {"pid": 1000, "start": 0x10000, "end": 0x20000, "protection": "PAGE_EXECUTE_READ", "path": "C:\\Windows\\explorer.exe"},
            {"pid": 2000, "start": 0x10000, "end": 0x20000, "protection": "PAGE_EXECUTE_READWRITE", "path": None} # Suspicious
        ]
        
        dtos = (processes, regions)
        
        prov = ProvenanceRecord(
            _provider_id=self.provider_id(),
            _artifact_identity="mock_artifact_hash",
            _acquisition_mode="OFFLINE",
            acquisition_time=datetime.now()
        )
        
        return ProviderResult(
            _capability_status=CapabilityStatus.SUCCESS,
            _available_capabilities=frozenset([ProviderCapability.PROCESS_LIST, ProviderCapability.VAD_INFO]),
            _extracted_dtos=dtos,
            _capability_failures=tuple(),
            _provenance=prov
        )
