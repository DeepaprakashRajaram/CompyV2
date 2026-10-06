"""
WHAT: Evidence Mapper.
WHY: Transforms raw telemetry from Collectors into immutable Evidence Nodes.
OWNS: Normalization logic.
DOES NOT OWN: Acquisition logic, Ledger storage.
"""

from typing import List, Any, Dict
import uuid
from datetime import datetime

from fmd.v2.domain.contracts import ILedgerWrite, ProviderId, EvidenceId, IProvenanceRecord
from fmd.v2.domain.evidence.nodes import ProcessNode, MemoryRegionNode

class EvidenceMapper:
    """
    Ingests raw data (e.g. from MockCollector or Volatility) and appends to Ledger.
    """
    def __init__(self, ledger: ILedgerWrite):
        self.ledger = ledger

    def ingest_process_list(self, raw_processes: List[Any], provenance: IProvenanceRecord) -> None:
        """
        Takes DTO outputs and creates ProcessNodes with deterministic UUIDv5 EvidenceIds.
        """
        NAMESPACE_URL = uuid.NAMESPACE_URL
        
        for p in raw_processes:
            # Check if it's a dict (for mock backwards compatibility) or a ProcessDTO
            if isinstance(p, dict):
                pid = p.get("pid")
                name = p.get("name", "Unknown")
                ppid = p.get("ppid")
                create_time = p.get("create_time")
                exit_time = p.get("exit_time")
            else:
                pid = p.pid
                name = p.image_file_name
                ppid = p.ppid
                create_time = getattr(p, "create_time", None)
                exit_time = getattr(p, "exit_time", None)
                
            # Evidence Identity (Canonical Facts): uuid5(NAMESPACE_URL, artifact_identity + stable_forensic_properties)
            stable_prop = f"{provenance.artifact_identity}-PID-{pid}"
            eid = uuid.uuid5(NAMESPACE_URL, stable_prop)
            
            node = ProcessNode(
                _id=EvidenceId(str(eid)),
                pid=pid,
                name=name,
                ppid=ppid,
                create_time=create_time,
                exit_time=exit_time
            )
            self.ledger.append_node(node, provenance)

    def ingest_memory_regions(self, raw_regions: List[Dict[str, Any]], provenance: IProvenanceRecord) -> None:
        """
        Takes raw dictionary outputs and creates MemoryRegionNodes, linking them to processes.
        """
        NAMESPACE_URL = uuid.NAMESPACE_URL
        
        for r in raw_regions:
            pid = r.get("pid")
            start = r.get("start")
            
            stable_prop_region = f"{provenance.artifact_identity}-REGION-{pid}-{start}"
            node_id = EvidenceId(str(uuid.uuid5(NAMESPACE_URL, stable_prop_region)))
            
            node = MemoryRegionNode(
                _id=node_id,
                start_address=start,
                end_address=r.get("end"),
                protection=r.get("protection", "UNKNOWN"),
                mapped_path=r.get("path")
            )
            self.ledger.append_node(node, provenance)
            
            # Record FACTUAL structural relationship
            stable_prop_proc = f"{provenance.artifact_identity}-PID-{pid}"
            proc_id = EvidenceId(str(uuid.uuid5(NAMESPACE_URL, stable_prop_proc)))
            
            self.ledger.append_relationship(
                source=proc_id,
                target=node_id,
                relation_type="CONTAINS",
                provenance=provenance
            )
