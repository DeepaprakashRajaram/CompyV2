"""
WHAT: Evidence Mapper.
WHY: Transforms raw telemetry from Collectors into immutable Evidence Nodes.
OWNS: Normalization logic.
DOES NOT OWN: Acquisition logic, Ledger storage.
"""

from typing import List, Any, Dict, Optional, Set
import re
import uuid
from datetime import datetime

from fmd.v2.domain.contracts import ILedgerWrite, ProviderId, EvidenceId, IProvenanceRecord, ProviderCapability
from fmd.v2.domain.evidence.nodes import ProcessNode, MemoryRegionNode, ScanMetadataNode, InjectedCodeNode, YaraMatchNode

class EvidenceMapper:
    """
    Ingests raw data (e.g. from MockCollector or Volatility) and appends to Ledger.
    """
    def __init__(self, ledger: ILedgerWrite):
        self.ledger = ledger

    def record_scan_metadata(self, scan_name: str, status: str, item_count: int, provenance: IProvenanceRecord) -> None:
        """Appends scan execution metadata to the ledger."""
        eid = EvidenceId(str(uuid.uuid5(uuid.NAMESPACE_URL, f"{provenance.artifact_identity}-SCAN-{scan_name}")))
        if hasattr(self.ledger, "get_node") and self.ledger.get_node(eid) is not None:
            return
        node = ScanMetadataNode(
            _id=eid,
            scan_name=scan_name,
            status=status,
            item_count=item_count
        )
        self.ledger.append_node(node, provenance)

    def ingest_process_list(
        self, 
        raw_processes: List[Any], 
        provenance: IProvenanceRecord,
        available_capabilities: Optional[Set[Any]] = None
    ) -> None:
        """
        Takes DTO outputs and creates ProcessNodes with deterministic UUIDv5 EvidenceIds.
        """
        NAMESPACE_URL = uuid.NAMESPACE_URL
        pslist_count = 0
        psscan_count = 0
        
        for p in raw_processes:
            # Check if it's a dict (for mock backwards compatibility) or a ProcessDTO
            if isinstance(p, dict):
                pid = p.get("pid")
                name = p.get("name", "Unknown")
                ppid = p.get("ppid")
                create_time = p.get("create_time")
                exit_time = p.get("exit_time")
                is_hidden = p.get("is_hidden", False)
                source_view = p.get("source_view", "PSLIST")
                offset = p.get("offset")
                threads = p.get("threads", 0)
                handles = p.get("handles", 0)
                cmdline = p.get("cmdline")
            else:
                pid = p.pid
                name = p.image_file_name
                ppid = p.ppid
                create_time = getattr(p, "create_time", None)
                exit_time = getattr(p, "exit_time", None)
                is_hidden = getattr(p, "is_hidden", False)
                source_view = getattr(p, "source_view", "PSLIST")
                offset = getattr(p, "offset", None)
                threads = getattr(p, "threads", 0)
                handles = getattr(p, "handles", 0)
                cmdline = getattr(p, "cmdline", None)
                
            # Evidence Identity (Canonical Facts):
            # Preserves source_view and offsets to distinguish independent views (PSLIST vs PSSCAN)
            # and to handle PID reuse.
            create_str = f"-{create_time.isoformat()}" if isinstance(create_time, datetime) else (f"-{create_time}" if create_time else "")
            off_str = f"-OFF-{offset}" if offset is not None else ""
            view_str = f"-{source_view}" if source_view else ""
            stable_prop = f"{provenance.artifact_identity}{view_str}-PID-{pid}{off_str}{create_str}"
            eid = EvidenceId(str(uuid.uuid5(NAMESPACE_URL, stable_prop)))
            
            # Deduplication: do not append identical duplicate observations from the exact same origin
            if hasattr(self.ledger, "get_node") and self.ledger.get_node(eid) is not None:
                continue

            node = ProcessNode(
                _id=eid,
                pid=pid,
                name=name,
                ppid=ppid,
                create_time=create_time,
                exit_time=exit_time,
                is_hidden=is_hidden,
                source_view=source_view,
                offset=offset,
                threads=threads,
                handles=handles,
                cmdline=cmdline
            )
            if getattr(node, "source_view", "") == "PSSCAN":
                psscan_count += 1
            else:
                pslist_count += 1
            self.ledger.append_node(node, provenance)

        # Record scan metadata
        if pslist_count > 0 or (available_capabilities and ProviderCapability.PROCESS_LIST in available_capabilities):
            self.record_scan_metadata("PSLIST", "COMPLETED", pslist_count, provenance)
        if psscan_count > 0 or (available_capabilities and ProviderCapability.PROCESS_SCAN in available_capabilities):
            self.record_scan_metadata("PSSCAN", "COMPLETED", psscan_count, provenance)

    def ingest_injected_code(
        self,
        raw_injections: List[Any],
        provenance: IProvenanceRecord,
        available_capabilities: Optional[Set[Any]] = None
    ) -> None:
        """
        Takes InjectedCodeDTO outputs and creates InjectedCodeNodes linked to the owning ProcessNode.
        """
        NAMESPACE_URL = uuid.NAMESPACE_URL
        injection_count = 0

        for inj in raw_injections:
            if isinstance(inj, dict):
                pid = inj.get("pid", 0)
                process_name = inj.get("process_name", "")
                start_addr = inj.get("start_vpn", 0)
                end_addr = inj.get("end_vpn", 0)
                tag = inj.get("tag", "")
                protection = inj.get("protection", "")
                hexdump = inj.get("hexdump_preview", "")
                disasm = inj.get("disasm_preview", "")
            else:
                pid = inj.pid
                process_name = inj.process_name
                start_addr = inj.start_vpn
                end_addr = inj.end_vpn
                tag = getattr(inj, "tag", "")
                protection = getattr(inj, "protection", "")
                hexdump = getattr(inj, "hexdump_preview", "")
                disasm = getattr(inj, "disasm_preview", "")

            stable_prop = f"{provenance.artifact_identity}-INJ-PID-{pid}-{start_addr:#x}"
            node_id = EvidenceId(str(uuid.uuid5(NAMESPACE_URL, stable_prop)))

            if hasattr(self.ledger, "get_node") and self.ledger.get_node(node_id) is not None:
                continue

            node = InjectedCodeNode(
                _id=node_id,
                pid=pid,
                process_name=process_name,
                start_address=start_addr,
                end_address=end_addr,
                protection=protection,
                tag=tag,
                hexdump_preview=hexdump,
                disasm_preview=disasm
            )
            self.ledger.append_node(node, provenance)
            injection_count += 1

            # Link to ProcessNode if available
            proc_id = None
            if hasattr(self.ledger, "get_all_nodes"):
                proc_nodes = [
                    n for n in self.ledger.get_all_nodes()
                    if getattr(n, "node_type", None) == "Process" and getattr(n, "pid", None) == pid
                ]
                if proc_nodes:
                    proc_id = proc_nodes[0].id

            if proc_id:
                try:
                    self.ledger.append_relationship(
                        source=proc_id,
                        target=node_id,
                        relation_type="CONTAINS",
                        provenance=provenance
                    )
                    self.ledger.append_relationship(
                        source=proc_id,
                        target=node_id,
                        relation_type="CONTAINS_INJECTION",
                        provenance=provenance
                    )
                except Exception:
                    pass

        if injection_count > 0 or (available_capabilities and ProviderCapability.INJECTED_CODE in available_capabilities):
            self.record_scan_metadata("MALFIND", "COMPLETED", injection_count, provenance)

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
            proc_id = None
            if hasattr(self.ledger, "get_all_nodes"):
                proc_nodes = [
                    n for n in self.ledger.get_all_nodes() 
                    if getattr(n, "node_type", None) == "Process" and getattr(n, "pid", None) == pid
                ]
                if proc_nodes:
                    pslist_nodes = [n for n in proc_nodes if getattr(n, "source_view", "PSLIST") == "PSLIST"]
                    proc_id = (pslist_nodes[0] if pslist_nodes else proc_nodes[0]).id
            
            if not proc_id:
                stable_prop_proc = f"{provenance.artifact_identity}-PID-{pid}"
                proc_id = EvidenceId(str(uuid.uuid5(NAMESPACE_URL, stable_prop_proc)))
            
            self.ledger.append_relationship(
                source=proc_id,
                target=node_id,
                relation_type="CONTAINS",
                provenance=provenance
            )

    def ingest_yara_matches(
        self,
        raw_matches: List[Any],
        provenance: IProvenanceRecord,
        available_capabilities: Optional[Set[Any]] = None
    ) -> None:
        """
        Takes YaraMatchDTO or dict outputs and creates immutable YaraMatchNodes.
        """
        NAMESPACE_URL = uuid.NAMESPACE_URL
        match_count = 0

        for m in raw_matches:
            if isinstance(m, dict):
                rule_name = m.get("rule_name", "UnknownRule")
                namespace = m.get("namespace", "default")
                tags = tuple(m.get("tags", ()))
                matched_strings = tuple(tuple(s) for s in m.get("matched_strings", ()))
                target_type = m.get("target_type", "PROCESS_MEMORY")
                target_identifier = m.get("target_identifier", "")
                meta = m.get("meta", {})
            else:
                rule_name = getattr(m, "rule_name", "UnknownRule")
                namespace = getattr(m, "namespace", "default")
                tags = tuple(getattr(m, "tags", ()))
                matched_strings = tuple(tuple(s) for s in getattr(m, "matched_strings", ()))
                target_type = getattr(m, "target_type", "PROCESS_MEMORY")
                target_identifier = getattr(m, "target_identifier", "")
                meta = getattr(m, "meta", {})

            stable_prop = f"{provenance.artifact_identity}-YARA-{namespace}-{rule_name}-{target_identifier}"
            node_id = EvidenceId(str(uuid.uuid5(NAMESPACE_URL, stable_prop)))

            if hasattr(self.ledger, "get_node") and self.ledger.get_node(node_id) is not None:
                continue

            node = YaraMatchNode(
                _id=node_id,
                rule_name=rule_name,
                namespace=namespace,
                tags=tags,
                matched_strings=matched_strings,
                target_type=target_type,
                target_identifier=target_identifier,
                meta=meta
            )
            match_count += 1
            self.ledger.append_node(node, provenance)

            # Link YaraMatchNode to ProcessNode if target specifies a PID
            pid_match = re.search(r'\bPID\s+(\d+)\b', target_identifier)
            if pid_match and hasattr(self.ledger, "get_all_nodes"):
                try:
                    target_pid = int(pid_match.group(1))
                    proc_nodes = [
                        n for n in self.ledger.get_all_nodes()
                        if getattr(n, "node_type", None) == "Process" and getattr(n, "pid", None) == target_pid
                    ]
                    if proc_nodes:
                        self.ledger.append_relationship(
                            source=proc_nodes[0].id,
                            target=node_id,
                            relation_type="CONTAINS",
                            provenance=provenance
                        )
                except Exception:
                    pass

        if match_count > 0 or (available_capabilities and ProviderCapability.YARA_SCAN in available_capabilities):
            self.record_scan_metadata("YARA_SCAN", "COMPLETED", match_count, provenance)
