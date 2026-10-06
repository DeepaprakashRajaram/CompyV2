"""
WHAT: Evidence Ledger.
WHY: Authoritative source of immutable forensic facts.
OWNS: Evidence storage, retrieval, and identity.
DOES NOT OWN: Detection algorithms, YARA execution, UI logic.
INVARIANTS: 
- Must remain passive.
- Nodes and Relationships are strictly append-only.
- Cannot mutate existing evidence.
"""

from typing import Dict, List, Optional, Tuple
from fmd.v2.domain.contracts import ILedgerWrite, ILedgerQuery, IGraphQuery
from fmd.v2.domain.contracts import IEvidenceNode, IProvenanceRecord, EvidenceId

class EvidenceLedger(ILedgerWrite, ILedgerQuery, IGraphQuery):
    """
    In-memory immutable ledger for Phase 1.
    Satisfies both the Ledger and GraphQuery ports.
    """
    
    def __init__(self):
        # Maps EvidenceId -> Node
        self._nodes: Dict[EvidenceId, IEvidenceNode] = {}
        # Maps EvidenceId -> Provenance
        self._node_provenance: Dict[EvidenceId, IProvenanceRecord] = {}
        
        # Edges for graph projection: (SourceId, TargetId, RelationType)
        self._edges: List[Tuple[EvidenceId, EvidenceId, str]] = []
        # Provenance for edges
        self._edge_provenance: Dict[Tuple[EvidenceId, EvidenceId, str], IProvenanceRecord] = {}

    # --- ILedgerWrite Implementation ---
    
    def append_node(self, node: IEvidenceNode, provenance: IProvenanceRecord) -> None:
        if node.id in self._nodes:
            raise ValueError(f"Evidence ID {node.id} already exists in ledger. Evidence must be immutable.")
        self._nodes[node.id] = node
        self._node_provenance[node.id] = provenance

    def append_relationship(self, source: EvidenceId, target: EvidenceId, relation_type: str, provenance: IProvenanceRecord) -> None:
        if source not in self._nodes or target not in self._nodes:
            raise ValueError(f"Cannot create relationship {relation_type} between {source} and {target}: node missing.")
        
        edge = (source, target, relation_type)
        if edge in self._edge_provenance:
            # Fact already established
            return
            
        self._edges.append(edge)
        self._edge_provenance[edge] = provenance

    # --- ILedgerQuery Implementation ---
    
    def get_node(self, evidence_id: EvidenceId) -> Optional[IEvidenceNode]:
        return self._nodes.get(evidence_id)

    def get_all_nodes(self) -> List[IEvidenceNode]:
        return list(self._nodes.values())

    # --- IGraphQuery Implementation ---
    
    def get_children(self, parent_id: EvidenceId, relation_type: str) -> List[IEvidenceNode]:
        children = []
        for src, tgt, rel in self._edges:
            if src == parent_id and rel == relation_type:
                children.append(self._nodes[tgt])
        return children

    def get_parent(self, child_id: EvidenceId, relation_type: str) -> Optional[IEvidenceNode]:
        for src, tgt, rel in self._edges:
            if tgt == child_id and rel == relation_type:
                return self._nodes[src]
        return None
