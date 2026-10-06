"""
WHAT: Compy V2 CLI Entrypoint.
WHY: First-class interface to the core domain.
OWNS: Command line parsing, printing to stdout.
DOES NOT OWN: Forensic logic.
"""

import sys
from datetime import datetime, timezone

from fmd.v2.application.use_cases import AnalyzeMemoryUseCase, AnalyzeMemoryRequest
from fmd.v2.application.coordinator import SessionCoordinator
from fmd.v2.adapters.providers.mock_collector import MockCollector
from fmd.v2.adapters.providers.mock_detector import MockStructuralDetector
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.reasoning.corroboration import DeterministicCorroborator
from fmd.v2.domain.reasoning.verification import StrictVerifier
from fmd.v2.domain.governance.gate import CLIGovernanceGate

def build_v2_app() -> AnalyzeMemoryUseCase:
    """Dependency Injection root for Phase 1."""
    
    def coordinator_factory() -> SessionCoordinator:
        # 1. State
        ledger = EvidenceLedger()
        
        # 2. Providers
        collector = MockCollector()
        detectors = [MockStructuralDetector()]
        
        # 3. Domain Logic
        corroborator = DeterministicCorroborator()
        verifier = StrictVerifier()
        governance = CLIGovernanceGate()
        
        # 4. Coordinator
        return SessionCoordinator(
            collector=collector,
            detectors=detectors,
            ledger=ledger,
            ledger_query=ledger,
            graph_query=ledger,
            corroborator=corroborator,
            verifier=verifier,
            governance=governance
        )
    
    # 5. Use Case
    return AnalyzeMemoryUseCase(coordinator_factory=coordinator_factory)

def main():
    print("=========================================")
    print(" COMPSOGNATHUS (COMPY) FORENSIC ENGINE   ")
    print(" V2.0 - Phase 1 Integration              ")
    print("=========================================")
    
    use_case = build_v2_app()
    req = AnalyzeMemoryRequest(
        target_path="mock://memory.raw",
        session_timestamp=datetime.now(timezone.utc)
    )
    
    dossier = use_case.execute(req)
    
    print(f"\n[+] Analysis Complete.")
    print(f"[+] Investigation ID: {dossier.investigation_id}")
    print(f"[+] System Status: {dossier.system_status.value}")
    print("\nArchitecture rules enforced:")
    print("- Immutable Evidence Ledger")
    print("- Hexagonal Ports & Adapters")
    print("- No God Objects")
    print("- Tri-State Logic ready")

if __name__ == "__main__":
    main()
