import sys
import os
import logging
from datetime import datetime, timezone

# Add the src folder to Python path
sys.path.append(os.path.abspath('src'))

from fmd.v2.application.use_cases import AnalyzeMemoryRequest, AnalyzeMemoryUseCase
from fmd.v2.application.coordinator import SessionCoordinator
from fmd.v2.adapters.providers.volatility.collector import VolatilityCollector
from fmd.v2.adapters.providers.mock_detector import MockStructuralDetector
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.reasoning.corroboration import DeterministicCorroborator
from fmd.v2.domain.reasoning.verification import StrictVerifier
from fmd.v2.domain.governance.gate import CLIGovernanceGate
from fmd.v2.domain.contracts import CapabilityStatus

logging.basicConfig(level=logging.INFO)

def run_analysis(image_path, expected_hash):
    def coordinator_factory() -> SessionCoordinator:
        ledger = EvidenceLedger()
        collector = VolatilityCollector(memory_image_path=image_path, artifact_hash=expected_hash)
        detectors = [MockStructuralDetector()]
        return SessionCoordinator(
            collector=collector,
            detectors=detectors,
            ledger=ledger,
            ledger_query=ledger,
            graph_query=ledger,
            corroborator=DeterministicCorroborator(),
            verifier=StrictVerifier(),
            governance=CLIGovernanceGate()
        )

    use_case = AnalyzeMemoryUseCase(coordinator_factory=coordinator_factory)
    req = AnalyzeMemoryRequest(
        target_path=image_path,
        session_timestamp=datetime.now(timezone.utc)
    )
    
    print(f"--- Running Volatility on {image_path} ---")
    try:
        dossier = use_case.execute(req)
        
        print(f"Investigation ID: {dossier.investigation_id}")
        print(f"System Status: {dossier.system_status.value}")
        print(f"Capability Failures: {len(dossier.capability_failures)}")
        for failure in dossier.capability_failures:
            print(f"  - {failure.status}: {failure.failure_reason}")
            
        print("Capabilities available in dossier:")
        for cap in dossier.available_capabilities:
            print(f"  - {cap}")
            
        coordinator = use_case.coordinator_factory()
        # To get node count, we need the ledger from the *executed* run, but coordinator_factory makes a new one.
        # Let's run it directly.
    except Exception as e:
        print(f"Exception: {e}")

if __name__ == "__main__":
    run_analysis(r"C:\Users\Deepak\Projects\FilelessMalwareDetector\base.raw", "68a5b3c3baf146958fdbb11f7f38942e0eecb5484cba8d9222a6e72f551f7fec")
    run_analysis(r"C:\Users\Deepak\Projects\FilelessMalwareDetector\WannaCry1.raw", "775c858e4c7349e9b6ad706aaea449545d81bcd9f92c6a67790489eb2533219c")
