"""
WHAT: Application Use Cases.
WHY: Shared boundary for CLI and Application UI.
OWNS: Routing user intent to domain logic.
DOES NOT OWN: Forensic logic, UI rendering.
"""

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable

from fmd.v2.application.coordinator import SessionCoordinator
from fmd.v2.domain.reasoning.investigation import InvestigationDossier

@dataclass
class AnalyzeMemoryRequest:
    target_path: str
    session_timestamp: datetime
    run_structural: bool = True
    run_yara: bool = False

class AnalyzeMemoryUseCase:
    """
    Both the CLI and Application UI will instantiate this to begin an analysis.
    """
    def __init__(self, coordinator_factory: Callable[[], SessionCoordinator]):
        self.coordinator_factory = coordinator_factory
        
    def execute(self, request: AnalyzeMemoryRequest) -> InvestigationDossier:
        """
        Returns the resulting Investigation Dossier.
        (Updated to return Dossier instead of just ID so CLI can inspect status)
        """
        # Run isolation: We instantiate a brand new SessionCoordinator (and Ledger) per execute.
        coordinator = self.coordinator_factory()
        
        dossier = coordinator.run_analysis(request.target_path, request.session_timestamp)
        return dossier
