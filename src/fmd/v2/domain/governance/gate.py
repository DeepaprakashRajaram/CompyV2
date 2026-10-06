"""
WHAT: Governance Port.
WHY: Policy / Human-in-the-loop gate before any response is executed.
OWNS: Authorization checks.
DOES NOT OWN: Initial detection, UI prompts.
"""

from fmd.v2.domain.contracts import IGovernanceGate, IVerifiedConclusion, TriState

class CLIGovernanceGate(IGovernanceGate):
    """
    Adapter implementation of Governance Gate.
    For Phase 1, automatically approves justified conclusions 
    (to avoid blocking the test pipeline), but in a real CLI 
    this would block and prompt the user.
    """
    def request_approval(self, conclusion: IVerifiedConclusion) -> bool:
        if conclusion.status == TriState.TRUE:
            # In V2 Phase 5, this will pause and ask the user.
            return True
        return False
