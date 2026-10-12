"""
WHAT: Phase 2E-E Candidate Environment + Scanner Contracts
WHY: Establish domain contracts for evidence-driven environment discovery (Candidate != Verified).
OWNS: EnvironmentIdentity, CandidateEnvironment, VerifiedEnvironment, AddressSpaceIdentity, IScanner, ICandidateEvaluator.
DOES NOT OWN: Actual DTB discovery, OS-specific parsers, symbol fetching.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Any, Protocol, List, Tuple
from .address_space import IAddressSpace

class EnvironmentStatus(Enum):
    VERIFIED = "VERIFIED"
    CANDIDATE = "CANDIDATE"
    UNSUPPORTED = "UNSUPPORTED"
    UNAVAILABLE = "UNAVAILABLE"
    UNKNOWN = "UNKNOWN"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    INVALID = "INVALID"


@dataclass(frozen=True)
class AddressSpaceIdentity:
    """
    Represents a distinct address-space / translation context.
    Independent from EnvironmentIdentity. Multiple address spaces may belong to one environment.
    """
    description: str
    properties: Tuple[Tuple[str, str], ...] = field(default_factory=tuple)

@dataclass(frozen=True)
class EnvironmentIdentity:
    """
    Extensible composite identity derived from evidence.
    Not an enum of hardcoded OS versions. Not Windows-specific.
    """
    os_family: Optional[str] = None
    distribution: Optional[str] = None
    version: Optional[str] = None
    build: Optional[str] = None
    architecture: Optional[str] = None
    endianness: Optional[str] = None
    page_size: Optional[int] = None
    symbol_identity: Optional[Any] = None
    # Frozen tuple of key-value pairs for deterministic extended properties
    extended_properties: Tuple[Tuple[str, Any], ...] = field(default_factory=tuple)

@dataclass(frozen=True)
class ObservationProvenance:
    scanner_identity: str
    target_artifact: str
    target_address_space: Optional[str]
    observed_address: Optional[int]
    evidence_references: Tuple[str, ...]

@dataclass(frozen=True)
class ScannerObservation:
    identity: str
    evidence_type: str
    extracted_properties: Tuple[Tuple[str, Any], ...]
    provenance: ObservationProvenance

class CandidateEnvironment:
    """
    Represents an environment hypothesis produced from evidence.
    Cannot be treated as a VerifiedEnvironment implicitly.
    """
    def __init__(self, identity: EnvironmentIdentity, supporting_observations: List[ScannerObservation], status: EnvironmentStatus = EnvironmentStatus.CANDIDATE):
        self.identity = identity
        self.supporting_observations = tuple(supporting_observations) # freeze for determinism
        self.status = status

class VerifiedEnvironment:
    """
    Represents an environment identity that has passed explicit verification requirements.
    Verification is an explicit semantic boundary.
    """
    def __init__(self, candidate: CandidateEnvironment, verification_evidence: Tuple[str, ...]):
        if candidate.status in (EnvironmentStatus.UNAVAILABLE, EnvironmentStatus.UNSUPPORTED, 
                                EnvironmentStatus.INSUFFICIENT_EVIDENCE, EnvironmentStatus.UNKNOWN,
                                EnvironmentStatus.INVALID):
            raise ValueError(f"Cannot verify candidate with failing status: {candidate.status.name}")
        self.identity = candidate.identity
        self.candidate_provenance = candidate.supporting_observations
        self.verification_evidence = verification_evidence

class IScanner(Protocol):
    """
    Provider-neutral scanner contract.
    Inspects, observes, returns structured evidence, and provides provenance.
    Does NOT verify the environment, declare malware, or fetch symbols.
    """
    def inspect(self, address_space: IAddressSpace) -> List[ScannerObservation]:
        ...

class ICandidateEvaluator(Protocol):
    """
    Consumes scanner observations and produces CandidateEnvironment hypotheses.
    Maintains separation between candidate generation and verification.
    """
    def evaluate(self, observations: List[ScannerObservation]) -> List[CandidateEnvironment]:
        ...
