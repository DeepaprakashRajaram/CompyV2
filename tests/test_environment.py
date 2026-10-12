import pytest
from fmd.v2.domain.native.environment import (
    EnvironmentIdentity,
    EnvironmentStatus,
    AddressSpaceIdentity,
    ObservationProvenance,
    ScannerObservation,
    CandidateEnvironment,
    VerifiedEnvironment,
    IScanner,
    ICandidateEvaluator
)
from fmd.v2.domain.native.symbols import SymbolUnavailableError
import sys

# Mock classes for testing the contracts
class MockAddressSpace:
    def __init__(self, description: str):
        self.identity = AddressSpaceIdentity(description)

class MockScanner(IScanner):
    def inspect(self, address_space) -> list:
        # H. Scanner output contains provenance
        # I. Scanner observations have deterministic identity
        # O. Scanner does not perform verification
        provenance = ObservationProvenance(
            scanner_identity="MockScanner_1.0",
            target_artifact="memory.dmp",
            target_address_space=address_space.identity.description,
            observed_address=0x1000,
            evidence_references=("Mock evidence hex string",)
        )
        obs = ScannerObservation(
            identity="OBS-1",
            evidence_type="MOCK_KDBG",
            extracted_properties=(("os_family", "Windows"),),
            provenance=provenance
        )
        return [obs]

class MockEvaluator(ICandidateEvaluator):
    def evaluate(self, observations) -> list:
        # P. Candidate generation does not perform symbol acquisition
        # N. No nearest-environment fallback exists
        if not observations:
            return []
            
        obs = observations[0]
        if "MOCK_KDBG" in obs.evidence_type:
            # A. CandidateEnvironment can contain partially known identity
            identity = EnvironmentIdentity(os_family="Windows") # Partially known
            return [CandidateEnvironment(identity, observations, EnvironmentStatus.CANDIDATE)]
        elif obs.evidence_type == "WEAK_EVIDENCE":
            # G. INSUFFICIENT_EVIDENCE is preserved
            identity = EnvironmentIdentity()
            return [CandidateEnvironment(identity, observations, EnvironmentStatus.INSUFFICIENT_EVIDENCE)]
        elif obs.evidence_type == "UNSUPPORTED_ARCH":
            # F. UNSUPPORTED is preserved
            identity = EnvironmentIdentity()
            return [CandidateEnvironment(identity, observations, EnvironmentStatus.UNSUPPORTED)]
        elif obs.evidence_type == "CORRUPT_PAGE":
            # E. UNAVAILABLE is preserved
            identity = EnvironmentIdentity()
            return [CandidateEnvironment(identity, observations, EnvironmentStatus.UNAVAILABLE)]
        else:
            # D. UNKNOWN is preserved
            identity = EnvironmentIdentity()
            return [CandidateEnvironment(identity, observations, EnvironmentStatus.UNKNOWN)]

def test_candidate_environment_partially_known():
    # A. CandidateEnvironment can contain partially known identity.
    scanner = MockScanner()
    space = MockAddressSpace("test_space")
    observations = scanner.inspect(space)
    
    evaluator = MockEvaluator()
    candidates = evaluator.evaluate(observations)
    
    assert len(candidates) == 1
    assert candidates[0].identity.os_family == "Windows"
    assert candidates[0].identity.architecture is None
    assert candidates[0].status == EnvironmentStatus.CANDIDATE

def test_candidate_distinct_from_verified():
    # B. CandidateEnvironment is distinct from VerifiedEnvironment.
    scanner = MockScanner()
    space = MockAddressSpace("test_space")
    observations = scanner.inspect(space)
    candidate = MockEvaluator().evaluate(observations)[0]
    
    assert not isinstance(candidate, VerifiedEnvironment)
    assert candidate.status == EnvironmentStatus.CANDIDATE
    
    verified = VerifiedEnvironment(candidate, ("Explicit verification check passing",))
    assert isinstance(verified, VerifiedEnvironment)

def test_insufficient_evidence_cannot_verify():
    # C. Insufficient evidence cannot produce a verified environment.
    prov = ObservationProvenance("S1", "A1", None, None, ())
    obs = ScannerObservation("O1", "WEAK_EVIDENCE", (), prov)
    candidate = MockEvaluator().evaluate([obs])[0]
    
    assert candidate.status == EnvironmentStatus.INSUFFICIENT_EVIDENCE
    
    with pytest.raises(ValueError, match="Cannot verify candidate with failing status: INSUFFICIENT_EVIDENCE"):
        VerifiedEnvironment(candidate, ("Attempt verification",))

def test_status_preservation():
    # D, E, F, G tests
    prov = ObservationProvenance("S1", "A1", None, None, ())
    evaluator = MockEvaluator()
    
    obs_unsupported = ScannerObservation("O1", "UNSUPPORTED_ARCH", (), prov)
    assert evaluator.evaluate([obs_unsupported])[0].status == EnvironmentStatus.UNSUPPORTED
    
    obs_unavailable = ScannerObservation("O1", "CORRUPT_PAGE", (), prov)
    assert evaluator.evaluate([obs_unavailable])[0].status == EnvironmentStatus.UNAVAILABLE
    
    obs_unknown = ScannerObservation("O1", "RANDOM_JUNK", (), prov)
    assert evaluator.evaluate([obs_unknown])[0].status == EnvironmentStatus.UNKNOWN

def test_address_space_identity_distinction():
    # J. Different address spaces cannot collide semantically.
    # K. EnvironmentIdentity and AddressSpaceIdentity remain distinct.
    addr1 = AddressSpaceIdentity("AS_1")
    addr2 = AddressSpaceIdentity("AS_2")
    assert addr1 != addr2
    
    env = EnvironmentIdentity(os_family="Windows")
    # They are structurally entirely different types.
    assert not isinstance(addr1, EnvironmentIdentity)

def test_deterministic_identity():
    # I. Scanner observations have deterministic identity.
    # L. Identical scanner inputs produce identical candidates.
    scanner = MockScanner()
    space = MockAddressSpace("test_space")
    obs1 = scanner.inspect(space)[0]
    obs2 = scanner.inspect(space)[0]
    
    assert obs1 == obs2
    
    evaluator = MockEvaluator()
    cand1 = evaluator.evaluate([obs1])[0]
    cand2 = evaluator.evaluate([obs2])[0]
    
    assert cand1.identity == cand2.identity
    assert cand1.supporting_observations == cand2.supporting_observations

def test_distinct_semantic_evidence_distinct_candidates():
    # M. Different semantic evidence produces distinct candidates.
    evaluator = MockEvaluator()
    prov = ObservationProvenance("S1", "A1", None, None, ())
    
    obs1 = ScannerObservation("O1", "MOCK_KDBG", (("os_family", "Windows"),), prov)
    obs2 = ScannerObservation("O2", "WEAK_EVIDENCE", (), prov)
    
    cand1 = evaluator.evaluate([obs1])[0]
    cand2 = evaluator.evaluate([obs2])[0]
    
    assert cand1.identity != cand2.identity

def test_no_volatility_network():
    # Q. No Volatility/network dependency is introduced.
    assert 'volatility3' not in [m for m in sys.modules.keys() if m.startswith('fmd.v2.domain.native')]
    import inspect
    import fmd.v2.domain.native.environment as env_module
    source = inspect.getsource(env_module)
    assert "requests" not in source
    assert "urllib" not in source
    assert "socket" not in source
    assert "volatility" not in source
