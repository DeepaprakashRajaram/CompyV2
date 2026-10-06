import pytest
import os
from fmd.v2.adapters.providers.volatility.collector import VolatilityCollector
from fmd.v2.domain.contracts import CapabilityStatus, ProviderCapability

# We use the dummy file to test the failure paths.
DUMMY_RAW_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "dummy.raw")

def test_volatility_missing_symbols_or_invalid_image():
    # If the image is invalid or missing symbols, it should cleanly return UNAVAILABLE
    collector = VolatilityCollector(memory_image_path=DUMMY_RAW_PATH, artifact_hash="dummyhash")
    result = collector.extract_evidence()
    
    assert result.capability_status == CapabilityStatus.UNAVAILABLE or result.capability_status == CapabilityStatus.FAILED
    assert len(result.capability_failures) > 0
    assert ProviderCapability.PROCESS_LIST not in result.available_capabilities

def test_volatility_provenance():
    collector = VolatilityCollector(memory_image_path=DUMMY_RAW_PATH, artifact_hash="testhash123")
    result = collector.extract_evidence()
    
    # Even on failure, provenance is preserved
    prov = result.provenance
    assert prov.provider_id.startswith("volatility3")
    assert prov.artifact_identity == "testhash123"
    assert prov.acquisition_mode == "NATIVE_VOLATILITY3"

def test_volatility_provider_id():
    collector = VolatilityCollector(memory_image_path=DUMMY_RAW_PATH, artifact_hash="testhash123")
    assert "volatility3" in collector.provider_id()

def test_volatility_failure_isolation():
    # Providing a completely nonexistent file to ensure no hard crashes
    collector = VolatilityCollector(memory_image_path="/does/not/exist.raw", artifact_hash="testhash123")
    result = collector.extract_evidence()
    
    # The provider boundary must catch internal exceptions and return them as failures
    assert result.capability_status in (CapabilityStatus.FAILED, CapabilityStatus.UNAVAILABLE)
    assert len(result.capability_failures) > 0
