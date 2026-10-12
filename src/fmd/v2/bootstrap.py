"""
WHAT: Compy V2 Application Bootstrap & Composition Root.
WHY: Centralizes dependency injection for both CLI and Web adapters.
OWNS: Application factory and default coordinator wiring.
DOES NOT OWN: Transport-specific logic (HTTP, CLI formatting).
"""

from pathlib import Path
from typing import Optional, List

from fmd.v2.application.use_cases import AnalyzeMemoryUseCase
from fmd.v2.application.coordinator import SessionCoordinator
from fmd.v2.domain.contracts import ICollector, IDetector
from fmd.v2.adapters.providers.mock_collector import MockCollector
from fmd.v2.adapters.providers.mock_detector import MockStructuralDetector
from fmd.v2.adapters.providers.process_tree_detector import ProcessTreeAnomalyDetector
from fmd.v2.adapters.providers.hidden_process_detector import HiddenProcessDetector
from fmd.v2.adapters.providers.injected_code_detector import InjectedCodeDetector
from fmd.v2.adapters.providers.yara.detector import YaraDetector
from fmd.v2.domain.evidence.ledger import EvidenceLedger
from fmd.v2.domain.reasoning.corroboration import DeterministicCorroborator
from fmd.v2.domain.reasoning.verification import StrictVerifier
from fmd.v2.domain.governance.gate import CLIGovernanceGate

SUPPORTED_MEMORY_EXTENSIONS = {".raw", ".mem", ".dmp", ".vmem", ".bin", ".lime"}
SUPPORTED_EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".ocx"}
SUPPORTED_SCRIPT_EXTENSIONS = {".ps1", ".bat", ".cmd", ".vbs", ".js", ".py", ".sh"}
ALL_SUPPORTED_EXTENSIONS = SUPPORTED_MEMORY_EXTENSIONS | SUPPORTED_EXECUTABLE_EXTENSIONS | SUPPORTED_SCRIPT_EXTENSIONS

def is_supported_memory_image(path: str) -> bool:
    """Validates that the file has a supported memory image extension."""
    ext = Path(path).suffix.lower()
    return ext in SUPPORTED_MEMORY_EXTENSIONS

def classify_artifact(path: str) -> str:
    """
    Detects and classifies the submitted artifact type:
    - 'MEMORY_IMAGE': Raw RAM dumps, crash dumps (.raw, .mem, .dmp, etc.)
    - 'EXECUTABLE_PE': Windows portable executables (.exe, .dll, .sys)
    - 'SCRIPT': Command scripts (.ps1, .bat, .cmd, etc.)
    - 'UNSUPPORTED': Non-executable/unsupported file types
    """
    p = Path(path)
    ext = p.suffix.lower()
    if ext in SUPPORTED_MEMORY_EXTENSIONS:
        return "MEMORY_IMAGE"
    if ext in SUPPORTED_EXECUTABLE_EXTENSIONS:
        return "EXECUTABLE_PE"
    if ext in SUPPORTED_SCRIPT_EXTENSIONS:
        return "SCRIPT"
    return "UNSUPPORTED"

def create_v2_app(
    collector: Optional[ICollector] = None,
    detectors: Optional[List[IDetector]] = None
) -> AnalyzeMemoryUseCase:
    """
    Composition Root creating a fully wired AnalyzeMemoryUseCase.
    Allows injecting explicit collectors (real, fake, or mock) and detectors.
    """
    def coordinator_factory() -> SessionCoordinator:
        active_collector = collector if collector is not None else MockCollector()
        active_detectors = detectors if detectors is not None else [
            MockStructuralDetector(),
            ProcessTreeAnomalyDetector(),
            HiddenProcessDetector(),
            InjectedCodeDetector(),
            YaraDetector()
        ]
        ledger = EvidenceLedger()
        return SessionCoordinator(
            collector=active_collector,
            detectors=active_detectors,
            ledger=ledger,
            ledger_query=ledger,
            graph_query=ledger,
            corroborator=DeterministicCorroborator(),
            verifier=StrictVerifier(),
            governance=CLIGovernanceGate()
        )

    return AnalyzeMemoryUseCase(coordinator_factory=coordinator_factory)

def create_demo_app() -> AnalyzeMemoryUseCase:
    """Creates a deterministic synthetic demonstration application use case."""
    return create_v2_app(
        collector=MockCollector(),
        detectors=[
            MockStructuralDetector(),
            ProcessTreeAnomalyDetector(),
            HiddenProcessDetector(),
            InjectedCodeDetector(),
            YaraDetector()
        ]
    )

def create_real_app(
    memory_image_path: str,
    artifact_hash: str,
    custom_collector: Optional[ICollector] = None,
    yara_rules_dir: Optional[str] = None
) -> tuple[Optional[AnalyzeMemoryUseCase], Optional[str]]:
    """
    Creates the real forensic application use case.
    Does NOT fall back to MockCollector.
    Returns (use_case, None) if supported and provider available,
    or (None, failure_reason) if unsupported or unavailable.
    """
    if custom_collector is not None:
        # Allows injecting instrumented or native collectors for tests
        if callable(custom_collector):
            try:
                active_col = custom_collector(memory_image_path, artifact_hash)
            except TypeError:
                active_col = custom_collector()
        else:
            active_col = custom_collector
        app = create_v2_app(
            collector=active_col,
            detectors=[
                ProcessTreeAnomalyDetector(),
                HiddenProcessDetector(),
                InjectedCodeDetector(),
                YaraDetector()
            ]
        )
        return app, None

    # Classify artifact type before selecting analysis pipeline
    artifact_type = classify_artifact(memory_image_path)
    if artifact_type == "UNSUPPORTED":
        return None, (
            f"Unsupported artifact type or unreadable file: {memory_image_path}. "
            "Compy supports memory images (.raw, .vmem, .dmp, .bin), PE files (.exe, .dll, .sys), "
            "and scripts (.ps1, .bat, .cmd, .vbs, .js, .py, .sh)."
        )

    # If static executable or script, use FileArtifactCollector (never pass to Volatility)
    if artifact_type in ("EXECUTABLE_PE", "SCRIPT"):
        try:
            from fmd.v2.adapters.providers.file_collector import FileArtifactCollector
            file_collector = FileArtifactCollector(
                file_path=memory_image_path,
                artifact_hash=artifact_hash,
                artifact_type=artifact_type,
                yara_rules_dir=yara_rules_dir
            )
            app = create_v2_app(
                collector=file_collector,
                detectors=[
                    ProcessTreeAnomalyDetector(),
                    HiddenProcessDetector(),
                    InjectedCodeDetector(),
                    YaraDetector()
                ]
            )
            return app, None
        except Exception as e:
            return None, f"Failed to initialize file collector: {str(e)}"

    # Otherwise, it's a MEMORY_IMAGE: check if native Volatility 3 is available
    try:
        from fmd.v2.adapters.providers.volatility.collector import VolatilityCollector
        import volatility3
        real_collector = VolatilityCollector(
            memory_image_path=memory_image_path,
            artifact_hash=artifact_hash,
            yara_rules_dir=yara_rules_dir
        )
        app = create_v2_app(
            collector=real_collector,
            detectors=[
                ProcessTreeAnomalyDetector(),
                HiddenProcessDetector(),
                InjectedCodeDetector(),
                YaraDetector()
            ]
        )
        return app, None
    except ImportError:
        return None, (
            "Forensic provider 'volatility3' is not installed in runtime environment. "
            "Under Compy's FAIL_IF_MISSING policy, mock analysis will not be substituted."
        )
    except Exception as e:
        return None, f"Failed to initialize forensic provider: {str(e)}"
