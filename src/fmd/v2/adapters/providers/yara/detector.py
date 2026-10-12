"""
WHAT: YARA Detector for Compy V2.
WHY: Generates IObservation records from YARA rule matches in the evidence ledger.
OWNS: Normalization of YARA hits into domain observations.
DOES NOT OWN: Rule compilation, file system traversal.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Set, Tuple, Dict, Any

from fmd.v2.domain.contracts import (
    IDetector,
    ILedgerQuery,
    IGraphQuery,
    IContentAccessor,
    IObservation,
    IDetectorResult,
    ProviderId,
    EvidenceId,
    ProviderCapability,
    CapabilityStatus
)
from fmd.v2.domain.evidence.nodes import YaraMatchNode, InjectedCodeNode, ProcessNode
from fmd.v2.adapters.providers.yara.scanner import YaraScannerProvider

@dataclass(frozen=True)
class YaraObservation(IObservation):
    """
    Observation indicating a verified YARA signature match on memory or an artifact.
    """
    _detector_id: ProviderId
    _target: EvidenceId
    description: str
    rule_name: str
    namespace: str = "default"
    target_type: str = "PROCESS_MEMORY"
    target_identifier: str = ""
    matched_strings: Tuple[Tuple[str, int, str], ...] = ()
    meta: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.95
    anomaly_category: str = "YARA_RULE_MATCH"
    heuristic_severity: float = 0.90

    @property
    def detector_id(self) -> ProviderId:
        return self._detector_id

    @property
    def target_evidence_id(self) -> EvidenceId:
        return self._target


@dataclass
class YaraDetectorResult(IDetectorResult):
    _status: CapabilityStatus
    _observations: List[IObservation] = field(default_factory=list)
    _failure_reason: Optional[str] = None

    @property
    def status(self) -> CapabilityStatus:
        return self._status

    @property
    def observations(self) -> List[IObservation]:
        return self._observations

    @property
    def failure_reason(self) -> Optional[str]:
        return self._failure_reason


class YaraDetector(IDetector):
    """
    Evaluates evidence for YARA matches.
    If the ledger already contains YaraMatchNodes, normalizes them into observations.
    Can also invoke YaraScannerProvider on InjectedCodeNode and ProcessNode cmdlines.
    """

    def __init__(self, scanner: Optional[YaraScannerProvider] = None):
        self.scanner = scanner or YaraScannerProvider()

    def provider_id(self) -> ProviderId:
        return ProviderId("yara_signature_detector_v1")

    def required_capabilities(self) -> Set[ProviderCapability]:
        return {ProviderCapability.YARA_SCAN}

    def evaluate(
        self,
        ledger: ILedgerQuery,
        graph: IGraphQuery,
        content: Optional[IContentAccessor] = None
    ) -> IDetectorResult:
        # Check scanner health first
        if self.scanner.status == CapabilityStatus.FAILED:
            return YaraDetectorResult(
                _status=CapabilityStatus.FAILED,
                _failure_reason=self.scanner.failure_reason
            )
        elif self.scanner.status == CapabilityStatus.UNAVAILABLE:
            return YaraDetectorResult(
                _status=CapabilityStatus.UNAVAILABLE,
                _failure_reason=self.scanner.failure_reason or "YARA scanner backend unavailable"
            )

        observations: List[IObservation] = []
        nodes = ledger.get_all_nodes()

        # 1. Inspect existing YaraMatchNode facts in Ledger
        yara_nodes = [n for n in nodes if getattr(n, "node_type", None) == "YaraMatch"]
        for yn in yara_nodes:
            meta = getattr(yn, "meta", {}) or {}
            sev_str = meta.get("severity", "HIGH").upper()
            sev_score = 0.95 if sev_str == "CRITICAL" else (0.85 if sev_str == "HIGH" else 0.70)
            
            desc = (
                f"YARA rule '{yn.rule_name}' matched target '{yn.target_identifier}'. "
                f"Strings matched: {len(yn.matched_strings)}. Meta: {meta.get('description', 'N/A')}"
            )
            obs = YaraObservation(
                _detector_id=self.provider_id(),
                _target=yn.id,
                description=desc,
                rule_name=yn.rule_name,
                namespace=yn.namespace,
                target_type=yn.target_type,
                target_identifier=yn.target_identifier,
                matched_strings=yn.matched_strings,
                meta=meta,
                heuristic_severity=sev_score
            )
            observations.append(obs)

        # 2. If no YaraMatchNodes were pre-ingested, dynamically scan InjectedCodeNodes & Process cmdlines
        if not yara_nodes and self.scanner.status == CapabilityStatus.SUCCESS:
            injected_nodes = [n for n in nodes if getattr(n, "node_type", None) == "InjectedCode"]
            for inj in injected_nodes:
                matches = self.scanner.scan_injected_artifact(
                    pid=inj.pid,
                    process_name=inj.process_name,
                    start_addr=inj.start_address,
                    hexdump_preview=inj.hexdump_preview,
                    disasm_preview=inj.disasm_preview
                )
                for m in matches:
                    meta = m.meta or {}
                    sev_str = meta.get("severity", "HIGH").upper()
                    sev_score = 0.95 if sev_str == "CRITICAL" else (0.85 if sev_str == "HIGH" else 0.70)
                    desc = (
                        f"YARA rule '{m.rule_name}' matched injected allocation in PID {inj.pid} ({inj.process_name}) "
                        f"at 0x{inj.start_address:x}. Strings: {len(m.matched_strings)}."
                    )
                    obs = YaraObservation(
                        _detector_id=self.provider_id(),
                        _target=inj.id,
                        description=desc,
                        rule_name=m.rule_name,
                        namespace=m.namespace,
                        target_type=m.target_type,
                        target_identifier=m.target_identifier,
                        matched_strings=m.matched_strings,
                        meta=meta,
                        heuristic_severity=sev_score
                    )
                    observations.append(obs)

            # Also scan suspicious command lines
            process_nodes = [n for n in nodes if getattr(n, "node_type", None) == "Process" and getattr(n, "cmdline", None)]
            for proc in process_nodes:
                cmd_matches = self.scanner.scan_cmdline(
                    pid=proc.pid,
                    process_name=proc.name,
                    cmdline=proc.cmdline
                )
                for m in cmd_matches:
                    meta = m.meta or {}
                    desc = f"YARA rule '{m.rule_name}' matched command line of PID {proc.pid} ({proc.name})."
                    obs = YaraObservation(
                        _detector_id=self.provider_id(),
                        _target=proc.id,
                        description=desc,
                        rule_name=m.rule_name,
                        namespace=m.namespace,
                        target_type=m.target_type,
                        target_identifier=m.target_identifier,
                        matched_strings=m.matched_strings,
                        meta=meta,
                        heuristic_severity=0.80
                    )
                    observations.append(obs)

        return YaraDetectorResult(
            _status=CapabilityStatus.SUCCESS,
            _observations=observations
        )
