"""
WHAT: Session Coordinator.
WHY: Coordinates the flow of data between adapters and domain logic.
OWNS: Pipeline orchestration.
DOES NOT OWN: Detection algorithms, Evidence logic, UI logic (NO GOD OBJECT).
"""

import uuid
from datetime import datetime
from typing import List, Optional

from fmd.v2.domain.contracts import ICollector, IDetector, ILedgerWrite, ILedgerQuery, IGraphQuery
from fmd.v2.domain.contracts import ICorroborator, IVerifier, IGovernanceGate, CapabilityStatus, TriState, ProviderCapability
from fmd.v2.domain.contracts import IContentAccessor, IDetectorResult, IObservation
from fmd.v2.domain.evidence.mapper import EvidenceMapper
from fmd.v2.domain.reasoning.investigation import InvestigationDossier
from fmd.v2.adapters.providers.mock_detector import MockDetectorResult

class MissingCapabilityDetectorResult(IDetectorResult):
    def __init__(self, failure_reason: str, detector_id: Optional[str] = None):
        self._failure_reason = failure_reason
        self._detector_id = detector_id or ""
        
    @property
    def status(self) -> CapabilityStatus:
        return CapabilityStatus.UNAVAILABLE
        
    @property
    def observations(self) -> List[IObservation]:
        return []
        
    @property
    def failure_reason(self) -> Optional[str]:
        return self._failure_reason

    @property
    def provider_id(self) -> str:
        return self._detector_id

class SessionCoordinator:
    """
    Routes data. Does not make forensic decisions.
    """
    def __init__(self, 
                 collector: ICollector, 
                 detectors: List[IDetector],
                 ledger: ILedgerWrite,
                 ledger_query: ILedgerQuery,
                 graph_query: IGraphQuery,
                 corroborator: ICorroborator,
                 verifier: IVerifier,
                 governance: IGovernanceGate,
                 content_accessor: Optional[IContentAccessor] = None):
        self.collector = collector
        self.detectors = detectors
        self.content_accessor = content_accessor
        
        self.ledger = ledger
        self.ledger_query = ledger_query
        self.graph_query = graph_query
        
        self.corroborator = corroborator
        self.verifier = verifier
        self.governance = governance
        
        self.mapper = EvidenceMapper(ledger=self.ledger)

    def run_analysis(self, target_path: str, session_timestamp: datetime) -> InvestigationDossier:
        # 1. Collection (Coordinator routes command to Port)
        provider_result = self.collector.extract_evidence()
        
        # 2. Ingestion (Coordinator routes raw data to Mapper)
        dtos = provider_result.extracted_dtos
        raw_procs = dtos[0] if len(dtos) > 0 else ()
        raw_regions = dtos[1] if len(dtos) > 1 else ()
        raw_injected = dtos[2] if len(dtos) > 2 else ()
        self.mapper.ingest_process_list(
            raw_procs, 
            provider_result.provenance,
            available_capabilities=provider_result.available_capabilities
        )
        self.mapper.ingest_memory_regions(raw_regions, provider_result.provenance)
        if raw_injected:
            self.mapper.ingest_injected_code(
                raw_injected,
                provider_result.provenance,
                available_capabilities=provider_result.available_capabilities
            )
        raw_yara = dtos[3] if len(dtos) > 3 else ()
        if raw_yara:
            self.mapper.ingest_yara_matches(
                raw_yara,
                provider_result.provenance,
                available_capabilities=provider_result.available_capabilities
            )
        
        # 3. Detection
        all_observations = []
        failures = []
        
        for detector in self.detectors:
            # Check capabilities
            if not detector.required_capabilities().issubset(provider_result.available_capabilities):
                missing = detector.required_capabilities() - provider_result.available_capabilities
                failures.append(MissingCapabilityDetectorResult(
                    failure_reason=f"Detector {detector.provider_id()} requires missing capabilities: {missing}",
                    detector_id=detector.provider_id()
                ))
                continue
                
            try:
                result = detector.evaluate(self.ledger_query, self.graph_query, self.content_accessor)
                if result.status == CapabilityStatus.SUCCESS:
                    all_observations.extend(result.observations)
                else:
                    failures.append(result)
            except Exception as e:
                # Failure isolation
                failures.append(MockDetectorResult(
                    _status=CapabilityStatus.FAILED, 
                    _failure_reason=str(e)
                ))
        # Propagate collector capability failures into failures list
        collector_failures = getattr(provider_result, "capability_failures", ()) or ()
        for c_fail in collector_failures:
            failures.append(MissingCapabilityDetectorResult(
                failure_reason=str(c_fail),
                detector_id="volatility_forensic_collector"
            ))
        # 4. Corroboration
        candidates = self.corroborator.evaluate(all_observations, self.graph_query)
        
        # 5. Create Investigation (Deterministic ID based on Artifact Identity and Run Identity)
        # Investigation Identity is RunID + ArtifactID
        run_seed = f"{target_path}-{session_timestamp.isoformat()}"
        run_id = str(uuid.uuid5(uuid.NAMESPACE_URL, run_seed))
        
        inv_seed = f"{run_id}-{provider_result.provenance.artifact_identity}"
        deterministic_id = f"INV-{uuid.uuid5(uuid.NAMESPACE_URL, inv_seed).hex[:8]}"
        
        dossier = InvestigationDossier(
            investigation_id=deterministic_id,
            created_at=session_timestamp,
            candidates=candidates,
            capability_failures=failures
        )
        
        has_unknown = any(
            f.status in (CapabilityStatus.UNAVAILABLE, CapabilityStatus.FAILED, CapabilityStatus.PARTIAL)
            for f in failures
            if not getattr(f, "is_optional", False)
        )
        
        # 6. Verification
        if candidates:
            # Audit all candidates and prioritize TRUE > UNKNOWN > FALSE
            conclusions = [
                self.verifier.verify(c, self.ledger_query, self.graph_query)
                for c in candidates
            ]
            true_conclusions = [c for c in conclusions if c.status == TriState.TRUE]
            unknown_conclusions = [c for c in conclusions if c.status == TriState.UNKNOWN]

            if true_conclusions:
                chosen_conclusion = true_conclusions[0]
            elif unknown_conclusions:
                chosen_conclusion = unknown_conclusions[0]
            else:
                chosen_conclusion = conclusions[0]

            # If all candidates concluded FALSE, but a required capability failed, prevent clean FALSE
            if chosen_conclusion.status == TriState.FALSE and has_unknown:
                from fmd.v2.domain.reasoning.verification import VerifiedConclusion
                chosen_conclusion = VerifiedConclusion(
                    _status=TriState.UNKNOWN,
                    _rationale="INCONCLUSIVE: No candidates verified as malicious, but required analysis capabilities failed or were incomplete."
                )

            dossier.verification_conclusion = chosen_conclusion
            dossier.system_status = chosen_conclusion.status
            
            # 7. Governance
            approved = self.governance.request_approval(chosen_conclusion)
            if approved:
                pass # In V2, call ResponseExecutor here
        else:
            if has_unknown:
                dossier.system_status = TriState.UNKNOWN
            else:
                dossier.system_status = TriState.FALSE
                
        return dossier
