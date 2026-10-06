# Compy V2 Web Application Handoff

## 1. Purpose
This document provides the minimum required context, contracts, and architectural boundaries for building the Compy V2 Web Application. 

The web application is being built in parallel with the forensic core. This handoff isolates the web application from the complexities of the memory forensic core to ensure strict separation of concerns.

## 2. Architecture Boundary
The web application acts strictly as a **Presentation and Interaction Layer**. 
It must consume Compy exclusively through the Application / Use-Case boundary (`AnalyzeMemoryUseCase`), identically to the existing CLI adapter. 
The web application is a peer to the CLI, sitting above the API/IPC boundary.

## 3. Stable Contracts
The web application must build against the following stable files. These define the strict schema returned by the backend:
- `src/fmd/v2/domain/contracts.py` (Core Protocols and Interfaces)
- `src/fmd/v2/domain/reasoning/investigation.py` (The output `InvestigationDossier`)
- `src/fmd/v2/application/use_cases.py` (The boundary `AnalyzeMemoryRequest` and Use Case)

## 4. Current Evolving Contracts
The P0 Evidence Model Corrections have just been completed. The web developer should note the following updated semantics:
- **P0-1 (Corroboration):** `IInvestigationCandidate` now has a `independent_evidence_targets` property (`Set[EvidenceId]`) to group observations deduplicated by target.
- **P0-2 (Temporal Evidence):** `ProcessNode` now includes `create_time` and `exit_time` fields.
- **P0-3 (Verifier Sufficiency):** `StrictVerifier` logic requires both memory and thread execution evidence to conclude `TriState.TRUE`. If execution evidence is missing, the status defaults to `TriState.UNKNOWN`.

## 5. Evidence Model
- **Evidence ID:** Strongly typed wrapper `EvidenceId(str)` using UUIDv5 deterministic generation.
- **Evidence Type:** Denoted by the `node_type` property (e.g., `"Process"`, `"MemoryRegion"`, `"Thread"`).
- **Factual Attributes:** Available directly on concrete nodes (e.g., `pid`, `start_address`, `protection`).
- **Provenance / Lineage / Relationships / Temporal Info:** Extracted from collectors and tracked on the `IEvidenceNode` and graph relationships.

## 6. Observation Model
- **Detector ID:** ID of the detector that flagged the anomaly.
- **Target Evidence ID:** The UUID of the underlying factual node (e.g., the specific `MemoryRegionNode`).
- **Observation Semantics:** Descriptive metadata regarding the hypothesis.

## 7. Corroboration Model
- **Investigation Candidate:** A grouping of observations into a coherent hypothesis.
- **Related Observations:** Flat list of all `IObservation`s.
- **Underlying Evidence / Independence:** Extracted via `independent_evidence_targets` to deduplicate observations targeting the exact same factual node.

## 8. Investigation Model
- **Investigation Identity:** Uniquely generated UUIDv5 (`investigation_id`).
- **Run Identity & Artifact Identity:** Used as seeds to deterministically generate the `investigation_id`.
- **Findings / Status:** Encapsulated in the `InvestigationDossier`.

## 9. Verification Model
- **Verification State:** Returned as an `IVerifiedConclusion` containing a `status` (`TriState`) and a `rationale` string explaining the sufficiency of evidence.
- **UNKNOWN Semantics:** Explicitly represents "Insufficient Evidence" (e.g., finding a suspicious memory region without thread execution context).

## 10. Governance Model
- **Recommendation & Approval:** Represents human/policy approval of response plans. Currently handled by `IGovernanceGate`.

## 11. Capability Status Model
- **Capability State:** Tracks provider feature availability (e.g., `PROCESS_LIST`, `VAD_INFO`).
- Missing or failed capabilities are reported in the dossier's `capability_failures`.

## 12. Identity Semantics
All evidence and investigations utilize strictly deterministic **UUIDv5** hashing based on artifact provenance and stable forensic properties (e.g., PID, timestamps). The UI should expect identities to remain stable across identical analysis runs.

## 13. Provenance Semantics
Defined by `IProvenanceRecord`, this explicitly tracks the origin (`provider_id`, `artifact_identity`, `acquisition_mode`) of every factual piece of evidence to ensure defensibility.

## 14. Mock/Demo Data Availability
Since real memory parsing is currently blocked, the UI developer should use the provided mock data to build the frontend.
- **Reference:** `src/fmd/v2/adapters/providers/mock_collector.py` and `src/fmd/v2/adapters/providers/mock_detector.py`.
- **Warning:** This is **DEMO / MOCK DATA — NOT REAL MEMORY EVIDENCE**.

## 15. What the Frontend MUST NOT Implement
The web application must **NOT** implement any forensic reasoning, evaluation, or mitigation logic. 
- **BAD:** Frontend parses evidence properties to decide "This is malware."
- **GOOD:** Backend evaluates observations/corroboration to produce a verification state; Frontend simply renders the `InvestigationDossier`, its status, and its explanatory rationale.

## 16. What is Currently Unavailable
Do not invent APIs for features not currently in the V2 backend. The following are **NOT CURRENTLY AVAILABLE**:
- Volatility 3 Real Memory Integration
- YARA / YARA-X scanning
- Live Windows / Linux providers
- Automated response execution (mitigation)

## 17. How the Future Backend Will Connect
Future integration of Volatility, YARA, and Live Forensics will happen entirely *behind* the Application boundary. The `AnalyzeMemoryUseCase` and `InvestigationDossier` schemas will remain stable. The web app will simply begin receiving richer node types and observations.

## 18. Current Gate 3 Limitation
Phase 2B Gate 3 remains **BLOCKED** pending the arrival of a real benign Windows x64 memory fixture. The web application may proceed using the mock providers. Do not claim or expect successful real-memory demonstrations at this stage.

---

## File Selection Guide

### 🟢 REQUIRED FOR WEB DEVELOPER
*(Do not copy these into your repo; reference them directly from the Compy V2 structure to stay in sync with the backend contracts.)*
- `src/fmd/v2/domain/contracts.py`
- `src/fmd/v2/domain/evidence/nodes.py`
- `src/fmd/v2/domain/reasoning/investigation.py`
- `src/fmd/v2/application/use_cases.py`

### 🟡 USEFUL REFERENCE
- `tests/v2/test_core_integration.py` (Living API example of Use Case invocation)
- `src/fmd/v2/domain/reasoning/corroboration.py` (Explains P0-1 grouping logic)
- `src/fmd/v2/domain/reasoning/verification.py` (Explains P0-3 evidence sufficiency logic)
- `src/fmd/v2/adapters/cli/compy_cli.py` (Example of a sibling frontend adapter)
- `src/fmd/v2/domain/evidence/provenance.py`
- `src/fmd/v2/adapters/providers/mock_collector.py` (The mock data fixture)
- `src/fmd/v2/adapters/providers/mock_detector.py`

### 🔴 DO NOT SHARE / DO NOT COUPLE TO
- `src/fmd/v2/adapters/providers/volatility/` (No direct coupling to forensic internals)
- `src/fmd/v1/` (Legacy code)
- `src/fmd/v2/domain/evidence/ledger.py` and `mapper.py` (Internal state management)
- `research/`, `checkpoints/`, `memory dumps` (Experimental or irrelevant data)
