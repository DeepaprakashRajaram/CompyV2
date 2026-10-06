# Compsognathus (Compy)

**Advanced Fileless Malware Forensic Engine (V2.0)**

Compsognathus (Compy) is a next-generation forensic engine designed to detect, analyze, and map fileless malware behavior in system memory. By leveraging an immutable Evidence Ledger, deterministic Tri-State logic, and a strict Hexagonal Architecture, Compy provides mathematically rigorous forensic investigations.

## 1. Problem Statement
Traditional memory forensics often relies on ad-hoc plugin outputs and probabilistic heuristics that can lead to contradictory conclusions or silent failures (e.g., when debugging symbols are missing). Compy solves this by elevating memory analysis into a strongly-typed, deterministic domain model where every forensic capability is strictly verified, and missing dependencies result in explicit failure paths rather than false negatives.

## 2. Architecture
Compy V2 implements a strict **Hexagonal Architecture (Ports and Adapters)**:
- **Core Domain:** Immutable Evidence Ledger, Domain Nodes, Corroboration, and Verification.
- **Application Layer:** Isolated Use Cases (e.g., `AnalyzeMemoryUseCase`) and the `SessionCoordinator`.
- **Adapters:** External integrations (Volatility 3, CLI, Web App API).

## 3. Current Capabilities
- **Status:** Phase 1 Integration Complete.
- **Supported:** Evidence Model (Nodes, Edges, Provenance), Tri-State Logic (True/False/Unknown), Strict Verification, CLI Application Boundary.
- **Not Yet Implemented:** YARA integration, Live memory acquisition, Automated response execution, Desktop UI application.

## 4. Installation
Compy requires Python 3.10+.

```powershell
git clone https://github.com/DeepaprakashRajaram/CompyV2.git
cd CompyV2
python -m venv .venv
.venv\Scripts\activate
pip install -e .
```

## 5. CLI Usage
Compy exposes a product-level CLI for direct interaction with the forensic engine.

```powershell
compy
```
*Note: Currently, the CLI demonstrates the structural architecture and domain logic using mock data, as arbitrary real-memory execution requires localized symbol provisioning.*

## 6. Volatility 3 & Symbol Safety Policy
Compy enforces a strict **`LOCAL_ONLY + FAIL_IF_MISSING`** policy for Volatility 3.
- Compy will **never** silently download forensic symbols from the internet.
- Missing required symbols cause a controlled capability failure (`CapabilityStatus.UNAVAILABLE`).
- Users must manually provision compatible symbols to their local Volatility cache legally and securely.
- We do not distribute raw memory images or symbols in this repository.

## 7. Web Application Integration
A future desktop/web interface is planned. The web application must consume Compy solely through the Application Layer (`fmd.v2.application.use_cases`).
Frontend code must **never** directly depend on Volatility, YARA, or OS memory APIs.
See `docs/web-app/COMPY_WEB_APP_HANDOFF.md` for IPC boundary definitions.

## 8. Testing
- **Unit Tests:** Execute via `pytest tests/v2`. (Safe, fast, no real memory required).
- **Integration Tests:** Execute via `pytest tests/v2`.
- **Forensic Validation:** Raw memory tests are excluded from the default test suite to prevent accidental dependency on private memory dumps.

## 9. Safety Boundaries
- **Immutability:** The Evidence Ledger is append-only.
- **Side-Effects:** Volatility is strictly executed offline.
- **Determinism:** `Investigation ID` generation is mathematically bound to the run identity and artifact hash.

## 10. Contribution
See `CONTRIBUTING.md` for guidelines on extending the core domain. All PRs must adhere to the Hexagonal Architecture and safety policies.

## 11. Roadmap
- **Phase 2:** Advanced Detectors and Volatility Plugin integration.
- **Phase 3:** YARA Integration & Signature Matching.
- **Phase 4:** Live Memory Acquisition.
- **Phase 5:** Web/Desktop Application UI.
