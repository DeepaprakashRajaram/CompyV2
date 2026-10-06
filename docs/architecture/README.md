# Architecture Overview

Compsognathus (Compy) V2 operates on a strict **Hexagonal Architecture**. 
This pattern decouples the forensic logic (the core domain) from external systems, such as Volatility 3, CLIs, and Web Applications.

## Core Domain (`src/fmd/v2/domain`)
The core domain is the heart of the engine and contains pure Python logic with ZERO external dependencies (no Volatility, no YARA, no UI).
It defines:
- **Evidence Ledger:** An immutable append-only graph that stores forensic nodes and edges.
- **Tri-State Logic:** Evidence evaluation returns `True`, `False`, or `Unknown` (when capabilities are missing).
- **Corroborator:** Links multiple independent observations to reduce false positives.
- **Verifier:** Evaluates the sufficiency of evidence to draw a final forensic conclusion.
- **Governance Gate:** Provides rules around when to alert, quarantine, or escalate.

## Application Layer (`src/fmd/v2/application`)
- **Use Cases:** E.g., `AnalyzeMemoryUseCase` coordinates user actions.
- **Session Coordinator:** Routes extracted DTOs from providers into the Evidence Mapper. Does NOT make detection decisions.

## Adapters (`src/fmd/v2/adapters`)
Adapters plug external tools into the engine.
- **Volatility 3 Provider:** Safely extracts process lists and memory regions.
- **CLI Adapter:** The command-line interface for local use.
- **Web API Adapter (Future):** REST or gRPC endpoints for UI integration.
