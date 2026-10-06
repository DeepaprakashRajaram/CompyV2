# Contributing to Compy V2

Thank you for your interest in contributing to Compsognathus (Compy)!

## Architectural Rules
Any code contributions must strictly adhere to the project's Hexagonal Architecture:
- **Core Domain (`fmd.v2.domain`)**: No dependencies on external frameworks, databases, or UI. Pure Python data classes and interfaces.
- **Application (`fmd.v2.application`)**: Orchestrates the flow of data via use cases. Must not contain forensic detection algorithms.
- **Adapters (`fmd.v2.adapters`)**: Implementations for the CLI, Web API, and Volatility 3.

## Safety Boundaries
- **Immutability**: The Evidence Ledger is append-only. Nodes cannot be mutated once ingested.
- **Volatility Offline Execution**: All Volatility 3 integration MUST enforce `LOCAL_ONLY` and `FAIL_IF_MISSING`. We do not permit silent symbol downloading from the internet under any circumstances.
- **Real Memory**: Never commit `.raw`, `.mem`, or any forensic artifacts.

## Testing
- Run unit tests with `pytest tests/v2`.
- Write unit tests for all new domain logic.
- Do not introduce tests that require private memory images or downloaded symbols.
