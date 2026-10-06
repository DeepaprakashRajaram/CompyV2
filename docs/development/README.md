# Development Guide

Welcome to Compy V2 development.

## Project Structure
- `src/fmd/v2/domain/`: Core forensic models, interfaces, and logic.
- `src/fmd/v2/application/`: Orchestration and Use Cases.
- `src/fmd/v2/adapters/`: Interfaces to Volatility, CLI, Web API.
- `tests/v2/`: All V2 tests.

## Running Tests
Tests are built with `pytest`. Execute the test suite using:
```powershell
pytest tests/v2
```
All tests in the default suite use Mock Providers. They run quickly and safely on any machine.

### Real Memory Validation
Tests and validation scripts that require real memory (e.g., `Gate 3 Validation`) are isolated. Do NOT include real memory dumps (`.raw`, `.mem`) in Git.
If you need to validate against real memory:
1. Ensure your local Volatility cache is populated.
2. Run explicit, manual validation scripts (e.g., `run_gate3.py`).

## Adding a New Detector
1. Implement the `IDetector` interface in `fmd.v2.domain.contracts`.
2. Define your `required_capabilities()`.
3. If capabilities are missing, return a `CapabilityStatus.UNAVAILABLE` result, NOT a false positive.
4. Ensure your detector operates entirely on the `ILedgerQuery` interface. No direct provider calls are allowed.
