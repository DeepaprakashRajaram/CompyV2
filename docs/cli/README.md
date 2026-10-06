# Command Line Interface (CLI)

The Compy CLI is a first-class product interface designed for local, offline forensic analysis.

## Invocation
The CLI is automatically installed when installing the package via `pip install -e .`.
You can run it directly:
```powershell
compy
```

## Current Status (V2.0 Phase 1)
- **Currently Available:** Structural architecture, Mock Providers, Tri-State verification execution, Domain Rules.
- **Designed:** Full pipeline for `AnalyzeMemoryUseCase` through to `EvidenceLedger`.
- **Not Yet Implemented:** The CLI currently uses Mock Providers for demonstration. Passing arbitrary `.mem` files for full Volatility processing is restricted until dynamic localized symbol provisioning is completed (to maintain the strict offline safety boundary).

## Future Roadmap
In future updates, the CLI will allow passing a raw memory image path along with a validated symbol directory to perform complete localized analysis.
