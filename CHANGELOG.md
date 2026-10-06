# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]
### Added
- V2 Core Domain: Immutable Evidence Ledger, Tri-State logic.
- Application Layer: SessionCoordinator, AnalyzeMemoryUseCase.
- Adapters: Initial Volatility 3 provider with strict Offline/No-Download safety boundaries.
- Adapters: CLI Entrypoint.
- Extensive test coverage for V2 domain and contracts.

### Changed
- Repository restructured from Web App Handoff to Complete Installable Product.
- Dependency management isolated.

### Fixed
- P0-1 Corroboration Double Counting.
- P0-2 Temporal Evidence Loss.
- P0-3 Verifier Evidence Sufficiency.
