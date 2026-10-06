# Installation Guide

Compy V2 requires Python 3.10 or higher. 

## 1. Clone the Repository
```powershell
git clone https://github.com/DeepaprakashRajaram/CompyV2.git
cd CompyV2
```

## 2. Environment Setup
Create an isolated Python virtual environment to prevent dependency conflicts.
```powershell
python -m venv .venv
.venv\Scripts\activate
```

## 3. Install Compy
Install Compy in development mode.
```powershell
pip install -e .
```
*Note: This command reads `pyproject.toml` and installs the core dependencies, including `volatility3`.*

## 4. Verify Installation
Ensure the Compy CLI is available:
```powershell
compy
```

## Note on Dependencies
- **Core Dependencies:** `pydantic`, `typer`, `intervaltree`, `volatility3`
- **Optional/Future Dependencies:** YARA, live memory drivers.

## Note on Volatility Symbols
Compy enforces an **Offline-Only** policy for Volatility 3. It will not download symbols from the internet.
You must manually provision the required symbols (ISF files) for your memory dumps into the local Volatility symbol cache. 
If symbols are missing, Compy will gracefully report `CapabilityStatus.UNAVAILABLE`.
