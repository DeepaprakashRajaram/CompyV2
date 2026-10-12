# Compsognathus (Compy) V2

**Practical Fileless Malware Memory Forensics & Detection System**

Compsognathus (Compy) is an evidence-backed, production-grade memory forensics application engineered to detect, classify, and mitigate fileless malware in volatile system memory (RAM). Powered by **Volatility 3** and **YARA**, Compy integrates deep memory inspection with a strictly immutable Evidence Ledger, deterministic Tri-State verdict logic, hexagonal architecture, and an automated forensic reporting engine.

---

## 1. Core Architecture & Philosophy

Compy V2 adheres strictly to a **Hexagonal Architecture (Ports and Adapters)**:
- **Core Domain:** Immutable Evidence Ledger, Domain Nodes, Corroboration Engine, Tri-State Verdict Logic (`DETECTED`, `NOT DETECTED`, `UNKNOWN`), and Evidence-Backed Mitigation Engine.
- **Application Layer:** Isolated Use Cases (`AnalyzeMemoryUseCase`) and the `SessionCoordinator`.
- **Adapters (Inbound):** CLI (`compy_cli.py`), Web Application Dashboard (`app.py`), and standalone Report CLI (`generate_report.py`).
- **Adapters (Outbound):** Volatility 3 Collector (`VolatilityCollector`), Multi-Engine YARA Scanner (`YaraScanner`), and DFIR Multi-Format Renderer (`HtmlToPdfRenderer` / PyMuPDF / WeasyPrint).

### Design Invariants
1. **Offline & Fail-Closed:** Strict `LOCAL_ONLY + FAIL_IF_MISSING` symbol resolution policy. Compy never connects to the internet or downloads symbols dynamically during forensic evaluation. If required symbols or plugins are missing, the system emits an explicit `UNAVAILABLE` or `PARTIAL` status—never a false negative.
2. **Immutable Audit Trail:** Every ingested artifact and pipeline outcome is cryptographically sealed into an SHA-256 hash-chained ledger.
3. **Evidence-Linked Mitigation:** Containment recommendations strictly trace back to verified findings, prioritizing non-destructive steps and enforcing human authorization gates.

---

## 2. Key Capabilities & Detectors

| Capability | Module / Detector | Description | MITRE ATT&CK |
| :--- | :--- | :--- | :--- |
| **Process Lineage Analysis** | `ppid_tree_anomaly_detector` | Audits parent-child relationships, identifies anomalous exploit spawns (e.g. `winword.exe` spawning `powershell.exe`), and flags PPID spoofing. | T1134.004, T1059 |
| **Rootkit & DKOM Detection** | `rootkit_dkom_detector` | Performs cross-view differential analysis between active linked processes (`pslist` / `ActiveProcessLinks`) and physical memory pool carving (`psscan`). Discovers unlinked processes. | T1014 |
| **YARA Signature Scanning** | `yara_signature_scanner` | Multi-engine YARA scanning across extracted memory VAD injections and process command lines. Features native `yara-python` acceleration with automatic pure-Python fallback. | T1055, T1059.001 |
| **Memory Injection Scanner** | `vad_injection_scanner` | Inspects Virtual Address Descriptors for unbacked executable memory (`PAGE_EXECUTE_READWRITE`), reflective DLL loading, and shellcode execution. | T1055.001 |
| **Mitigation Guidance** | `MitigationEngine` | Generates prioritized (`IMMEDIATE`, `SHORT_TERM`, `STRATEGIC`), actionable containment procedures linked to verified evidence nodes. | Non-destructive DFIR |
| **DFIR Report Generation** | `HtmlToPdfRenderer` | Produces comprehensive multi-page PDF, HTML, and JSON reports with embedded vector charts, IOC appendices, and statutory certificates. | ISO/IEC 27037, IEA 65B |

---

## 3. Installation & Prerequisites

Compy requires **Python 3.10+**.

```powershell
# Clone or navigate to the repository
git clone https://github.com/DeepaprakashRajaram/CompyV2.git
cd CompyV2

# Set up Python virtual environment
python -m venv .venv
.\.venv\Scripts\activate

# Install dependencies in editable mode
pip install -e .
```

---

## 4. CLI Usage

Compy provides a unified command-line interface (`compy_cli.py`) supporting both real volatile memory dumps and synthetic demonstration runs.

### Real Memory Dump Analysis
```powershell
python src/fmd/v2/adapters/cli/compy_cli.py C:\Path\To\dump.raw `
    --os windows `
    --yara-rules rules/yara `
    -o forensic_report.pdf `
    --html forensic_report.html `
    --json forensic_report.json
```

### Synthetic Pipeline Demonstration
Run the pipeline against built-in synthetic fixtures to verify reporting and detector reasoning:
```powershell
python src/fmd/v2/adapters/cli/compy_cli.py --demo `
    -o sample_report.pdf `
    --html sample_report.html `
    --json sample_report.json
```

### Standalone DFIR Report Compilation
Render high-fidelity PDF and HTML reports directly from any exported forensic JSON document:
```powershell
python generate_report.py sample_report.json -o custom_report.pdf --html custom_report.html
```

---

## 5. Web Application Dashboard

Compy features an interactive web interface offering real-time memory analysis, progress tracking, live detector card telemetry, and one-click report downloads.

### Starting the Web Server
Run using the provided batch launcher or directly via Uvicorn:
```powershell
# Option A: Run the batch script
.\start_web_app.bat

# Option B: Run via uvicorn directly
python -m uvicorn fmd.v2.adapters.web.app:app --host 127.0.0.1 --port 8085
```

- **Dashboard UI:** Open your browser to `http://localhost:8085`
- **Instant Demo:** Click **Run Instant Demo Analysis** on the home page to test all four indicator modules in seconds.
- **Sample DFIR Report Preview:** Access the pre-compiled forensic report at `http://localhost:8085/report/sample`
- **Upload Analysis:** Upload `.raw`, `.dmp`, `.vmem`, or `.img` memory artifacts for automated analysis.

---

## 6. YARA Signature Rules

Compy ships with built-in YARA detection rules in `rules/yara/`:
- `memory_injection.yar`: Identifies Cobalt Strike Beacon reflectors, Meterpreter reverse TCP stagers, process hollowing loaders, and early bird injection primitives.
- `download_cradles.yar`: Flags fileless download cradles, hidden PowerShell execution flags (`-W Hidden -Enc`), Mshta JavaScript execution, and certutil encoded payload decoders.

Custom rule directories can be passed to the CLI via `--yara-rules <path>` or configured in the engine.

---

## 7. Volatility 3 & Symbol Policy

Compy enforces a strict **`LOCAL_ONLY`** symbol policy:
- Compy will **never** connect to Microsoft Symbol Servers or external networks during forensic processing.
- Required Windows symbols must be populated in the local Volatility symbol cache directory ahead of time.
- If required symbols are missing, Compy terminates the affected detector gracefully and reports `CapabilityStatus.UNAVAILABLE`, ensuring no unverified assumptions or false negatives are produced.

---

## 8. Verification & Test Suite

Compy includes an extensive test suite verifying hexagonal contracts, Volatility adapters, YARA scanners, mitigation generation, and DFIR report compilation:

```powershell
# Run the entire V2 test suite
python -m pytest tests/v2
```

All 72 tests execute deterministically offline without network calls or external dependencies.
