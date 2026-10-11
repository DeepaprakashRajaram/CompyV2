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
- **Status:** Phase 2 Complete (Advanced Detectors & DFIR Reporting Module).
- **Supported:**
  - **Memory Injection Detection:** RWX VADs, unbacked executable code memory, reflective loading.
  - **Parent-PID / Process Lineage Anomaly Detection:** Office/spoolsv exploit spawns, PPID spoofing (T1134.004), rogue svchost/lsass/csrss parentage, masquerading (T1036).
  - **Hidden Process & Kernel Rootkit Detection:** Cross-view matrix comparing `ActiveProcessLinks` (pslist) against memory pool carving (psscan), PspCidTable, and handle tables; unlinked DKOM processes (T1014); SSDT/IDT/IRP hook checks.
  - **Hexagonal DFIR Report Generator:** Industry-grade, 8–19 page forensic report matching Mandiant / CrowdStrike standards, strictly compliant with Sections 45 & 65B of the Indian Evidence Act, 1872 and CERT-In Incident Guidelines.
  - **Evidence Integrity:** Immutable SHA-256 hash-chained ledger, Tri-State logic (DETECTED / NOT DETECTED / UNKNOWN) with explicit verification worksheets.
  - **100% Offline Generation:** Embedded local vector SVG charts (severity donut, risk gauge, process tree, QR code), zero CDN/network dependencies.

## 4. Installation
Compy requires Python 3.10+.

```powershell
git clone https://github.com/DeepaprakashRajaram/CompyV2.git
cd CompyV2
python -m venv .venv
.\.venv\Scripts\activate
pip install -e .
```

## 5. Web Application Interface
Compy includes a web dashboard providing instant memory analysis and PDF/HTML/JSON report downloads:

```powershell
.\.venv\Scripts\python.exe -m uvicorn fmd.v2.adapters.web.app:app --host 0.0.0.0 --port 8085
```
- Open your browser at: `http://localhost:8085`
- Preview the 19-page DFIR sample report: `http://localhost:8085/report/sample`

## 6. Standalone DFIR Report Generator CLI
Generate an evidence-grade forensic PDF or HTML document from any validated forensic JSON dataset:

```powershell
# Generate PDF and HTML reports from sample forensic data
python generate_report.py sample_report.json -o sample_report.pdf --html sample_report.html
```

Output includes:
1. Cover Page with QR Code, Classification Banner, and Risk Gauge.
2. Document Control, Distribution, and Table of Contents.
3. Executive Summary with Severity Donut Chart and Key Findings.
4. Scope, Objectives & Evidence Cryptographic Hashes (SHA-256/MD5).
5. Methodology & Legal Standards (NIST SP 800-86, ISO/IEC 27037:2012, IEA 65B).
6. Findings Overview Matrix.
7. Process Tree Analysis with Vector Diagram & Anomaly Explanations.
8. Hidden Process & Kernel Rootkit DKOM Cross-View Comparison Matrix.
9. Detailed Findings (Hex dumps, Disassembly, YARA matches, IOCs, Remediation).
10. MITRE ATT&CK Enterprise Matrix Mapping.
11. Consolidated Indicators of Compromise (IOC) Appendix.
12. Attack Timeline.
13. Forensic Risk Scoring Methodology Breakdown.
14. Prioritized Recommendations & Action Plan.
15. Limitations & Assumptions (Smear, Paged Memory, UNKNOWN semantics).
16. Chain of Custody & Hash-Chained Evidence Ledger.
17. Forensic Glossary.
18. Statutory Certificate under Section 65B(4) & Section 45, Indian Evidence Act, 1872.

## 7. Volatility 3 & Symbol Safety Policy
Compy enforces a strict **`LOCAL_ONLY + FAIL_IF_MISSING`** policy for Volatility 3.
- Compy will **never** silently download forensic symbols from the internet.
- Missing required symbols cause a controlled capability failure (`CapabilityStatus.UNAVAILABLE`).
- Users must manually provision compatible symbols to their local Volatility cache legally and securely.
- We do not distribute raw memory images or symbols in this repository.

## 8. Testing
- **Unit & Integration Tests:** Execute via `pytest`:
```powershell
.\.venv\Scripts\pytest.exe
```
All 27 automated tests validate core reasoning, detectors, reporting contracts, Pydantic schemas, and PDF compilation.

## 9. Safety Boundaries
- **Immutability:** The Evidence Ledger is append-only and cryptographically chained.
- **Side-Effects:** Volatility is strictly executed offline.
- **Determinism:** `Investigation ID` generation is mathematically bound to the run identity and artifact hash.
