"""
WHAT: Compy V2 CLI Entrypoint.
WHY: First-class command-line interface to the Volatility 3 fileless malware detection engine.
OWNS: Argument parsing, execution orchestration, console progress and findings output, report export.
DOES NOT OWN: Core reasoning logic, Volatility internals.
"""

import sys
import os
import argparse
import hashlib
from pathlib import Path
from typing import Optional, List
from datetime import datetime, timezone

# Ensure src directory is in sys.path and fileless_detector\src is purged
sys.path = [p for p in sys.path if r"fileless_detector\src" not in p and "fileless_detector/src" not in p]
for parent in Path(__file__).resolve().parents:
    if (parent / "fmd").is_dir():
        if str(parent) not in sys.path:
            sys.path.insert(0, str(parent))
        break

from fmd.v2.application.use_cases import AnalyzeMemoryUseCase, AnalyzeMemoryRequest
from fmd.v2.bootstrap import (
    create_v2_app,
    create_demo_app,
    create_real_app,
    is_supported_memory_image,
    SUPPORTED_MEMORY_EXTENSIONS
)
from fmd.v2.domain.contracts import CapabilityStatus, TriState
from fmd.v2.adapters.reporting.html_to_pdf_renderer import HtmlToPdfRenderer
from fmd.v2.adapters.reporting.mapper import dossier_to_report_dict


def compute_file_sha256(filepath: str) -> str:
    """Streams file from disk and computes SHA-256 hash."""
    sha256 = hashlib.sha256()
    with open(filepath, "rb") as f:
        while chunk := f.read(8 * 1024 * 1024):
            sha256.update(chunk)
    return sha256.hexdigest()


def get_human_size(size_bytes: int) -> str:
    """Formats bytes into human readable size."""
    size = float(size_bytes)
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} PB"


def build_v2_app() -> AnalyzeMemoryUseCase:
    """Dependency Injection root delegating to shared bootstrap."""
    return create_v2_app()


def run_analysis_pipeline(
    image_path: Optional[str] = None,
    demo_mode: bool = False,
    output_pdf: Optional[str] = None,
    output_html: Optional[str] = None,
    output_json: Optional[str] = None,
    yara_rules: Optional[str] = None,
    quiet: bool = False
) -> int:
    """
    Programmatic entrypoint for running the Compy analysis pipeline.
    """
    cmd_args: List[str] = []
    if demo_mode:
        cmd_args.append("--demo")
    elif image_path:
        cmd_args.append(str(image_path))
    if output_pdf:
        cmd_args.extend(["-o", str(output_pdf)])
    if output_html:
        cmd_args.extend(["--html", str(output_html)])
    if output_json:
        cmd_args.extend(["--json", str(output_json)])
    if yara_rules:
        cmd_args.extend(["--yara-rules", str(yara_rules)])
    return main(cmd_args, quiet=quiet)


def main(args_list: Optional[List[str]] = None, quiet: bool = False) -> int:
    parser = argparse.ArgumentParser(
        description="Compy V2 (Compsognathus) — Volatility 3 Powered Fileless Malware Detector"
    )
    parser.add_argument(
        "image", 
        nargs="?", 
        default=None, 
        help="Path to target memory image (.raw, .mem, .dmp, .vmem, .bin, .lime)"
    )
    parser.add_argument(
        "-i", "--image-path", 
        dest="flag_image", 
        default=None, 
        help="Alternative flag for memory image path"
    )
    parser.add_argument(
        "--demo", 
        action="store_true", 
        help="Run deterministic synthetic demonstration scenario (isolated demo mode)"
    )
    parser.add_argument(
        "--yara-rules",
        default="rules/yara",
        help="Path to directory containing YARA rules (.yar/.yara) [default: rules/yara]"
    )
    parser.add_argument(
        "-o", "--output", 
        default=None, 
        help="Output PDF report path (e.g., report.pdf)"
    )
    parser.add_argument(
        "--html", 
        default=None, 
        help="Output HTML report path (e.g., report.html)"
    )
    parser.add_argument(
        "--json", 
        default=None, 
        help="Output JSON summary file"
    )

    args = parser.parse_args(args_list)

    target_image = args.image or args.flag_image

    if not quiet:
        print("=" * 70)
        print(" COMPSOGNATHUS (COMPY) — VOLATILITY 3 FILELESS MALWARE DETECTOR")
        print(" Engine: Compy V2 Forensic Engine (Hexagonal Architecture)")
        print("=" * 70)

    if not args.demo and not target_image:
        if not quiet:
            print("[-] Error: No target memory image provided.", file=sys.stderr)
            print("    Usage: python -m fmd.v2.adapters.cli.compy_cli <path/to/memory.raw> [-o report.pdf]", file=sys.stderr)
            print("    Or run demonstration mode with: python -m fmd.v2.adapters.cli.compy_cli --demo", file=sys.stderr)
        return 1

    if args.demo:
        print("[*] Mode: SYNTHETIC DEMONSTRATION (Deterministic Fixtures)")
        print("[*] NOTICE: Results are synthetic fixtures for pipeline verification.")
        use_case = create_demo_app()
        image_name = "synthetic_demo_image.raw"
        image_hash = "0000000000000000000000000000000000000000000000000000000000000000"
        image_size_str = "16.00 GB (Synthetic Demo)"
        is_synthetic = True
    else:
        image_path = Path(target_image).resolve()
        if not image_path.exists():
            if not quiet:
                print(f"[-] Error: Target memory image not found: {image_path}", file=sys.stderr)
            return 2

        if not is_supported_memory_image(str(image_path)):
            if not quiet:
                print(f"[-] Error: Unsupported memory format: {image_path.suffix}", file=sys.stderr)
                print(f"    Supported formats: {', '.join(sorted(SUPPORTED_MEMORY_EXTENSIONS))}", file=sys.stderr)
            return 3

        if not quiet:
            print(f"[*] Target Image: {image_path.name}")
            print(f"[*] Path:         {image_path}")
        size_bytes = os.path.getsize(image_path)
        image_size_str = get_human_size(size_bytes)
        if not quiet:
            print(f"[*] File Size:    {image_size_str}")
            print("[*] Computing SHA-256 evidence integrity hash...")
        image_hash = compute_file_sha256(str(image_path))
        if not quiet:
            print(f"[*] Evidence SHA-256: {image_hash}")
            print("[*] Initializing Volatility 3 forensic collector (LOCAL_ONLY offline policy)...")
        use_case, failure_reason = create_real_app(
            memory_image_path=str(image_path),
            artifact_hash=image_hash,
            yara_rules_dir=args.yara_rules
        )

        if use_case is None:
            if not quiet:
                print(f"[-] Capability Error: {failure_reason}", file=sys.stderr)
            return 4

        image_name = image_path.name
        is_synthetic = False

    # Execute Analysis
    if not quiet:
        print("\n[*] Executing memory analysis pipeline...")
    req = AnalyzeMemoryRequest(
        target_path=str(target_image) if target_image else "demo://memory.raw",
        session_timestamp=datetime.now(timezone.utc)
    )

    try:
        dossier = use_case.execute(req)
    except Exception as e:
        if not quiet:
            print(f"[-] Analysis execution failed: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
        return 5

    # Display Results
    if not quiet:
        print("\n" + "=" * 70)
        print(" INVESTIGATION FINDINGS & VERDICT")
        print("=" * 70)
        status_suffix = ""
        if dossier.system_status == TriState.FALSE:
            status_suffix = " (No Threats Detected Within Executed Scope)"
        elif dossier.system_status == TriState.TRUE:
            status_suffix = " (Malicious Threats Detected)"
        elif dossier.system_status == TriState.UNKNOWN:
            status_suffix = " (Inconclusive / Incomplete Scope)"
        print(f" System Status:      {dossier.system_status.value}{status_suffix}")
    
    # Categorize findings
    tree_anomalies = getattr(dossier, "process_tree_anomalies", [])
    rootkit_anomalies = getattr(dossier, "hidden_process_anomalies", [])
    injected_anomalies = getattr(dossier, "injected_code_anomalies", [])
    yara_anomalies = getattr(dossier, "yara_anomalies", [])
    recommendations = getattr(dossier, "mitigation_recommendations", [])
    failures = getattr(dossier, "capability_failures", [])

    if not quiet:
        print(f"\n [+] Process Tree Anomalies:   {len(tree_anomalies)}")
        for a in tree_anomalies:
            print(f"     - [PID {getattr(a, 'process_pid', '?')}] {getattr(a, 'process_name', '')}: {getattr(a, 'description', '')}")

        print(f"\n [+] Rootkit / DKOM Unlinked: {len(rootkit_anomalies)}")
        for r in rootkit_anomalies:
            print(f"     - [PID {getattr(r, 'process_pid', '?')}] {getattr(r, 'process_name', '')}: {getattr(r, 'description', '')}")

        print(f"\n [+] Memory Injection (VAD):  {len(injected_anomalies)}")
        for inj in injected_anomalies:
            print(f"     - [PID {getattr(inj, 'process_pid', '?')}] {getattr(inj, 'process_name', '')}: {getattr(inj, 'description', '')}")

        print(f"\n [+] YARA Signature Matches:  {len(yara_anomalies)}")
        for y in yara_anomalies:
            rule = getattr(y, "rule_name", "UNKNOWN")
            target = getattr(y, "target_identifier", "TARGET")
            matched = getattr(y, "matched_strings", ())
            print(f"     - [{rule}] on {target} ({len(matched)} match instances): {getattr(y, 'description', '')}")

        if recommendations:
            print(f"\n [+] Evidence-Backed Mitigation Guidance ({len(recommendations)}):")
            for rec in recommendations:
                r_dict = rec.to_dict() if hasattr(rec, "to_dict") else dict(rec)
                auth = " [HUMAN AUTH REQUIRED]" if r_dict.get("human_authorization_required") else ""
                print(f"     - [{r_dict.get('priority')}] [{r_dict.get('action_type')}] {r_dict.get('finding_title')}:")
                print(f"       Action: {r_dict.get('recommended_action')}{auth}")
                print(f"       Prerequisites: {r_dict.get('prerequisites')}")

        if failures:
            print(f"\n [!] Analysis Limitations / Capability Failures ({len(failures)}):")
            for f in failures:
                reason = getattr(f, "failure_reason", str(f))
                status = getattr(f, "status", getattr(f, "_status", "UNKNOWN"))
                print(f"     - [{status}]: {reason}")

    # Generate Reports if requested
    report_dict = dossier_to_report_dict(
        dossier=dossier,
        file_name=image_name,
        file_hash=image_hash,
        file_size=image_size_str,
        is_synthetic_demo=is_synthetic
    )

    if args.json:
        import json
        json_path = Path(args.json)
        json_path.write_text(json.dumps(report_dict, indent=2), encoding="utf-8")
        if not quiet:
            print(f"\n[+] Exported JSON summary to: {json_path}")

    if args.output or args.html:
        renderer = HtmlToPdfRenderer()
        try:
            res = renderer.render(
                report_data=report_dict,
                output_pdf_path=args.output,
                output_html_path=args.html
            )
            if not quiet:
                print(f"\n[+] Report exported successfully:")
                if args.output:
                    print(f"    - PDF:  {res.pdf_path} ({res.file_size_bytes / 1024:.1f} KB)")
                if args.html:
                    print(f"    - HTML: {res.html_path}")
        except Exception as report_e:
            if not quiet:
                print(f"[-] Report generation failed: {report_e}", file=sys.stderr)

    if not quiet:
        print("\n" + "=" * 70)
        print(" COMPY V2 EXECUTION COMPLETE")
        print("=" * 70)
    return 0


if __name__ == "__main__":
    sys.exit(main())
