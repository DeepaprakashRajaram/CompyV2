#!/usr/bin/env python3
"""
Compy V2 Forensic Engine - Senior DFIR Report Generation CLI.
Usage:
    python generate_report.py sample_report.json -o report.pdf
"""

import sys
import json
import argparse
from pathlib import Path

# Add src to python path for standalone execution
project_root = Path(__file__).resolve().parent
src_dir = project_root / "src"
if str(src_dir) not in sys.path:
    sys.path.insert(0, str(src_dir))

from fmd.v2.adapters.reporting.html_to_pdf_renderer import HtmlToPdfRenderer

def main():
    parser = argparse.ArgumentParser(
        description="Compy V2 Digital Forensic Report Generator (DFIR Report Standards)"
    )
    parser.add_argument("input_json", help="Path to validated forensic JSON file (e.g. sample_report.json)")
    parser.add_argument("-o", "--output", default="report.pdf", help="Output PDF file path (default: report.pdf)")
    parser.add_argument("--html", default=None, help="Optional output HTML file path")
    
    args = parser.parse_args()
    
    json_path = Path(args.input_json)
    if not json_path.exists():
        print(f"[-] Error: Input JSON file not found: {json_path}", file=sys.stderr)
        sys.exit(1)
        
    try:
        report_data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[-] Error: Failed to parse JSON document: {e}", file=sys.stderr)
        sys.exit(1)
        
    print("=" * 65)
    print(" COMPY V2 FORENSIC ENGINE // DFIR REPORT GENERATOR")
    print(" Standard: DFIR Report Generation & Technical Findings Declaration")
    print("=" * 65)
    print(f"[*] Ingesting forensic data: {json_path.name}")
    print(f"[*] Case ID: {report_data.get('case', {}).get('id', 'N/A')}")
    print(f"[*] Target Evidence: {report_data.get('evidence', {}).get('filename', 'N/A')}")
    
    renderer = HtmlToPdfRenderer()
    try:
        res = renderer.render(
            report_data=report_data,
            output_pdf_path=args.output,
            output_html_path=args.html
        )
        print("\n[+] REPORT GENERATION SUCCESSFUL")
        print(f"[+] Output PDF:   {res.pdf_path}")
        print(f"[+] Output HTML:  {res.html_path}")
        print(f"[+] Total Pages:  {res.page_count} A4 Pages")
        print(f"[+] File Size:    {res.file_size_bytes / 1024:.1f} KB")
        print(f"[+] PDF Engine:   {res.renderer_name}")
        print("=" * 65)
    except Exception as e:
        print(f"[-] Report generation failed: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(2)

if __name__ == "__main__":
    main()
