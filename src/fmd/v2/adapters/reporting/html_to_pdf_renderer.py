"""
WHAT: HTML to PDF Forensic Report Renderer Adapter.
WHY: Implements the ReportRendererPort using Jinja2 and Headless Chromium/Edge.
OWNS: Template rendering, inline CSS injection, SVG embedding, and headless PDF compilation.
DOES NOT OWN: Forensic investigation domain models.
"""

import os
import subprocess
import shutil
from typing import Dict, Any, Optional
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

from fmd.v2.domain.reporting.contracts import ReportRendererPort, RenderResult
from fmd.v2.domain.reporting.models import ForensicReportModel
from fmd.v2.adapters.reporting.svg_charts import (
    generate_donut_chart,
    generate_risk_gauge,
    generate_process_tree_svg,
    generate_qr_code_svg
)

class HtmlToPdfRenderer(ReportRendererPort):
    """
    Hexagonal Adapter that transforms forensic JSON data into an industry-grade PDF
    via Jinja2 and Chromium/Edge Headless print-to-pdf engine.
    """

    def __init__(self, template_dir: Optional[str] = None, static_dir: Optional[str] = None):
        base_dir = Path(__file__).resolve().parent
        self.template_dir = Path(template_dir) if template_dir else base_dir / "templates"
        self.static_dir = Path(static_dir) if static_dir else base_dir / "static"
        
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=select_autoescape(['html', 'xml'])
        )
        self.browser_executable = self._locate_browser_executable()

    def _locate_browser_executable(self) -> str:
        """Locates available Edge or Chrome binary on the host."""
        candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            shutil.which("msedge"),
            shutil.which("chrome"),
            shutil.which("google-chrome")
        ]
        for c in candidates:
            if c and os.path.exists(c):
                return c
        raise RuntimeError("No headless Chromium/Edge browser executable found for PDF generation.")

    def render(
        self,
        report_data: Dict[str, Any],
        output_pdf_path: str,
        output_html_path: Optional[str] = None
    ) -> RenderResult:
        """
        Validates data, injects inline charts and CSS, and renders the PDF artifact.
        """
        # 1. Schema Validation (Pydantic)
        validated_model = ForensicReportModel.model_validate(report_data)
        data_dict = validated_model.model_dump()

        # 2. Load Design System CSS
        css_file = self.static_dir / "report.css"
        css_content = css_file.read_text(encoding="utf-8") if css_file.exists() else ""

        # 3. Generate Inline Vector SVGs
        counts = data_dict.get("summary", {}).get("counts_by_severity", {})
        donut_svg = generate_donut_chart(counts)

        risk_score = data_dict.get("summary", {}).get("risk_score", 0)
        risk_gauge_svg = generate_risk_gauge(risk_score)

        process_tree = data_dict.get("process_tree", [])
        process_tree_svg = generate_process_tree_svg(process_tree)

        case_id = data_dict.get("case", {}).get("id", "CASE-000")
        sha256 = data_dict.get("evidence", {}).get("sha256", "UNKNOWN")
        qr_code_svg = generate_qr_code_svg(f"{case_id}:{sha256[:16]}")

        # 4. Render Master HTML
        template = self.jinja_env.get_template("report.html.j2")
        rendered_html = template.render(
            data=data_dict,
            css_content=css_content,
            donut_svg=donut_svg,
            risk_gauge_svg=risk_gauge_svg,
            process_tree_svg=process_tree_svg,
            qr_code_svg=qr_code_svg
        )

        # 5. Output HTML file
        out_pdf = Path(output_pdf_path).resolve()
        out_pdf.parent.mkdir(parents=True, exist_ok=True)
        
        if not output_html_path:
            out_html = out_pdf.with_suffix(".html")
        else:
            out_html = Path(output_html_path).resolve()
            out_html.parent.mkdir(parents=True, exist_ok=True)
            
        out_html.write_text(rendered_html, encoding="utf-8")

        # 6. Execute Headless Chromium Print-to-PDF
        cmd = [
            self.browser_executable,
            "--headless=new",
            "--disable-gpu",
            "--no-sandbox",
            "--run-all-compositor-stages-before-draw",
            f"--print-to-pdf={str(out_pdf)}",
            "--no-pdf-header-footer",
            str(out_html)
        ]
        
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0 and not out_pdf.exists():
            # Fallback to standard --headless flag if --headless=new fails
            cmd[1] = "--headless"
            subprocess.run(cmd, capture_output=True, text=True, timeout=60)

        if not out_pdf.exists():
            raise RuntimeError(f"Headless print failed to generate PDF. Stderr: {proc.stderr}")

        # 7. Compute exact page count via PyMuPDF / PyPDF
        page_count = 0
        try:
            import fitz
            doc = fitz.open(str(out_pdf))
            page_count = len(doc)
            doc.close()
        except Exception:
            try:
                from pypdf import PdfReader
                reader = PdfReader(str(out_pdf))
                page_count = len(reader.pages)
            except Exception:
                page_count = 1

        file_size = out_pdf.stat().st_size

        return RenderResult(
            pdf_path=str(out_pdf),
            html_path=str(out_html),
            page_count=page_count,
            renderer_name=Path(self.browser_executable).stem,
            file_size_bytes=file_size
        )
