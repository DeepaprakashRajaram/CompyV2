"""
WHAT: Reporting Domain Contracts (Hexagonal Port).
WHY: Decouples forensic reporting domain logic from specific PDF/HTML rendering implementations.
OWNS: Port protocols and render result contracts.
DOES NOT OWN: Jinja2, WeasyPrint, Chromium or browser automation logic.
"""

from typing import Protocol, Dict, Any, Optional
from dataclasses import dataclass

@dataclass(frozen=True)
class RenderResult:
    pdf_path: str
    html_path: str
    page_count: int
    renderer_name: str
    file_size_bytes: int

class ReportRendererPort(Protocol):
    """Hexagonal Port for rendering forensic reports."""
    
    def render(
        self,
        report_data: Dict[str, Any],
        output_pdf_path: str,
        output_html_path: Optional[str] = None
    ) -> RenderResult:
        """Renders report data dictionary into PDF and HTML artifacts."""
        ...
