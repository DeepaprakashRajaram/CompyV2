import os
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib.units import inch

from fmd.v2.domain.reasoning.investigation import InvestigationDossier

def generate_forensic_report(
    dossier: InvestigationDossier, 
    file_name: str, 
    file_hash: str, 
    file_size: str, 
    output_path: str
):
    """
    Generates a CERT-In / Indian Evidence Act Section 65B compliant forensic report.
    """
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=40, leftMargin=40,
        topMargin=40, bottomMargin=40
    )
    
    styles = getSampleStyleSheet()
    title_style = styles['Title']
    title_style.fontSize = 16
    h1_style = styles['Heading1']
    h2_style = styles['Heading2']
    h2_style.alignment = 1 # Center align
    normal_style = styles['Normal']
    
    bold_style = ParagraphStyle(
        name='BoldNormal',
        parent=styles['Normal'],
        fontName='Helvetica-Bold'
    )
    
    elements = []
    
    # Header
    elements.append(Paragraph("<b>CONFIDENTIAL - FOR LAW ENFORCEMENT & JUDICIAL USE ONLY</b>", bold_style))
    elements.append(Spacer(1, 0.5 * inch))
    
    elements.append(Paragraph("CYBER FORENSIC ANALYSIS REPORT", title_style))
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(Paragraph("<para align=center>Pursuant to Section 45 & 65B of the Indian Evidence Act, 1872</para>", normal_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    elements.append(Paragraph(f"<b>Investigation ID:</b> {dossier.investigation_id}", normal_style))
    elements.append(Paragraph(f"<b>Date of Report:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')}", normal_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    # 1. Executive Summary
    elements.append(Paragraph("1. Executive Summary", h1_style))
    summary_text = "This report details the forensic analysis of a digital memory dump submitted for investigation. The objective was to determine the presence of fileless malware or related malicious artifacts residing purely in volatile memory."
    elements.append(Paragraph(summary_text, normal_style))
    
    conclusion = dossier.system_status.value
    elements.append(Spacer(1, 0.1 * inch))
    elements.append(Paragraph(f"<b>Primary Finding:</b> System Status is determined as <b>{conclusion}</b> for fileless malware.", bold_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    # 2. Details of Evidence
    elements.append(Paragraph("2. Details of Evidence Analyzed", h1_style))
    
    data = [
        ["Attribute", "Value"],
        ["File Name", file_name],
        ["File Size", file_size],
        ["SHA-256 Hash", file_hash],
        ["Date of Analysis", dossier.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
    ]
    t = Table(data, colWidths=[2 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#ecf0f1")),
        ('GRID', (0, 0), (-1, -1), 1, colors.black)
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.3 * inch))
    
    # 3. Methodology & Tools
    elements.append(Paragraph("3. Methodology and Tools Used", h1_style))
    method_text = "The analysis was conducted using the Compsognathus (Compy) V2 Advanced Fileless Malware Forensic Engine, utilizing Hexagonal Architecture, Tri-State Logic, and Immutable Evidence Ledgers. All analysis was conducted on an isolated forensic workstation in a read-only environment to ensure evidence integrity."
    elements.append(Paragraph(method_text, normal_style))
    elements.append(Spacer(1, 0.3 * inch))
    
    # 4. Forensic Findings
    elements.append(Paragraph("4. Technical Findings", h1_style))
    if not dossier.candidates:
        findings_text = "No suspicious candidates or anomalies were detected in the provided memory dump."
    else:
        findings_text = f"Identified {len(dossier.candidates)} potential candidate(s) requiring verification."
    elements.append(Paragraph(findings_text, normal_style))
    
    if dossier.capability_failures:
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(Paragraph("<b>Note on Constraints:</b> Certain capabilities could not be executed due to missing symbols or unsupported profiles (Fail-Safe mechanism).", normal_style))
        for cf in dossier.capability_failures:
            elements.append(Paragraph(f"- Capability Failure: {cf.status}", normal_style))
            
    elements.append(Spacer(1, 0.3 * inch))
    
    # 5. Section 65B Certificate
    elements.append(PageBreak())
    elements.append(Paragraph("CERTIFICATE UNDER SECTION 65B(4) OF THE INDIAN EVIDENCE ACT, 1872", h2_style))
    elements.append(Spacer(1, 0.4 * inch))
    
    cert_text = (
        "I, [Authorized Examiner Name], [Designation], hereby certify that the electronic record contained in "
        f"the file '{file_name}' (SHA-256 Hash: {file_hash}) was analyzed on a computer system which was operating properly "
        "at all material times. The analysis output represented in this report was generated by the computer "
        "in the ordinary course of lawful forensic activities. To the best of my knowledge and belief, "
        "the conditions under Section 65B(2) of the Indian Evidence Act, 1872 are fulfilled in relation to "
        "the computer system and the electronic records."
    )
    elements.append(Paragraph(cert_text, normal_style))
    elements.append(Spacer(1, 0.8 * inch))
    
    elements.append(Paragraph("______________________________", normal_style))
    elements.append(Paragraph("<b>Signature of Authorized Examiner</b>", normal_style))
    elements.append(Paragraph("Name: ", normal_style))
    elements.append(Paragraph("Designation: Cyber Forensic Analyst", normal_style))
    elements.append(Paragraph("Agency / Lab: ", normal_style))
    
    doc.build(elements)
    return output_path
