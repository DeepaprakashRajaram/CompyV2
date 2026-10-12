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
    Generates a digital forensic artifact analysis report
    featuring comprehensive Parent-PID and Rootkit (DKOM) analysis.
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
    h3_style = styles['Heading3']
    normal_style = styles['Normal']
    
    bold_style = ParagraphStyle(
        name='BoldNormal',
        parent=styles['Normal'],
        fontName='Helvetica-Bold'
    )

    alert_style = ParagraphStyle(
        name='AlertStyle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        textColor=colors.HexColor("#c0392b")
    )

    pass_style = ParagraphStyle(
        name='PassStyle',
        parent=styles['Normal'],
        fontName='Helvetica',
        textColor=colors.HexColor("#27ae60")
    )
    
    elements = []
    
    # ---------------------------------------------------------
    # HEADER
    # ---------------------------------------------------------
    elements.append(Paragraph("<b>CONFIDENTIAL - FORENSIC EXAMINATION RECORD</b>", alert_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    elements.append(Paragraph("DIGITAL FORENSIC EXAMINATION REPORT", title_style))
    elements.append(Spacer(1, 0.05 * inch))
    elements.append(Paragraph("<para align=center>Automated Memory Forensic Analysis</para>", normal_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    meta_data = [
        ["Investigation ID", dossier.investigation_id, "Date of Report", datetime.now().strftime('%Y-%m-%d %H:%M:%S IST')],
        ["Forensic Engine", "Compy V2 (FMD-Engine)", "Standard", "Deterministic Memory Forensics"]
    ]
    meta_table = Table(meta_data, colWidths=[1.8 * inch, 2.0 * inch, 1.4 * inch, 2.0 * inch])
    meta_table.setStyle(TableStyle([
        ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
        ('FONTSIZE', (0, 0), (-1, -1), 8),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTNAME', (2, 0), (2, -1), 'Helvetica-Bold'),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor("#2c3e50")),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 0.25 * inch))
    
    # ---------------------------------------------------------
    # 1. EXECUTIVE SUMMARY
    # ---------------------------------------------------------
    elements.append(Paragraph("1. Executive Summary", h1_style))
    summary_text = (
        "A volatile memory (RAM) dump was acquired and submitted for digital forensic examination to "
        "identify active fileless malware, anomalous execution ancestry, and stealth kernel-level rootkits. "
        "Analysis was performed deterministically using Hexagonal Forensics, immutable evidence ledgers, and Tri-State logic."
    )
    elements.append(Paragraph(summary_text, normal_style))
    elements.append(Spacer(1, 0.1 * inch))
    
    status_val = dossier.system_status.value
    if status_val == "TRUE":
        status_banner = "<b>VERDICT: MALICIOUS THREAT DETECTED (TRUE)</b>"
        b_color = colors.HexColor("#c0392b")
    elif status_val == "FALSE":
        status_banner = "<b>VERDICT: NO THREATS DETECTED (EXECUTED SCOPE)</b>"
        b_color = colors.HexColor("#27ae60")
    else:
        status_banner = "<b>VERDICT: INCONCLUSIVE / UNKNOWN (FURTHER SYMBOLS REQUIRED)</b>"
        b_color = colors.HexColor("#f39c12")

    banner_data = [[Paragraph(f"<para align=center><font color='white' size=11>{status_banner}</font></para>", normal_style)]]
    banner_table = Table(banner_data, colWidths=[7.2 * inch])
    banner_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), b_color),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
    ]))
    elements.append(banner_table)
    elements.append(Spacer(1, 0.25 * inch))
    
    # ---------------------------------------------------------
    # 2. EVIDENCE CUSTODY & INTEGRITY
    # ---------------------------------------------------------
    elements.append(Paragraph("2. Details of Evidence Analyzed", h1_style))
    data = [
        ["Forensic Attribute", "Recorded Value"],
        ["Submitted Artifact Name", file_name],
        ["Calculated File Size", file_size],
        ["Cryptographic Hash (SHA-256)", file_hash],
        ["Analysis Timestamp", dossier.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')],
        ["Integrity Verification", "Cryptographically Bound to Ledger Run Identity"]
    ]
    t = Table(data, colWidths=[2.5 * inch, 4.7 * inch])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 9),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
        ('TOPPADDING', (0, 0), (-1, -1), 5),
        ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f8f9fa")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7"))
    ]))
    elements.append(t)
    elements.append(Spacer(1, 0.25 * inch))
    
    # ---------------------------------------------------------
    # 3. FORENSIC FINDINGS - PROCESS TREE & PPID ANOMALIES
    # ---------------------------------------------------------
    elements.append(Paragraph("3. Process Lineage & PPID Spoofing Analysis", h1_style))
    ppid_anomalies = dossier.process_tree_anomalies
    
    if ppid_anomalies:
        elements.append(Paragraph(
            "<b>ALERT:</b> The following processes exhibit unauthorized parent-child relationships, masquerading, or exploit spawn lineage:",
            alert_style
        ))
        elements.append(Spacer(1, 0.1 * inch))
        
        ppid_headers = ["PID", "Process Name", "PPID", "Parent Name", "Category", "Triage Score"]
        ppid_rows = [ppid_headers]
        for obs in ppid_anomalies:
            ppid_rows.append([
                str(getattr(obs, "process_pid", "-")),
                str(getattr(obs, "process_name", "-")),
                str(getattr(obs, "ppid", "-")),
                str(getattr(obs, "actual_parent", "-")),
                str(getattr(obs, "anomaly_category", "-")),
                f"{obs.confidence:.2f}"
            ])
        
        ppid_table = Table(ppid_rows, colWidths=[0.8 * inch, 1.8 * inch, 0.8 * inch, 1.5 * inch, 1.5 * inch, 0.8 * inch])
        ppid_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#c0392b")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fdf2e9"))
        ]))
        elements.append(ppid_table)
    else:
        elements.append(Paragraph(
            "<b>[PASS]</b> All analyzed processes conform strictly to standard Windows operating system baseline parent-child hierarchies. No PPID spoofing or suspicious exploit spawns detected.",
            pass_style
        ))
    elements.append(Spacer(1, 0.25 * inch))

    # ---------------------------------------------------------
    # 4. FORENSIC FINDINGS - ROOTKIT & HIDDEN PROCESSES (DKOM)
    # ---------------------------------------------------------
    elements.append(Paragraph("4. Stealth Rootkit & DKOM Analysis (pslist vs. psscan)", h1_style))
    hidden_anomalies = dossier.hidden_process_anomalies
    
    if hidden_anomalies:
        elements.append(Paragraph(
            "<b>ALERT:</b> The following processes were carved from physical memory pools (psscan) but were unlinked from the active process list (pslist) to evade detection (Direct Kernel Object Manipulation):",
            alert_style
        ))
        elements.append(Spacer(1, 0.1 * inch))
        
        rootkit_headers = ["PID", "Process Name", "PPID", "Active Threads", "Detection Status", "Triage Score"]
        rootkit_rows = [rootkit_headers]
        for obs in hidden_anomalies:
            rootkit_rows.append([
                str(getattr(obs, "process_pid", "-")),
                str(getattr(obs, "process_name", "-")),
                str(getattr(obs, "ppid", "-")),
                str(getattr(obs, "thread_count", "-")),
                "UNLINKED (DKOM)",
                f"{obs.confidence:.2f}"
            ])
            
        rootkit_table = Table(rootkit_rows, colWidths=[0.8 * inch, 2.0 * inch, 0.8 * inch, 1.2 * inch, 1.6 * inch, 0.8 * inch])
        rootkit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#8e44ad")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#f4ecf7"))
        ]))
        elements.append(rootkit_table)
    else:
        elements.append(Paragraph(
            "<b>[PASS]</b> 100% correlation verified between active linked processes (pslist) and physical pool tag carving (psscan). No hidden or unlinked DKOM processes detected.",
            pass_style
        ))
    elements.append(Spacer(1, 0.25 * inch))

    # ---------------------------------------------------------
    # 5. IN-MEMORY INJECTION & TECHNICAL AUDIT
    # ---------------------------------------------------------
    elements.append(Paragraph("5. Memory Injection & Verification Audit", h1_style))
    if dossier.verification_conclusion:
        elements.append(Paragraph(f"<b>Verification Rationale:</b> {dossier.verification_conclusion.rationale}", normal_style))
    else:
        elements.append(Paragraph("No verification candidates required auditing.", normal_style))

    # ---------------------------------------------------------
    # 6. YARA SIGNATURE MATCHES
    # ---------------------------------------------------------
    elements.append(Paragraph("6. YARA Signature Rule Matches", h1_style))
    yara_matches = getattr(dossier, "yara_anomalies", [])
    if yara_matches:
        elements.append(Paragraph(
            "<b>ALERT:</b> The following validated YARA signatures matched against memory segments or process command-lines:",
            alert_style
        ))
        elements.append(Spacer(1, 0.1 * inch))
        yara_headers = ["Rule Name", "PID", "Target", "Namespace", "Confidence"]
        yara_rows = [yara_headers]
        for ym in yara_matches:
            yara_rows.append([
                str(getattr(ym, "rule_name", "-")),
                str(getattr(ym, "process_pid", "-") or "-"),
                str(getattr(ym, "target_type", "-")),
                str(getattr(ym, "namespace", "-")),
                f"{getattr(ym, 'confidence', 1.0):.2f}"
            ])
        yara_table = Table(yara_rows, colWidths=[2.2 * inch, 0.8 * inch, 1.8 * inch, 1.4 * inch, 1.0 * inch])
        yara_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#d35400")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#fef5e7"))
        ]))
        elements.append(yara_table)
    else:
        elements.append(Paragraph(
            "<b>[PASS]</b> No active YARA memory injection or cradle signatures matched against target memory artifacts.",
            pass_style
        ))
    elements.append(Spacer(1, 0.25 * inch))

    # ---------------------------------------------------------
    # 7. MITIGATION GUIDANCE
    # ---------------------------------------------------------
    elements.append(Paragraph("7. Evidence-Backed Mitigation Guidance", h1_style))
    mitigations = getattr(dossier, "mitigation_recommendations", [])
    if mitigations:
        elements.append(Paragraph(
            "<b>RECOMMENDED ACTIONS:</b> Prioritized, non-destructive mitigation guidance based on verified forensic findings:",
            normal_style
        ))
        elements.append(Spacer(1, 0.1 * inch))
        mit_headers = ["Priority", "Action Type", "Title", "Human Auth", "Prerequisites"]
        mit_rows = [mit_headers]
        for m in mitigations:
            mit_rows.append([
                str(getattr(m, "priority", "-")),
                str(getattr(m, "action_type", "-")),
                Paragraph(str(getattr(m, "title", "-")), normal_style),
                "YES" if getattr(m, "requires_human_auth", True) else "NO",
                Paragraph(str(getattr(m, "prerequisites", "-")), normal_style)
            ])
        mit_table = Table(mit_rows, colWidths=[1.0 * inch, 1.2 * inch, 2.2 * inch, 0.8 * inch, 2.0 * inch])
        mit_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#2980b9")),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#bdc3c7")),
            ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor("#ebf5fb"))
        ]))
        elements.append(mit_table)
    else:
        elements.append(Paragraph(
            "No containment or remediation actions required.",
            normal_style
        ))
    elements.append(Spacer(1, 0.25 * inch))

    # ---------------------------------------------------------
    # 8. TECHNICAL EXAMINATION STATEMENT & DISCLAIMER
    # ---------------------------------------------------------
    elements.append(PageBreak())
    elements.append(Paragraph("8. Technical Examination Statement & Admissibility Notice", h2_style))
    elements.append(Spacer(1, 0.2 * inch))
    
    cert_text = (
        "This document represents automated technical reasoning generated by the Compsognathus Forensic Engine "
        f"operating upon memory image artifact '{file_name}' (SHA-256 Hash: {file_hash}). "
        "The software does not establish legal admissibility, prove physical acquisition provenance, or independently satisfy "
        "statutory chain of custody requirements. Formal legal admissibility (such as under Section 65B/45 of the Indian Evidence Act, "
        "Federal Rule of Evidence 902, or equivalent jurisdictional standards) requires physical acquisition verification and "
        "attestation by authorized human forensic personnel."
    )
    elements.append(Paragraph(cert_text, normal_style))
    elements.append(Spacer(1, 0.4 * inch))
    
    elements.append(Paragraph("<b>Report Attestation:</b> Automated Software Generation. No human operator credentials supplied.", normal_style))
    elements.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", normal_style))
    
    doc.build(elements)
    return output_path
