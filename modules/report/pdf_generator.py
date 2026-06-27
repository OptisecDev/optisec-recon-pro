from datetime import datetime
from pathlib import Path
from config import REPORTS_DIR, APP_NAME, APP_VERSION, ACCENT_COLOR

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.colors import HexColor, white, black, Color
    from reportlab.lib.units import cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, PageBreak
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


ACCENT = HexColor("#00ff88") if REPORTLAB_AVAILABLE else None
DARK_BG = HexColor("#0d1117") if REPORTLAB_AVAILABLE else None
CARD_BG = HexColor("#161b22") if REPORTLAB_AVAILABLE else None
TEXT_COLOR = HexColor("#e6edf3") if REPORTLAB_AVAILABLE else None

SEVERITY_COLORS = {
    "Critical": "#ff4444",
    "High": "#ff8800",
    "Medium": "#ffcc00",
    "Low": "#00aaff",
    "Info": "#888888",
} if REPORTLAB_AVAILABLE else {}


def generate_report(
    target: str,
    recon_data: dict = None,
    vuln_findings: list = None,
    osint_data: dict = None,
    ai_analysis: str = "",
    output_path: str = None,
) -> str:
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab not installed. Run: pip install reportlab")

    if output_path is None:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = target.replace("://", "_").replace("/", "_").replace(".", "_")
        output_path = str(REPORTS_DIR / f"optisec_report_{safe_target}_{ts}.pdf")

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm,
        leftMargin=2*cm,
        topMargin=2*cm,
        bottomMargin=2*cm,
    )

    styles = getSampleStyleSheet()
    story = []

    title_style = ParagraphStyle(
        "OptisecTitle",
        fontSize=28,
        textColor=ACCENT,
        spaceAfter=6,
        fontName="Helvetica-Bold",
        alignment=TA_CENTER,
    )
    subtitle_style = ParagraphStyle(
        "OptisecSubtitle",
        fontSize=14,
        textColor=TEXT_COLOR,
        spaceAfter=4,
        fontName="Helvetica",
        alignment=TA_CENTER,
    )
    heading_style = ParagraphStyle(
        "OptisecHeading",
        fontSize=16,
        textColor=ACCENT,
        spaceBefore=12,
        spaceAfter=6,
        fontName="Helvetica-Bold",
    )
    body_style = ParagraphStyle(
        "OptisecBody",
        fontSize=10,
        textColor=HexColor("#c9d1d9"),
        spaceAfter=4,
        fontName="Helvetica",
        leading=14,
    )
    meta_style = ParagraphStyle(
        "OptisecMeta",
        fontSize=9,
        textColor=HexColor("#8b949e"),
        fontName="Helvetica",
        alignment=TA_CENTER,
    )

    story.append(Spacer(1, 1*cm))
    story.append(Paragraph(APP_NAME, title_style))
    story.append(Paragraph("Security Assessment Report", subtitle_style))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=2, color=ACCENT))
    story.append(Spacer(1, 0.5*cm))

    story.append(Paragraph(f"Target: {target}", body_style))
    story.append(Paragraph(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", meta_style))
    story.append(Paragraph(f"Version: {APP_VERSION}", meta_style))
    story.append(Spacer(1, 1*cm))

    vuln_findings = vuln_findings or []
    severity_counts = {}
    for f in vuln_findings:
        sev = f.get("severity", "Info")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    story.append(Paragraph("Executive Summary", heading_style))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#30363d")))
    story.append(Spacer(1, 0.3*cm))

    total_vulns = len(vuln_findings)
    story.append(Paragraph(f"Total vulnerabilities discovered: {total_vulns}", body_style))
    for sev, count in sorted(severity_counts.items()):
        story.append(Paragraph(f"  • {sev}: {count}", body_style))

    if recon_data:
        story.append(PageBreak())
        story.append(Paragraph("Reconnaissance Results", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#30363d")))
        story.append(Spacer(1, 0.3*cm))

        if recon_data.get("subdomains"):
            story.append(Paragraph(f"Subdomains Found: {len(recon_data['subdomains'])}", body_style))
            sub_data = [["Subdomain", "IP Address"]]
            for sub in recon_data["subdomains"][:30]:
                sub_data.append([sub.get("subdomain", ""), sub.get("ip", "")])
            t = Table(sub_data, colWidths=[10*cm, 6*cm])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                ("TEXTCOLOR", (0, 0), (-1, 0), black),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("BACKGROUND", (0, 1), (-1, -1), CARD_BG),
                ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_COLOR),
                ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#30363d")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [CARD_BG, HexColor("#0d1117")]),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.5*cm))

        if recon_data.get("dns"):
            story.append(Paragraph("DNS Records", body_style))
            dns_data = [["Record Type", "Value"]]
            for rtype, values in recon_data["dns"].items():
                for val in values:
                    dns_data.append([rtype, val])
            if len(dns_data) > 1:
                t = Table(dns_data, colWidths=[4*cm, 12*cm])
                t.setStyle(TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
                    ("TEXTCOLOR", (0, 0), (-1, 0), black),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("BACKGROUND", (0, 1), (-1, -1), CARD_BG),
                    ("TEXTCOLOR", (0, 1), (-1, -1), TEXT_COLOR),
                    ("GRID", (0, 0), (-1, -1), 0.5, HexColor("#30363d")),
                ]))
                story.append(t)

    if vuln_findings:
        story.append(PageBreak())
        story.append(Paragraph("Vulnerability Findings", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#30363d")))
        story.append(Spacer(1, 0.3*cm))

        for i, finding in enumerate(vuln_findings, 1):
            sev = finding.get("severity", "Info")
            sev_color = HexColor(SEVERITY_COLORS.get(sev, "#888888"))

            sev_style = ParagraphStyle(
                f"Sev_{i}",
                fontSize=11,
                textColor=sev_color,
                fontName="Helvetica-Bold",
                spaceBefore=8,
                spaceAfter=4,
            )
            story.append(Paragraph(f"{i}. [{sev}] {finding.get('type', 'Unknown')}", sev_style))

            detail_data = [
                ["URL", finding.get("url", "")[:80]],
                ["Parameter", finding.get("parameter", "")],
                ["Payload", finding.get("payload", "")[:60]],
                ["Evidence", finding.get("evidence", "")[:80]],
            ]
            t = Table(detail_data, colWidths=[3*cm, 13*cm])
            t.setStyle(TableStyle([
                ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("TEXTCOLOR", (0, 0), (0, -1), HexColor("#8b949e")),
                ("TEXTCOLOR", (1, 0), (1, -1), TEXT_COLOR),
                ("BACKGROUND", (0, 0), (-1, -1), CARD_BG),
                ("GRID", (0, 0), (-1, -1), 0.3, HexColor("#30363d")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.2*cm))

    if ai_analysis:
        story.append(PageBreak())
        story.append(Paragraph("AI Security Analysis", heading_style))
        story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#30363d")))
        story.append(Spacer(1, 0.3*cm))

        for line in ai_analysis.split("\n"):
            if line.strip():
                story.append(Paragraph(line.strip(), body_style))

    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=HexColor("#30363d")))
    story.append(Paragraph(
        f"Generated by {APP_NAME} v{APP_VERSION} | {datetime.now().strftime('%Y-%m-%d')}",
        meta_style
    ))

    doc.build(story)
    return output_path
