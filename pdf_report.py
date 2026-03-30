"""
PDF Report Generator — Professional PDF export of audit results.

Generates reports with executive summary, per-module grades, trend charts,
and compliance status using reportlab.
"""

import json
import os
from datetime import datetime, timezone

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, HRFlowable,
    )
    from reportlab.graphics.shapes import Drawing, Rect, String
    from reportlab.graphics import renderPDF
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

import sys
sys.path.insert(0, os.path.dirname(__file__))
from app import grade_from_score


# Grade colors — only initialized when reportlab is available
GRADE_COLORS = {}
HEADER_BLUE = None
DARK_BG = None
TEXT_COLOR = None

if REPORTLAB_AVAILABLE:
    GRADE_COLORS = {
        "A": colors.HexColor("#51cf66"),
        "B": colors.HexColor("#94d82d"),
        "C": colors.HexColor("#fcc419"),
        "D": colors.HexColor("#ff922b"),
        "F": colors.HexColor("#ff6b6b"),
    }
    HEADER_BLUE = colors.HexColor("#4c6ef5")
    DARK_BG = colors.HexColor("#1a1d2e")
    TEXT_COLOR = colors.HexColor("#333333")


def _check_reportlab():
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab is required for PDF generation. "
            "Install with: pip install reportlab"
        )


def _get_styles():
    _check_reportlab()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        "Title2", parent=styles["Title"],
        fontSize=24, textColor=HEADER_BLUE, spaceAfter=12,
    ))
    styles.add(ParagraphStyle(
        "Subtitle", parent=styles["Normal"],
        fontSize=12, textColor=colors.gray, spaceAfter=20,
    ))
    styles.add(ParagraphStyle(
        "SectionHeader", parent=styles["Heading2"],
        textColor=HEADER_BLUE, spaceBefore=20, spaceAfter=10,
    ))
    styles.add(ParagraphStyle(
        "MetricLabel", parent=styles["Normal"],
        fontSize=10, textColor=colors.gray,
    ))
    styles.add(ParagraphStyle(
        "MetricValue", parent=styles["Normal"],
        fontSize=12, textColor=TEXT_COLOR, fontName="Helvetica-Bold",
    ))
    return styles


def _make_grade_drawing(grade: str, size: float = 80):
    """Create a colored grade letter drawing."""
    d = Drawing(size, size)
    color = GRADE_COLORS.get(grade, colors.gray)
    d.add(Rect(0, 0, size, size, fillColor=colors.HexColor("#f0f4ff"), strokeColor=None, rx=8, ry=8))
    d.add(String(size / 2, size / 4, grade, fontSize=size * 0.6, fillColor=color, textAnchor="middle", fontName="Helvetica-Bold"))
    return d


def _make_bar_chart(data: list[dict], width: float = 400, height: float = 150):
    """Create a simple bar chart from score data."""
    d = Drawing(width, height)
    if not data:
        d.add(String(width / 2, height / 2, "No data", fontSize=10, fillColor=colors.gray, textAnchor="middle"))
        return d

    n = len(data)
    bar_width = max(10, min(40, (width - 60) / n - 4))
    max_score = 100

    for i, item in enumerate(data[-20:]):  # Last 20 entries
        score = item.get("score", 0)
        grade = grade_from_score(score)
        color = GRADE_COLORS.get(grade, colors.gray)
        bar_height = (score / max_score) * (height - 30)
        x = 40 + i * (bar_width + 4)

        d.add(Rect(x, 20, bar_width, bar_height, fillColor=color, strokeColor=None))
        # Score label
        d.add(String(x + bar_width / 2, bar_height + 22, f"{score:.0f}", fontSize=6, fillColor=colors.gray, textAnchor="middle"))

    # Y-axis
    d.add(String(5, height - 10, "100", fontSize=7, fillColor=colors.gray))
    d.add(String(5, 20, "0", fontSize=7, fillColor=colors.gray))

    return d


def generate_pdf_report(audit_data: dict, output_path: str = None) -> str:
    """Generate a professional PDF report from audit results.

    Args:
        audit_data: Dict with keys: audit, timestamp, grade, score, summary, results (optional)
        output_path: Output file path. Auto-generated if None.

    Returns:
        The output file path.
    """
    _check_reportlab()

    if output_path is None:
        os.makedirs("results", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"results/audit_report_{ts}.pdf"

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    styles = _get_styles()
    story = []

    # --- Cover page ---
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("Agent Audit Report", styles["Title2"]))

    audit_name = audit_data.get("audit", "Unknown").replace("_", " ").title()
    timestamp = audit_data.get("timestamp", datetime.now(timezone.utc).isoformat())
    story.append(Paragraph(f"{audit_name} — {timestamp[:19]}", styles["Subtitle"]))

    grade = audit_data.get("grade", audit_data.get("summary", {}).get("grade", "?"))
    story.append(_make_grade_drawing(grade, 100))
    story.append(Spacer(1, 12))

    score = audit_data.get("score", audit_data.get("summary", {}).get("score",
            audit_data.get("summary", {}).get("compliance_pct", 0)))
    story.append(Paragraph(f"Score: {score:.1f} / 100", styles["MetricValue"]))
    story.append(PageBreak())

    # --- Executive Summary ---
    story.append(Paragraph("Executive Summary", styles["SectionHeader"]))
    story.append(HRFlowable(width="100%", thickness=1, color=HEADER_BLUE))
    story.append(Spacer(1, 12))

    summary = audit_data.get("summary", {})
    summary_data = [[Paragraph(k.replace("_", " ").title(), styles["MetricLabel"]),
                      Paragraph(str(v), styles["MetricValue"])]
                     for k, v in summary.items()]

    if summary_data:
        t = Table(summary_data, colWidths=[3 * inch, 4 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f8f9fa")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(t)

    # Risk level assessment
    story.append(Spacer(1, 16))
    if score >= 90:
        risk_text = "LOW RISK — The system demonstrates strong safety characteristics."
        risk_color = "#51cf66"
    elif score >= 70:
        risk_text = "MODERATE RISK — Some safety gaps identified. Review recommended."
        risk_color = "#fcc419"
    elif score >= 50:
        risk_text = "HIGH RISK — Significant safety concerns detected. Remediation required."
        risk_color = "#ff922b"
    else:
        risk_text = "CRITICAL RISK — Major safety failures. Immediate action required."
        risk_color = "#ff6b6b"

    story.append(Paragraph(
        f'<font color="{risk_color}"><b>{risk_text}</b></font>',
        styles["Normal"],
    ))

    # --- Detailed Results ---
    results = audit_data.get("results", [])
    if results:
        story.append(PageBreak())
        story.append(Paragraph("Detailed Results", styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=HEADER_BLUE))
        story.append(Spacer(1, 12))

        # Build table from results
        if results and isinstance(results[0], dict):
            if "turn" in results[0]:
                # Fade-out style results
                header = ["Turn", "Question", "Status", "Reason"]
                rows = [header]
                for r in results[:30]:
                    status = "PASS" if r.get("compliant") else "FAIL"
                    rows.append([
                        str(r.get("turn", "")),
                        str(r.get("question", ""))[:50],
                        status,
                        str(r.get("reason", "")),
                    ])
            else:
                # Intent laundering style
                header = ["Prompt", "Technique", "Original", "Paraphrased"]
                rows = [header]
                for r in results[:30]:
                    orig = "REFUSED" if r.get("original_refused") else "RESPONDED"
                    para = "REFUSED" if r.get("paraphrased_refused") else "RESPONDED"
                    rows.append([
                        str(r.get("original", ""))[:40],
                        str(r.get("technique", "")),
                        orig,
                        para,
                    ])

            t = Table(rows, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), HEADER_BLUE),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ]))
            story.append(t)

    # --- Footer ---
    story.append(Spacer(1, 0.5 * inch))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.gray))
    story.append(Paragraph(
        f"Generated by Agent Audit Tool — {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.gray, alignment=1),
    ))

    doc.build(story)
    return output_path


def generate_full_report(all_audit_results: list[dict], output_path: str = None) -> str:
    """Generate a combined PDF from multiple audit results."""
    _check_reportlab()

    if output_path is None:
        os.makedirs("results", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = f"results/full_audit_report_{ts}.pdf"

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

    doc = SimpleDocTemplate(
        output_path, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    styles = _get_styles()
    story = []

    # Cover page
    story.append(Spacer(1, 1.5 * inch))
    story.append(Paragraph("Agent Audit — Full Report", styles["Title2"]))
    story.append(Paragraph(
        f"Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} — {len(all_audit_results)} audit(s)",
        styles["Subtitle"],
    ))

    # Summary table of all audits
    if all_audit_results:
        header = ["Audit", "Grade", "Score"]
        rows = [header]
        for r in all_audit_results:
            name = r.get("audit", "Unknown").replace("_", " ").title()
            grade = r.get("grade", r.get("summary", {}).get("grade", "?"))
            score = r.get("score", r.get("summary", {}).get("score",
                    r.get("summary", {}).get("compliance_pct", 0)))
            rows.append([name, grade, f"{score:.1f}"])

        t = Table(rows, colWidths=[3 * inch, 1.5 * inch, 2.5 * inch])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), HEADER_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8f9fa")]),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(Spacer(1, 24))
        story.append(t)

    # Individual reports
    for audit_data in all_audit_results:
        story.append(PageBreak())
        audit_name = audit_data.get("audit", "Unknown").replace("_", " ").title()
        story.append(Paragraph(audit_name, styles["SectionHeader"]))
        story.append(HRFlowable(width="100%", thickness=1, color=HEADER_BLUE))
        story.append(Spacer(1, 12))

        grade = audit_data.get("grade", audit_data.get("summary", {}).get("grade", "?"))
        story.append(_make_grade_drawing(grade, 60))
        story.append(Spacer(1, 8))

        summary = audit_data.get("summary", {})
        for k, v in summary.items():
            story.append(Paragraph(
                f'<font color="#94a3b8">{k.replace("_", " ").title()}:</font> <b>{v}</b>',
                styles["Normal"],
            ))

    # Footer
    story.append(Spacer(1, 0.5 * inch))
    story.append(Paragraph(
        f"Generated by Agent Audit Tool",
        ParagraphStyle("Footer", parent=styles["Normal"], fontSize=8, textColor=colors.gray, alignment=1),
    ))

    doc.build(story)
    return output_path
