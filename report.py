#!/usr/bin/env python3

import os
from datetime import datetime
from collections import Counter

from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)

TOOL_VERSION = "1.0"

SEVERITY_COLOR = {
    "Critical": colors.HexColor("#d32f2f"),
    "High":     colors.HexColor("#f57c00"),
    "Medium":   colors.HexColor("#f9a825"),
    "Low":      colors.HexColor("#388e3c"),
    "Info":     colors.HexColor("#1565c0"),
}

REMEDIATION_NOTES = {
    "Critical": "Apply the vendor patch immediately. Isolate the affected host from the network until remediation is confirmed.",
    "High":     "Schedule patching within 7 days. Review firewall rules to limit exposure of the affected service.",
    "Medium":   "Patch within 30 days. Verify service configuration follows vendor hardening guidelines.",
    "Low":      "Address in the next maintenance window. Monitor logs for exploitation attempts.",
    "Info":     "Review for compliance purposes. No immediate action required.",
}


def _styles():
    base = getSampleStyleSheet()
    custom = {
        "title":    ParagraphStyle("ReportTitle",   parent=base["Title"],    fontSize=22, spaceAfter=6),
        "h1":       ParagraphStyle("H1",             parent=base["Heading1"], fontSize=14, spaceBefore=14, spaceAfter=4),
        "h2":       ParagraphStyle("H2",             parent=base["Heading2"], fontSize=11, spaceBefore=10, spaceAfter=3),
        "normal":   base["Normal"],
        "small":    ParagraphStyle("Small",          parent=base["Normal"],   fontSize=8),
        "bold":     ParagraphStyle("Bold",           parent=base["Normal"],   fontName="Helvetica-Bold"),
        "meta":     ParagraphStyle("Meta",           parent=base["Normal"],   fontSize=9, textColor=colors.grey),
    }
    return custom


def _table_style(header_color=colors.HexColor("#37474f")):
    return TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0),  header_color),
        ("TEXTCOLOR",    (0, 0), (-1, 0),  colors.white),
        ("FONTNAME",     (0, 0), (-1, 0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0),  9),
        ("FONTSIZE",     (0, 1), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f5f5f5")]),
        ("GRID",         (0, 0), (-1, -1), 0.4, colors.HexColor("#cccccc")),
        ("VALIGN",       (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING",  (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING",   (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ])


def generate_report(target: str, scan_results: list[dict], output_dir: str = ".") -> str:
    timestamp   = datetime.now().strftime("%Y%m%d_%H%M%S")
    scan_date   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    safe_target = target.replace("/", "_").replace(".", "_")
    filename    = f"scan_{safe_target}_{timestamp}.pdf"
    filepath    = os.path.join(output_dir, filename)
    os.makedirs(output_dir, exist_ok=True)

    doc   = SimpleDocTemplate(filepath, pagesize=letter,
                               leftMargin=0.75*inch, rightMargin=0.75*inch,
                               topMargin=0.75*inch, bottomMargin=0.75*inch)
    s     = _styles()
    story = []
    W     = doc.width

    # ------------------------------------------------------------------ #
    # Section 1: Header
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Network Scan Report", s["title"]))
    story.append(Spacer(1, 4))

    meta_rows = [
        ["Target",       target],
        ["Scan Date",    scan_date],
        ["Duration",     "N/A"],
        ["Tool Version", TOOL_VERSION],
    ]
    meta_table = Table(meta_rows, colWidths=[1.4*inch, W - 1.4*inch])
    meta_table.setStyle(TableStyle([
        ("FONTNAME",  (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE",  (0, 0), (-1, -1), 9),
        ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#37474f")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("TOPPADDING",    (0, 0), (-1, -1), 3),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 16))

    # ------------------------------------------------------------------ #
    # Section 2: Executive Summary
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Executive Summary", s["h1"]))

    all_cves     = [cve for r in scan_results for cve in r.get("cves", [])]
    sev_counts   = Counter(c["severity"] for c in all_cves)
    open_ports   = len(scan_results)
    total_cves   = len(all_cves)

    summary_rows = [["Metric", "Count"]]
    summary_rows.append(["Open Ports", str(open_ports)])
    summary_rows.append(["Total CVEs Found", str(total_cves)])
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        count = sev_counts.get(sev, 0)
        summary_rows.append([f"  {sev}", str(count)])

    summary_table = Table(summary_rows, colWidths=[3*inch, 1.2*inch])
    sty = _table_style()
    for i, row in enumerate(summary_rows[1:], start=1):
        sev_label = row[0].strip()
        if sev_label in SEVERITY_COLOR:
            sty.add("TEXTCOLOR", (0, i), (0, i), SEVERITY_COLOR[sev_label])
            sty.add("FONTNAME",  (0, i), (0, i), "Helvetica-Bold")
    summary_table.setStyle(sty)
    story.append(summary_table)
    story.append(Spacer(1, 16))

    # ------------------------------------------------------------------ #
    # Section 3: Open Ports Table
    # ------------------------------------------------------------------ #
    story.append(Paragraph("Open Ports", s["h1"]))

    ports_rows = [["Port", "Service", "Banner Preview"]]
    for r in sorted(scan_results, key=lambda x: x["port"]):
        banner_preview = (r.get("banner") or "")[:80]
        ports_rows.append([
            f"{r['port']}/tcp",
            r.get("service", "unknown"),
            Paragraph(banner_preview, s["small"]),
        ])

    col_w = [0.7*inch, 1.1*inch, W - 1.8*inch]
    ports_table = Table(ports_rows, colWidths=col_w)
    ports_table.setStyle(_table_style())
    story.append(ports_table)
    story.append(Spacer(1, 16))

    # ------------------------------------------------------------------ #
    # Section 4: CVE Findings Table
    # ------------------------------------------------------------------ #
    story.append(Paragraph("CVE Findings", s["h1"]))

    if not all_cves:
        story.append(Paragraph("No CVEs matched any discovered banners.", s["normal"]))
    else:
        cve_rows = [["CVE ID", "Service", "CVSS", "Severity", "Description"]]
        for r in sorted(scan_results, key=lambda x: x["port"]):
            for cve in r.get("cves", []):
                sev   = cve.get("severity", "Info")
                color = SEVERITY_COLOR.get(sev, colors.black)
                cve_rows.append([
                    Paragraph(f'<font color="#{color.hexval()[2:]}">{cve["cve_id"]}</font>', s["small"]),
                    r.get("service", "unknown"),
                    str(cve.get("cvss_score", "")),
                    Paragraph(f'<font color="#{color.hexval()[2:]}">{sev}</font>', s["small"]),
                    Paragraph(cve.get("description", ""), s["small"]),
                ])

        col_w = [0.95*inch, 0.8*inch, 0.45*inch, 0.65*inch, W - 2.85*inch]
        cve_table = Table(cve_rows, colWidths=col_w)
        cve_table.setStyle(_table_style())
        story.append(cve_table)

    story.append(Spacer(1, 16))

    # ------------------------------------------------------------------ #
    # Section 5: Remediation Notes
    # ------------------------------------------------------------------ #
    story.append(PageBreak())
    story.append(Paragraph("Remediation Notes", s["h1"]))

    if not all_cves:
        story.append(Paragraph("No remediation required based on current scan results.", s["normal"]))
    else:
        seen = set()
        for r in sorted(scan_results, key=lambda x: x["port"]):
            for cve in r.get("cves", []):
                cve_id = cve["cve_id"]
                if cve_id in seen:
                    continue
                seen.add(cve_id)

                sev   = cve.get("severity", "Info")
                color = SEVERITY_COLOR.get(sev, colors.black)
                note  = REMEDIATION_NOTES.get(sev, "Review and remediate at earliest opportunity.")

                story.append(Paragraph(
                    f'<font color="#{color.hexval()[2:]}" name="Helvetica-Bold"><b>{cve_id}</b></font>'
                    f' &mdash; {sev} (CVSS {cve.get("cvss_score", "N/A")})',
                    s["bold"]
                ))
                story.append(Paragraph(
                    f'<b>Affected software:</b> {", ".join(cve.get("affected_software", []))}',
                    s["small"]
                ))
                story.append(Paragraph(note, s["normal"]))
                story.append(Spacer(1, 8))

    doc.build(story)
    print(f"Report saved: {filepath}")
    return filepath


# ------------------------------------------------------------------ #
# CLI for standalone use
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    import json
    import sys

    SAMPLE = [
        {
            "host": "192.168.1.1", "port": 22, "service": "ssh",
            "banner": "SSH-2.0-OpenSSH_7.4",
            "cves": [{
                "cve_id": "CVE-2016-6210", "description": "User enumeration via timing in OpenSSH before 7.4.",
                "cvss_score": 5.9, "severity": "Medium", "affected_software": ["openssh", "7.4"]
            }]
        },
        {
            "host": "192.168.1.1", "port": 80, "service": "http",
            "banner": "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6",
            "cves": [{
                "cve_id": "CVE-2017-7679", "description": "mod_mime heap overflow in Apache HTTP Server 2.4.x before 2.4.26.",
                "cvss_score": 9.8, "severity": "Critical", "affected_software": ["apache", "2.4.6"]
            }]
        },
    ]

    target     = sys.argv[1] if len(sys.argv) > 1 else "192.168.1.1"
    output_dir = sys.argv[2] if len(sys.argv) > 2 else "."
    generate_report(target, SAMPLE, output_dir)
