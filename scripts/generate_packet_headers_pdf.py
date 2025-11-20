#!/usr/bin/env python3
"""Generate PACKET_HEADERS.pdf from PACKET_HEADERS.md using ReportLab.
Requires: reportlab
"""
import os
from reportlab.lib.pagesizes import LETTER
from reportlab.pdfgen import canvas
from reportlab.lib.units import inch
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
from reportlab.lib import colors
from reportlab.lib.fonts import addMapping

MD_FILE = "PACKET_HEADERS.md"
PDF_FILE = "PACKET_HEADERS.pdf"

def load_markdown(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def simple_md_to_flowables(md_text: str):
    styles = getSampleStyleSheet()
    body = styles['BodyText']
    body.fontName = 'Helvetica'
    title = styles['Title']
    flow = []
    for line in md_text.splitlines():
        if not line.strip():
            flow.append(Spacer(1, 0.18*inch))
            continue
        if line.startswith('# '):
            p = Paragraph(f"<b>{line[2:].strip()}</b>", title)
        elif line.startswith('## '):
            p = Paragraph(f"<b>{line[3:].strip()}</b>", styles['Heading2'])
        elif line.startswith('- '):
            p = Paragraph(f"• {line[2:].strip()}", body)
        elif line.startswith('* '):
            p = Paragraph(f"• {line[2:].strip()}", body)
        else:
            # Basic emphasis for backticks
            esc = (line.replace('<', '&lt;').replace('>', '&gt;')
                    .replace('`', '<font color="blue">'))
            p = Paragraph(esc, body)
        flow.append(p)
    return flow

def build_pdf(md_text: str, out_path: str):
    doc = SimpleDocTemplate(out_path, pagesize=LETTER,
                            leftMargin=0.75*inch, rightMargin=0.75*inch,
                            topMargin=0.75*inch, bottomMargin=0.75*inch)
    flow = simple_md_to_flowables(md_text)
    doc.build(flow)

if __name__ == "__main__":
    if not os.path.exists(MD_FILE):
        raise SystemExit(f"Missing {MD_FILE}.")
    text = load_markdown(MD_FILE)
    build_pdf(text, PDF_FILE)
    print(f"Generated {PDF_FILE}")
