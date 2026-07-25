#!/usr/bin/env python3
"""Reproducible generator for semantics/lakearch.pdf from semantics/lakearch.md.

CLAUDE.md macht das Neugenerieren der PDF bei jeder Änderung von lakearch.md
verbindlich. Dieses Skript ist die eine, checked-in Quelle dieser Erzeugung —
es deutet den Inhalt nicht, es setzt ihn nur.

Usage:
    python3 -m venv .venv && . .venv/bin/activate
    pip install reportlab
    python3 semantics/build_pdf.py            # -> semantics/lakearch.pdf

Es werden ausschließlich lokal vorhandene Fonts eingebettet:
  * Body  = FreeSerif  (deckt die Notationsglyphe „⊳" U+22B3 sowie ⊃ ∈ ↔ ₁ ₂ …)
  * Head  = DejaVu Sans (Titel, §-Überschriften, Untertitel, Seitenfuß)
  * Mono  = DejaVu Sans Mono (Inline-Code, falls vorhanden)
FreeSerif ist Times-metrisch und entspricht optisch dem serifen Fließtext.
"""

import os
import re
import sys

from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_JUSTIFY, TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    HRFlowable,
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
)

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "lakearch.md")
OUT = os.path.join(HERE, "lakearch.pdf")

# --- palette (matches the established look: navy headings, serif body) ----------
NAVY = HexColor(0x2C3E50)
INK = HexColor(0x1A1A1A)
GREY = HexColor(0x7F8891)
RULE = HexColor(0xCCCCCC)

# --- font resolution: first existing candidate per face, coverage-safe ----------
# No hardcoded single path: each face lists the known distro locations of the very
# same font file (Debian/Ubuntu first, then Fedora/RHEL, then Arch). first-match
# wins, so the build stays instance-neutral and portable without changing metrics.
def _dirs(*names):
    roots = (
        "/usr/share/fonts/truetype/freefont", "/usr/share/fonts/gnu-free",
        "/usr/share/fonts/truetype/dejavu", "/usr/share/fonts/dejavu",
        "/usr/share/fonts/TTF", "/usr/local/share/fonts", "/usr/share/fonts",
    )
    return [os.path.join(r, n) for n in names for r in roots]


_CANDIDATES = {
    "Body": _dirs("FreeSerif.ttf"),
    "Body-Bold": _dirs("FreeSerifBold.ttf"),
    "Body-Italic": _dirs("FreeSerifItalic.ttf"),
    "Body-BoldItalic": _dirs("FreeSerifBoldItalic.ttf"),
    "Head": _dirs("DejaVuSans.ttf"),
    "Head-Bold": _dirs("DejaVuSans-Bold.ttf"),
    "Mono": _dirs("DejaVuSansMono.ttf"),
}


def _register_fonts():
    for name, paths in _CANDIDATES.items():
        path = next((p for p in paths if os.path.exists(p)), None)
        if path is None:
            sys.exit(f"missing font for face {name!r}; tried {paths}")
        pdfmetrics.registerFont(TTFont(name, path))
    pdfmetrics.registerFontFamily(
        "Body", normal="Body", bold="Body-Bold",
        italic="Body-Italic", boldItalic="Body-BoldItalic",
    )
    pdfmetrics.registerFontFamily(
        "Head", normal="Head", bold="Head-Bold", italic="Head", boldItalic="Head-Bold",
    )
    # verify the one non-negotiable glyph is embeddable
    if ord("⊳") not in pdfmetrics.getFont("Body").face.charToGlyph:
        sys.exit("resolved Body font does not cover ⊳ (U+22B3)")


# --- styles ---------------------------------------------------------------------
def _styles():
    return {
        "title": ParagraphStyle("title", fontName="Head-Bold", fontSize=25,
                                leading=29, textColor=NAVY, spaceAfter=5),
        "subtitle": ParagraphStyle("subtitle", fontName="Head", fontSize=9,
                                   leading=13, textColor=GREY, spaceAfter=2),
        "h2": ParagraphStyle("h2", fontName="Head-Bold", fontSize=14, leading=18,
                             textColor=NAVY, spaceBefore=15, spaceAfter=3),
        "body": ParagraphStyle("body", fontName="Body", fontSize=10.3, leading=14.6,
                               textColor=INK, alignment=TA_JUSTIFY, spaceAfter=3.5),
        "indent": ParagraphStyle("indent", fontName="Body", fontSize=10.3,
                                 leading=14.6, textColor=INK, alignment=TA_JUSTIFY,
                                 leftIndent=16, spaceAfter=3.5),
        "bullet": ParagraphStyle("bullet", fontName="Body", fontSize=10.3,
                                 leading=14.6, textColor=INK, alignment=TA_LEFT,
                                 leftIndent=16, bulletIndent=4, spaceAfter=3.5),
    }


# --- inline markdown -> reportlab mini-HTML -------------------------------------
def inline(s: str) -> str:
    s = s.replace("&nbsp;", " ")
    s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    s = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", s)
    s = re.sub(r"\*(.+?)\*", r"<i>\1</i>", s)
    s = re.sub(r"`(.+?)`", r'<font face="Mono" size="9.3">\1</font>', s)
    return s


# --- document assembly ----------------------------------------------------------
def build_story(text: str, st: dict) -> list:
    story = [Spacer(1, 14 * mm)]
    for raw in text.splitlines():
        line = raw.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith("# "):
            story.append(Paragraph(inline(line[2:]), st["title"]))
        elif line.startswith("> "):
            story.append(Paragraph(inline(line[2:]).upper(), st["subtitle"]))
            story.append(Spacer(1, 5 * mm))
        elif line.startswith("## "):
            story.append(KeepTogether([
                Paragraph(inline(line[3:]), st["h2"]),
                HRFlowable(width="100%", thickness=0.6, color=RULE,
                           spaceBefore=2, spaceAfter=7),
            ]))
        elif line.startswith("### "):
            story.append(Paragraph(inline(line[4:]), st["h2"]))
        elif line.strip() == "---":
            story.append(HRFlowable(width="100%", thickness=0.5, color=RULE,
                                    spaceBefore=8, spaceAfter=9))
        elif line.startswith("- "):
            story.append(Paragraph(inline(line[2:]), st["bullet"], bulletText="•"))
        elif line.startswith("&nbsp;"):
            stripped = re.sub(r"^(?:&nbsp;)+", "", line)
            story.append(Paragraph(inline(stripped), st["indent"]))
        else:
            story.append(Paragraph(inline(line), st["body"]))
    return story


class NumberedCanvas(canvas.Canvas):
    """Two-pass canvas so the footer can print 'page / total'."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved = []

    def showPage(self):
        self._saved.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        total = len(self._saved)
        for state in self._saved:
            self.__dict__.update(state)
            self.setFont("Head", 8)
            self.setFillColor(GREY)
            self.drawCentredString(A4[0] / 2.0, 12 * mm,
                                   f"{self._pageNumber} / {total}")
            super().showPage()
        super().save()


def main():
    _register_fonts()
    with open(SRC, encoding="utf-8") as fh:
        text = fh.read()
    doc = SimpleDocTemplate(
        OUT, pagesize=A4,
        leftMargin=23 * mm, rightMargin=23 * mm,
        topMargin=20 * mm, bottomMargin=18 * mm,
        title="lakearch — Das Datenmodell", author="lakearch",
        subject="Regelwerk", creator="semantics/build_pdf.py (reportlab)",
    )
    doc.build(build_story(text, _styles()), canvasmaker=NumberedCanvas)
    print(f"wrote {OUT} ({os.path.getsize(OUT)} bytes)")


if __name__ == "__main__":
    main()
