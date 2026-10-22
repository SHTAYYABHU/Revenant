"""Generate a forensic report from a scan result.

The report is meant to stand on its own as an exhibit. It records the evidence
identity and hashes, summarises what was found, lists every recovered item with
its provenance, and states plainly how each parser works and where it should be
trusted less. The layout reuses the Revenant colours so the report and the tool
feel like one thing.

Prose here is written to read like a person wrote it, since a report that
sounds machine generated invites doubt about the work behind it.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    BaseDocTemplate,
    Frame,
    Image,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    PageBreak,
)

from .models import ArtifactState, ScanResult
from .security import safe_output_path
from ..version import __version__, APP_NAME

log = logging.getLogger("revenant.report")

NAVY = colors.HexColor("#0E2A47")
ACCENT = colors.HexColor("#2E6FB7")
LIGHT = colors.HexColor("#EEF3F8")
MUTED = colors.HexColor("#5A6B7B")
LINE = colors.HexColor("#C9D6E3")

_STATE_COLOUR = {
    ArtifactState.LIVE: colors.HexColor("#3C7D3C"),
    ArtifactState.DELETED: colors.HexColor("#B23A48"),
    ArtifactState.OBSOLETE: colors.HexColor("#B5852A"),
    ArtifactState.ORPHANED: colors.HexColor("#6E5AA6"),
    ArtifactState.CARVED: ACCENT,
}

_MATURITY_NOTE = {
    "littlefs": "Replays every CRC checked commit, follows id shifts, and reads CTZ skip lists, then rebuilds unreferenced chains from their own back pointers. Scored against images made by the reference implementation.",
    "jffs2": "Validates each node with the kernel CRC, replays data nodes in version order so truncation is respected, and keeps each state a later write changed. Validate on nandsim images from the target kernel.",
    "ubifs": "Validates each node CRC and rebuilds files per inode. Live status comes from sequence numbers rather than the on flash index, so treat obsolete labels as a best estimate.",
    "yaffs": "Recovers object headers, names, and deletion markers. Data reassembly needs the spare area tags, which a plain image may not carry.",
    "spiffs": "Parses page headers and deletion flags and rebuilds files by span index. Checked against images made by Espressif's spiffsgen.",
    "signatures": "Finds known file types by their magic bytes anywhere in the image, which covers content the filesystem parsers cannot place.",
}


def _styles():
    ss = getSampleStyleSheet()
    styles = {
        "title": ParagraphStyle("rv_title", parent=ss["Title"], fontName="Helvetica-Bold",
                                 fontSize=26, textColor=NAVY, leading=30, spaceAfter=4),
        "subtitle": ParagraphStyle("rv_sub", parent=ss["Normal"], fontName="Helvetica",
                                   fontSize=12, textColor=MUTED, leading=16),
        "h2": ParagraphStyle("rv_h2", parent=ss["Heading2"], fontName="Helvetica-Bold",
                             fontSize=14, textColor=NAVY, spaceBefore=14, spaceAfter=6),
        "body": ParagraphStyle("rv_body", parent=ss["Normal"], fontName="Helvetica",
                              fontSize=10, textColor=colors.HexColor("#1D2A36"),
                              leading=15, alignment=TA_LEFT, spaceAfter=6),
        "small": ParagraphStyle("rv_small", parent=ss["Normal"], fontName="Helvetica",
                               fontSize=8, textColor=MUTED, leading=11),
        "cell": ParagraphStyle("rv_cell", parent=ss["Normal"], fontName="Helvetica",
                              fontSize=8, textColor=colors.HexColor("#1D2A36"), leading=11),
        "cellmono": ParagraphStyle("rv_mono", parent=ss["Normal"], fontName="Courier",
                                  fontSize=7.5, textColor=colors.HexColor("#1D2A36"), leading=10),
    }
    return styles


class _Doc(BaseDocTemplate):
    """A document template that paints the header band and the page footer."""

    def __init__(self, filename, **kw):
        super().__init__(filename, pagesize=A4,
                         leftMargin=18 * mm, rightMargin=18 * mm,
                         topMargin=24 * mm, bottomMargin=18 * mm, **kw)
        frame = Frame(self.leftMargin, self.bottomMargin,
                      self.width, self.height, id="main")
        self.addPageTemplates([PageTemplate(id="std", frames=[frame], onPage=self._decorate)])

    def _decorate(self, canvas, doc):
        canvas.saveState()
        # A slim accent rule under the top margin ties pages together.
        canvas.setStrokeColor(ACCENT)
        canvas.setLineWidth(2)
        canvas.line(doc.leftMargin, A4[1] - 16 * mm, A4[0] - doc.rightMargin, A4[1] - 16 * mm)
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(MUTED)
        canvas.drawString(doc.leftMargin, 10 * mm, f"{APP_NAME} {__version__}")
        canvas.drawRightString(A4[0] - doc.rightMargin, 10 * mm, f"Page {doc.page}")
        canvas.drawCentredString(A4[0] / 2, 10 * mm, "Recovered data remnant report")
        canvas.restoreState()


def _kv_table(rows, styles):
    data = [[Paragraph(_esc(k), styles["small"]), Paragraph(_esc(str(v)), styles["cell"])] for k, v in rows]
    t = Table(data, colWidths=[42 * mm, 132 * mm])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LINEBELOW", (0, 0), (-1, -1), 0.4, LINE),
    ]))
    return t


def build_report(result: ScanResult, output_dir: str, filename: str = "revenant_report.pdf",
                 audit_entries: Optional[list[dict]] = None,
                 logo_path: Optional[str] = None,
                 include_previews: bool = True) -> Path:
    """Write the report and return its path."""
    out_path = safe_output_path(Path(output_dir), filename)
    styles = _styles()
    story = []

    # Cover block with the logo when we have it.
    if logo_path and Path(logo_path).exists():
        try:
            story.append(Image(logo_path, width=26 * mm, height=26 * mm))
            story.append(Spacer(1, 6))
        except Exception:
            pass
    story.append(Paragraph("Revenant Recovery Report", styles["title"]))
    story.append(Paragraph("Deleted and superseded data remnants recovered from raw flash storage",
                           styles["subtitle"]))
    story.append(Spacer(1, 12))

    case = result.case
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    story.append(_kv_table([
        ("Case", case.case_name),
        ("Examiner", case.examiner or "not recorded"),
        ("Reference", case.reference or "not recorded"),
        ("Report generated", generated),
        ("Engine", f"{APP_NAME} {result.engine_version or __version__}"),
    ] + ([("Case notes", case.notes)] if case.notes else []), styles))

    # Evidence identity and integrity.
    story.append(Paragraph("Evidence", styles["h2"]))
    ev = result.evidence
    story.append(_kv_table([
        ("Source kind", ev.source_kind),
        ("Source", ev.source_path),
        ("Size", f"{ev.size_bytes:,} bytes"),
        ("Acquired", ev.acquired_utc),
        ("Access", "read only" if ev.read_only else "read write"),
        ("SHA-256", ev.sha256 or "not computed"),
        ("MD5", ev.md5 or "not computed"),
    ] + ([("Device", ev.device_path)] if ev.device_path else [])
      + ([("Acquired image", ev.acquired_image)] if ev.acquired_image else [])
      + ([("Acquisition check", "hash of the written image matches the hash taken during the copy"
           if ev.verified else "hash MISMATCH between the copy and the written image")]
         if ev.verified is not None else []), styles))
    story.append(Spacer(1, 4))
    story.append(Paragraph(
        "The source was opened read only and hashed before analysis. The hashes above fix the "
        "state of the evidence at examination time, so the same image can be verified later.",
        styles["small"]))

    # Summary.
    story.append(Paragraph("Summary", styles["h2"]))
    st = result.stats
    by_state = {}
    for a in result.artifacts:
        by_state[a.state] = by_state.get(a.state, 0) + 1
    fs_line = ", ".join(result.detected_filesystems) if result.detected_filesystems else "none identified by structure"
    summary = (
        f"The scan identified {fs_line} and examined {ev.size_bytes:,} bytes in "
        f"{st.duration_seconds:.2f} seconds. It returned {len(result.artifacts)} artifacts in total, "
        f"of which {st.live_count} belong to the live filesystem and {st.recovered_count} were recovered "
        f"from obsolete, deleted, orphaned, or unallocated regions. The recovered items are the point of "
        f"the exercise, since they represent data the device no longer presents through its filesystem."
    )
    if st.merged_duplicates == 1:
        summary += (" One signature find duplicated content that a filesystem parser had already recovered "
                    "with a name and a state, so it was folded into that record.")
    elif st.merged_duplicates > 1:
        summary += (f" A further {st.merged_duplicates} signature finds duplicated content that filesystem "
                    f"parsers had already recovered with names and states, so they were folded into those records.")
    if st.cancelled:
        summary += " The examiner cancelled this scan before it finished, so the result is partial."
    story.append(Paragraph(summary, styles["body"]))

    counts = [["State", "Count", "Meaning"]]
    meanings = {
        ArtifactState.LIVE: "part of the active filesystem",
        ArtifactState.DELETED: "removed from the filesystem, content recovered",
        ArtifactState.OBSOLETE: "an earlier version later superseded",
        ArtifactState.ORPHANED: "data with no surviving name",
        ArtifactState.CARVED: "found by raw signature scan",
    }
    for state in [ArtifactState.DELETED, ArtifactState.OBSOLETE, ArtifactState.ORPHANED,
                  ArtifactState.CARVED, ArtifactState.LIVE]:
        if by_state.get(state):
            counts.append([
                Paragraph(f'<font color="{_hx(_STATE_COLOUR[state])}">{state.value}</font>', styles["cell"]),
                Paragraph(str(by_state[state]), styles["cell"]),
                Paragraph(meanings[state], styles["cell"]),
            ])
    ct = Table(counts, colWidths=[30 * mm, 20 * mm, 124 * mm])
    ct.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 9),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
        ("GRID", (0, 0), (-1, -1), 0.4, LINE),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    story.append(Spacer(1, 6))
    story.append(ct)

    # Recovered items table.
    story.append(Paragraph("Recovered items", styles["h2"]))
    recovered = result.recovered()
    if not recovered:
        story.append(Paragraph("No recovered remnants were found in this image.", styles["body"]))
    else:
        story.append(Paragraph(
            "Every row below is an item that is not part of the live filesystem. The offset points to "
            "the source record in the image and the hash fixes the recovered bytes.", styles["small"]))
        header = ["Name", "FS", "State", "Conf", "Offset", "Size", "SHA-256 (first 16)"]
        table_data = [header]
        for a in recovered[:400]:
            table_data.append([
                Paragraph(_esc(a.path or a.name), styles["cell"]),
                Paragraph(a.filesystem, styles["cell"]),
                Paragraph(f'<font color="{_hx(_STATE_COLOUR[a.state])}">{a.state.value}</font>', styles["cell"]),
                Paragraph(a.confidence.value, styles["cell"]),
                Paragraph(f"0x{a.offset:x}", styles["cellmono"]),
                Paragraph(f"{a.size:,}", styles["cell"]),
                Paragraph((a.sha256 or "")[:16], styles["cellmono"]),
            ])
        rt = Table(table_data, colWidths=[42 * mm, 16 * mm, 18 * mm, 14 * mm, 24 * mm, 18 * mm, 42 * mm],
                   repeatRows=1)
        rt.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("GRID", (0, 0), (-1, -1), 0.3, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(Spacer(1, 4))
        story.append(rt)
        if len(recovered) > 400:
            story.append(Paragraph(f"Showing the first 400 of {len(recovered)} recovered items.", styles["small"]))

    # Previews for the most interesting recovered content.
    if include_previews and recovered:
        story.append(PageBreak())
        story.append(Paragraph("Recovered content previews", styles["h2"]))
        story.append(Paragraph(
            "A short printable preview of recovered items, with non printable bytes shown as dots. "
            "Deleted and obsolete items come first, since those carry the most weight.", styles["small"]))
        story.append(Spacer(1, 6))
        priority = sorted(recovered, key=lambda a: (
            {ArtifactState.DELETED: 0, ArtifactState.OBSOLETE: 1,
             ArtifactState.ORPHANED: 2, ArtifactState.CARVED: 3}.get(a.state, 4)))
        for a in priority[:40]:
            if not a.data:
                continue
            head = (f'<b>{_esc(a.path or a.name)}</b>  <font color="{_hx(_STATE_COLOUR[a.state])}">'
                    f'[{a.state.value}]</font>  {a.filesystem}  {a.size:,} bytes')
            story.append(Paragraph(head, styles["cell"]))
            preview = _esc(a.preview_text(300))
            story.append(Paragraph(f'<font face="Courier" size="7.5">{preview}</font>', styles["cellmono"]))
            if a.note:
                story.append(Paragraph(_esc(a.note), styles["small"]))
            story.append(Spacer(1, 6))

    # Method and limitations, written honestly per parser.
    story.append(PageBreak())
    story.append(Paragraph("Method and limitations", styles["h2"]))
    story.append(Paragraph(
        "Revenant reads the raw image and recovers remnants filesystem by filesystem. It never writes to "
        "the source. The notes below describe how far to trust each parser, which matters because some "
        "flash filesystems give up their history more readily than others.", styles["body"]))
    used = list(dict.fromkeys([a.filesystem for a in result.artifacts]))
    for fs in used:
        note = _MATURITY_NOTE.get(fs, "")
        if note:
            story.append(Paragraph(f"<b>{fs}</b>. {note}", styles["body"]))
    story.append(Paragraph(
        "Recovery figures should be read against a known ground truth. The controlled test images that "
        "ship with the tool have an exact record of what was deleted, so they give a fair measure of "
        "recall. Content pulled from real firmware only tells you the parser reads the format, not how "
        "much of a real deletion history it can bring back.", styles["small"]))

    # Chain of custody from the audit trail.
    if audit_entries:
        story.append(Paragraph("Chain of custody", styles["h2"]))
        story.append(Paragraph(
            "The tool recorded each step of this examination with a timestamp. The trail holds sizes and "
            "hashes rather than recovered content, so it can be shared without exposing the data itself.",
            styles["small"]))
        aud = [["Time (UTC)", "Action", "Detail"]]
        for e in audit_entries[:120]:
            aud.append([
                Paragraph(e.get("when_utc", "")[:19], styles["cellmono"]),
                Paragraph(_esc(e.get("action", "")), styles["cell"]),
                Paragraph(_esc(e.get("detail", "")), styles["cell"]),
            ])
        at = Table(aud, colWidths=[38 * mm, 34 * mm, 102 * mm], repeatRows=1)
        at.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 8),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, LIGHT]),
            ("GRID", (0, 0), (-1, -1), 0.3, LINE),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
            ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ]))
        story.append(Spacer(1, 4))
        story.append(at)

    doc = _Doc(str(out_path))
    doc.build(story)
    log.info("wrote report to %s", out_path)
    return out_path


def _hx(color) -> str:
    # reportlab font tags want a hash prefixed hex string, hexval gives 0xrrggbb.
    return "#" + color.hexval()[2:8]


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;"))
