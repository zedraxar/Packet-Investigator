"""Local graphical engineer brief; no network assets or remote fonts."""

from io import BytesIO
from typing import Any
from xml.sax.saxutils import escape

from packet_investigator.engineer_brief import EngineerBrief
from packet_investigator.report_output import ReportOutputError


def render_engineer_pdf(brief: EngineerBrief) -> bytes:
    """Render complete PDF bytes before safe no-overwrite publication."""
    try:
        from reportlab.lib import colors  # type: ignore[import-untyped]
        from reportlab.lib.styles import ParagraphStyle  # type: ignore[import-untyped]
        from reportlab.platypus import (  # type: ignore[import-untyped]
            HRFlowable,
            KeepTogether,
            PageBreak,
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as error:
        raise ReportOutputError(
            "PDF export is unavailable in this build. Use text or JSON export."
        ) from error
    navy, teal = colors.HexColor("#142D40"), colors.HexColor("#007F83")
    muted, pale = colors.HexColor("#526979"), colors.HexColor("#EDF4F6")
    title = ParagraphStyle(
        "title",
        fontName="Helvetica-Bold",
        fontSize=24,
        leading=28,
        textColor=navy,
        spaceAfter=12,
    )
    heading = ParagraphStyle(
        "heading",
        fontName="Helvetica-Bold",
        fontSize=11,
        leading=14,
        textColor=navy,
        spaceBefore=11,
        spaceAfter=5,
    )
    body = ParagraphStyle(
        "body",
        fontName="Helvetica",
        fontSize=9,
        leading=13,
        textColor=navy,
        spaceAfter=6,
        wordWrap="CJK",
    )
    small = ParagraphStyle(
        "small", parent=body, fontSize=7.5, leading=10, textColor=muted
    )

    def p(value: str, style: Any = body) -> Any:
        # Preserve unsupported filename characters as readable ASCII escapes.
        text = value.encode("ascii", "backslashreplace").decode("ascii")
        return Paragraph(escape(text).replace("\n", "<br/>"), style)

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=(612, 792),
        leftMargin=42,
        rightMargin=42,
        topMargin=40,
        bottomMargin=45,
        title="Packet Investigator - Engineer brief",
        author="Packet Investigator",
        pageCompression=1,
    )
    story: list[Any] = [
        p("PACKET INVESTIGATOR  /  ENGINEER BRIEF", small),
        p("Evidence before conclusions", title),
        p(f"{brief.capture.filename} | {brief.evidence_source}", small),
    ]
    if brief.capture.start_time and brief.capture.end_time:
        story.append(
            p(
                f"Capture window: {brief.capture.start_time.isoformat()} to "
                f"{brief.capture.end_time.isoformat()} | "
                f"TShark {brief.capture.tshark_version}",
                small,
            )
        )
    duration = (
        f"{brief.capture.duration_seconds:.2f} s"
        if brief.capture.duration_seconds is not None
        else "Unavailable"
    )
    cards = Table(
        [
            [
                p(f"{brief.capture.packet_count:,}\nPACKETS", heading),
                p(duration + "\nCAPTURE WINDOW", heading),
                p(f"{brief.tcp_total}\nTCP CONVERSATIONS", heading),
                p(f"{brief.dns_total}\nDNS TRANSACTIONS", heading),
            ]
        ],
        colWidths=[132] * 4,
    )
    cards.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, -1), pale),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.extend(
        (
            Spacer(1, 10),
            cards,
            p("Investigation context - supplied by the engineer", heading),
            p(
                f"Symptom: {brief.context.symptom.value} | "
                f"Target: {brief.context.target or 'All observed traffic'}"
            ),
            p(
                f"Client: {brief.context.client_ip or 'Not specified'} | "
                f"Capture point: {brief.context.capture_point.value}"
            ),
            p("Focus and relevance", heading),
        )
    )
    story.extend(p(line) for line in brief.focus_basis)
    focused_tcp = (
        str(brief.focused_tcp) if brief.focused_tcp is not None else "Unestablished"
    )
    focused_dns = (
        str(brief.focused_dns) if brief.focused_dns is not None else "Unestablished"
    )
    story.append(
        p(
            f"Focused evidence: {focused_tcp} TCP conversations; {focused_dns} DNS "
            "transactions. Background evidence remains in the full report.",
            small,
        )
    )
    story.append(p("DNS response evidence in the selected scope", heading))
    total = brief.focused_dns or 0
    matched = min(total, brief.dns_matched)
    width = 528 * matched / total if total else 0
    segments = []
    if width > 0:
        segments.append((width, teal))
    if width < 528:
        segments.append((528 - width, colors.HexColor("#D8E3E8")))
    bar = Table(
        [[""] * len(segments)], colWidths=[x[0] for x in segments], rowHeights=[12]
    )
    bar.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (i, 0), (i, 0), color)
                for i, (_, color) in enumerate(segments)
            ]
        )
    )
    story.extend(
        (
            bar,
            Spacer(1, 5),
            p(
                (
                    f"{matched} / {total} DNS exchanges include query and response. "
                    "Visible exchange completeness is not application health."
                    if total
                    else "No focused classic DNS observed. Cached or encrypted "
                    "DNS can be outside capture visibility."
                ),
                small,
            ),
        )
    )
    if brief.dns_response_codes:
        names = {0: "NOERROR", 3: "NXDOMAIN"}
        story.append(
            p(
                "Response observations: "
                + "; ".join(
                    f"{names.get(code, 'Code ' + str(code))}: {count}"
                    for code, count in brief.dns_response_codes
                ),
                small,
            )
        )
    story.append(p("What deserves attention", heading))
    for finding in brief.findings[:2]:
        story.append(
            KeepTogether(
                [
                    p(finding.title, heading),
                    p(finding.observation),
                    p(finding.interpretation, small),
                ]
            )
        )
    story.extend(
        (
            PageBreak(),
            p("Limits and next capture", title),
            p("This is evidence from one observation point, not a root-cause verdict."),
            HRFlowable(width="100%", thickness=2, color=colors.HexColor("#B16A12")),
            p("What remains uncertain", heading),
        )
    )
    story.extend(p("- " + limitation) for limitation in brief.limitations)
    if len(brief.findings) > 2:
        story.append(p("Additional focused observations", heading))
        for finding in brief.findings[2:]:
            story.append(p(finding.title + ": " + finding.observation))
    story.append(p("Evidence references", heading))
    for finding in brief.findings:
        if finding.source_ids:
            story.append(
                p(
                    f"{finding.title}: {', '.join(finding.source_ids)}; frames "
                    + ", ".join(map(str, finding.frames)),
                    small,
                )
            )
    story.append(p("Recommended next steps", heading))
    story.extend(p(f"{i}. {step}") for i, step in enumerate(brief.next_steps, 1))
    story.append(
        p(
            "Full evidence stays in the text/JSON report. Filenames, endpoint "
            "addresses and names can be sensitive; review before sharing.",
            small,
        )
    )

    def footer(canvas: Any, document: Any) -> None:
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(muted)
        canvas.drawString(
            42, 25, "LOCAL ANALYSIS | No root-cause or ownership determination"
        )
        canvas.drawRightString(570, 25, str(document.page))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
