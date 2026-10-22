"""Literal-text terminal summaries and full JSON for two-file comparison."""

from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text

from packet_investigator.models.capture_file_comparison import (
    CaptureFileComparisonReport,
)
from packet_investigator.renderers.capture_quality import render_capture_quality_rich


def render_capture_comparison_rich(report: CaptureFileComparisonReport) -> None:
    output = Console()
    output.print(Text("Packet Investigator — Two-capture TCP comparison", style="bold"))
    output.print(Text(f"Status: {report.status.upper()}"))
    output.print(
        Text(f"LEFT: {report.left_label} — {report.left_quality.capture.filename}")
    )
    output.print(
        Text(f"RIGHT: {report.right_label} — {report.right_quality.capture.filename}")
    )
    output.print(
        Text(
            f"Clock basis: {report.alignment.basis}; right offset: "
            f"{report.alignment.right_offset_ns} ns; tolerance: "
            f"{report.alignment.tolerance_ns} ns"
        )
    )
    output.print(
        Text(
            "Header correspondences only; no payload identity, proven loss, "
            "network latency, or technical ownership conclusions."
        )
    )
    for label, quality, summary in (
        (report.left_label, report.left_quality, report.left_collection),
        (report.right_label, report.right_quality, report.right_collection),
    ):
        output.print(Text(f"\nCapture quality at {label}", style="bold"))
        render_capture_quality_rich(quality, console=output)
        output.print(
            Text(
                f"TCP collection: {summary.rows_observed} rows; "
                f"{summary.records_retained} retained; "
                f"{summary.malformed_rows} malformed; "
                f"{summary.duplicate_frame_rows} duplicate; "
                f"{summary.capacity_omissions} omitted at capacity."
            )
        )
    result = report.comparison
    if result is not None:
        counts = Counter(x.status.value for x in result.comparisons)
        output.print(Text("\nComparison summary", style="bold"))
        for code, count in sorted(counts.items()):
            output.print(Text(f"{code}: {count}"))
        table = Table(show_lines=False)
        for name in (
            "Point",
            "Frame",
            "Result",
            "Opposite frames",
            "Omitted candidates",
        ):
            table.add_column(name)
        for row in result.comparisons[:50]:
            table.add_row(
                Text(row.observation),
                Text(str(row.header.frame_number)),
                Text(row.status.value),
                Text(", ".join(str(x.frame_number) for x in row.candidates) or "—"),
                Text(str(row.omitted_candidates)),
            )
        output.print(table)
        output.print(
            Text(
                f"Showing {min(50, len(result.comparisons))} of "
                f"{len(result.comparisons)} rows; "
                f"{max(0, len(result.comparisons) - 50)} terminal rows omitted. "
                "JSON includes all tracked rows and sampled header evidence."
            )
        )
    output.print(Text("\nLimitations", style="bold"))
    for limitation in report.limitations + (result.limitations if result else ()):
        output.print(Text(limitation))
    output.print(Text("\nNext capture / verification", style="bold"))
    for recommendation in report.recommendations:
        output.print(Text(recommendation))
