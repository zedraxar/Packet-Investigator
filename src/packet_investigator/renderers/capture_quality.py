"""Rich terminal and JSON rendering for capture-quality assessments."""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.text import Text

from packet_investigator.models.capture_quality import (
    CaptureLimitation,
    CaptureQualityAssessment,
    CaptureQualityFinding,
    CaptureQualityStatus,
    CaptureRecommendation,
)
from packet_investigator.utils.formatting import format_file_size

_EvidenceValue = int | float | str | bool | None


def render_capture_quality_rich(
    assessment: CaptureQualityAssessment,
    *,
    console: Console | None = None,
) -> None:
    """Render an existing assessment to a Rich console."""
    output = console if console is not None else Console()

    output.print(Text("Packet Investigator — Capture Quality", style="bold"))
    output.print(Text(f"Capture: {assessment.capture.filename}", style="bold"))
    output.print(
        Text(
            f"Overall status: {_status_label(assessment.status)}",
            style=_status_style(assessment.status),
        )
    )
    output.print(Text(assessment.status_summary))

    _print_section(output, "Capture metadata")
    output.print(_capture_table(assessment))

    _print_section(output, "Statistics")
    output.print(_statistics_table(assessment))

    if assessment.findings:
        _print_section(output, "Findings")
        for index, finding in enumerate(assessment.findings):
            if index:
                output.print()
            _print_finding(output, finding)

    if assessment.limitations:
        _print_section(output, "Assessment-wide limitations")
        for limitation in assessment.limitations:
            _print_limitation(output, limitation)

    if assessment.recommendations:
        _print_section(output, "Recommendations")
        for recommendation in assessment.recommendations:
            _print_recommendation(output, recommendation)


def render_capture_quality_json(
    assessment: CaptureQualityAssessment,
    *,
    indent: int | None = 2,
) -> str:
    """Return deterministic JSON text without a trailing newline."""
    _validate_indent(indent)
    return assessment.model_dump_json(indent=indent)


def _capture_table(assessment: CaptureQualityAssessment) -> Table:
    capture = assessment.capture
    rows: list[tuple[str, str]] = [("Filename", capture.filename)]
    if capture.path is not None:
        rows.append(("Path", str(capture.path)))
    rows.extend(
        (
            ("Format", capture.capture_format),
            (
                "File size",
                f"{format_file_size(capture.size_bytes)} "
                f"({capture.size_bytes:,} bytes)",
            ),
            ("Packet count", f"{capture.packet_count:,}"),
            ("Start time", _format_timestamp(capture.start_time)),
            ("End time", _format_timestamp(capture.end_time)),
            ("Duration", _format_duration(capture.duration_seconds)),
            ("Interface IDs", ", ".join(capture.interface_ids) or "Not available"),
            ("TShark version", capture.tshark_version),
            ("Inspection status", capture.inspection_status),
        )
    )
    return _key_value_table(rows)


def _statistics_table(assessment: CaptureQualityAssessment) -> Table:
    statistics = assessment.statistics
    rows = (
        ("Rows processed", f"{statistics.rows_processed:,}"),
        ("TCP packets", f"{statistics.tcp_packets:,}"),
        ("TCP SYN packets", f"{statistics.tcp_syn_packets:,}"),
        ("Tracked TCP flows", f"{statistics.tracked_tcp_flows:,}"),
        (
            "Candidate midstream flows",
            f"{statistics.candidate_midstream_flows:,}",
        ),
        (
            "Incomplete handshake flows",
            "Not assessed (use TCP analysis)",
        ),
        ("Truncated frames", f"{statistics.truncated_frames:,}"),
        (
            "Checksum warning frames",
            f"{statistics.checksum_warning_frames:,}",
        ),
        ("Timestamp regressions", f"{statistics.timestamp_regressions:,}"),
        ("Interface IDs observed", f"{statistics.interface_ids_observed:,}"),
        (
            "Flow tracking status",
            "Complete" if statistics.flow_tracking_complete else "Incomplete",
        ),
        ("Flow tracking limit", f"{statistics.flow_tracking_limit:,}"),
        (
            "Checksum rule enabled",
            _format_scalar(statistics.checksum_rule_enabled),
        ),
    )
    return _key_value_table(rows)


def _print_finding(console: Console, finding: CaptureQualityFinding) -> None:
    console.print(
        Text(
            f"{finding.code} — Severity: {finding.severity.value} — "
            f"Confidence: {finding.confidence.value}",
            style="bold",
        )
    )
    console.print(Text(f"Observation: {finding.observation}"))
    if finding.interpretation is not None:
        console.print(Text(f"Interpretation: {finding.interpretation}"))

    if finding.limitations:
        console.print(Text("Finding limitations:", style="bold"))
        for limitation in finding.limitations:
            console.print(Text(f"  - {limitation}"))

    if finding.recommendation_codes:
        console.print(
            Text(
                "Recommendation references: " + ", ".join(finding.recommendation_codes)
            )
        )

    console.print(Text("Evidence:", style="bold"))
    for key, value in finding.evidence.items():
        console.print(Text(f"  {key}: {_format_scalar(value)}"))


def _print_limitation(console: Console, limitation: CaptureLimitation) -> None:
    console.print(Text(limitation.code, style="bold"))
    console.print(Text(f"  Description: {limitation.description}"))
    console.print(
        Text(
            "  Affected capabilities: "
            + (", ".join(limitation.affected_capabilities) or "None")
        )
    )


def _print_recommendation(
    console: Console,
    recommendation: CaptureRecommendation,
) -> None:
    console.print(
        Text(
            f"{recommendation.priority}. {recommendation.code}",
            style="bold",
        )
    )
    console.print(Text(f"  Action: {recommendation.action}"))
    console.print(Text(f"  Rationale: {recommendation.rationale}"))


def _key_value_table(rows: Iterable[tuple[str, str]]) -> Table:
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column("Field", style="bold", no_wrap=True)
    table.add_column("Value")
    for label, value in rows:
        table.add_row(Text(f"{label}:"), Text(value))
    return table


def _print_section(console: Console, title: str) -> None:
    console.print()
    console.print(Text(title, style="bold underline"))


def _format_timestamp(timestamp: datetime | None) -> str:
    return timestamp.isoformat() if timestamp is not None else "Not available"


def _format_duration(duration_seconds: float | None) -> str:
    if duration_seconds is None:
        return "Not available"
    return f"{duration_seconds:.6f} seconds"


def _format_scalar(value: _EvidenceValue) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _status_label(status: CaptureQualityStatus) -> str:
    return status.value.replace("_", " ").upper()


def _status_style(status: CaptureQualityStatus) -> str:
    if status is CaptureQualityStatus.USABLE:
        return "bold green"
    if status is CaptureQualityStatus.USABLE_WITH_LIMITATIONS:
        return "bold yellow"
    if status is CaptureQualityStatus.LIMITED:
        return "bold bright_yellow"
    return "bold red"


def _validate_indent(indent: int | None) -> None:
    if indent is None:
        return
    if isinstance(indent, bool) or not isinstance(indent, int):
        raise TypeError("indent must be a non-negative integer or None")
    if indent < 0:
        raise ValueError("indent must be greater than or equal to zero")
