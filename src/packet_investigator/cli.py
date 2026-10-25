"""Command-line interface for Packet Investigator."""

from datetime import datetime
from decimal import Decimal, DecimalException, localcontext
from pathlib import Path
from typing import Annotated

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.table import Table

from packet_investigator import __version__
from packet_investigator.analyzers import (
    analyze_capture_quality,
    analyze_dns_transactions,
    analyze_tcp_conversations,
)
from packet_investigator.comparison import compare_capture_files
from packet_investigator.investigation import investigate_capture
from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.models.capture_comparison import CaptureHeaders, ClockAlignment
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.models.dns_transactions import DNSAnalysisStatus
from packet_investigator.models.tcp_conversations import TCPAnalysisStatus
from packet_investigator.parsers import (
    collect_capture_quality,
    collect_dns_transaction_evidence,
    collect_tcp_conversation_evidence,
)
from packet_investigator.parsers.tshark import (
    CaptureInspectionError,
    CaptureValidationError,
    inspect_capture,
)
from packet_investigator.renderers import (
    render_capture_quality_json,
    render_capture_quality_rich,
    render_dns_transactions_json,
    render_dns_transactions_rich,
    render_tcp_conversations_json,
    render_tcp_conversations_rich,
)
from packet_investigator.renderers.capture_comparison import (
    render_capture_comparison_rich,
)
from packet_investigator.renderers.investigation import render_investigation_rich
from packet_investigator.utils.formatting import format_file_size

app = typer.Typer(
    help="Evidence-driven offline packet capture investigation.",
    epilog=(
        "Run packet-investigator investigate CAPTURE_PATH for a combined report. "
        "Start with packet-investigator inspect CAPTURE_PATH for metadata, then "
        "packet-investigator quality CAPTURE_PATH for capture suitability. "
        "Use packet-investigator tcp CAPTURE_PATH or packet-investigator dns "
        "CAPTURE_PATH for protocol evidence. "
        "Use packet-investigator compare LEFT RIGHT for two-capture TCP evidence "
        "with explicit clock assumptions.\n\n"
        "Each capture command accepts --json for machine-readable output. "
        "For command options, run packet-investigator COMMAND --help "
        "(for example, packet-investigator dns --help).\n\n"
        "Captures are processed locally with TShark. Reports describe observed "
        "evidence and limitations; they do not establish root cause or ownership."
    ),
    invoke_without_command=True,
    no_args_is_help=True,
)


@app.callback()
def main(
    show_version: Annotated[
        bool,
        typer.Option(
            "--version",
            help="Display the Packet Investigator version and exit.",
            is_eager=True,
        ),
    ] = False,
) -> None:
    """Run Packet Investigator commands."""
    if show_version:
        typer.echo(__version__)
        raise typer.Exit()


@app.command()
def version() -> None:
    """Display the Packet Investigator version."""
    typer.echo(__version__)


@app.command()
def info() -> None:
    """Describe the current implementation status."""
    typer.echo(
        "Packet Investigator provides offline capture metadata inspection, "
        "capture-quality assessment, deterministic TCP conversation analysis, "
        "and deterministic classic DNS transaction analysis. Two-capture TCP "
        "header comparison is available with explicit clock assumptions. "
        "It does not provide "
        "root-cause or ownership conclusions."
    )


@app.command()
def investigate(
    capture_path: Annotated[
        Path,
        typer.Argument(help="Path to a .pcap or .pcapng capture file."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit only machine-readable JSON."),
    ] = False,
    details: Annotated[
        bool,
        typer.Option(
            "--details",
            help="Include per-transaction DNS evidence (up to 100 transactions).",
        ),
    ] = False,
) -> None:
    """Run capture quality, TCP, and classic DNS in one local investigation."""
    try:
        report = investigate_capture(capture_path)
    except CaptureInspectionError as error:
        typer.echo(f"Error: {_safe_capture_error(error, capture_path)}", err=True)
        raise typer.Exit(code=_exit_code(error)) from error
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        render_investigation_rich(report, details=details)
    raise typer.Exit(code=report.exit_code)


def _alignment_from_options(
    assume_synchronized: bool,
    offset_ms: str | None,
    tolerance_ms: str,
) -> ClockAlignment:
    if assume_synchronized and offset_ms is not None:
        raise ValueError("Choose either synchronized clocks or a right-clock offset.")

    def nanoseconds(value: str) -> int:
        if len(value) > 40:
            raise ValueError("Clock values must be finite millisecond numbers.")
        try:
            number = Decimal(value)
            if not number.is_finite() or abs(number) > Decimal(2**63 - 1) / 10**6:
                raise ValueError("Clock values are outside the supported range.")
            with localcontext() as context:
                context.prec = 80
                scaled = number * 10**6
            if (number and not scaled) or scaled != scaled.to_integral_value():
                raise ValueError("Clock values must have whole-nanosecond precision.")
            return int(scaled)
        except DecimalException as error:
            raise ValueError(
                "Clock values must be finite millisecond numbers."
            ) from error

    return ClockAlignment(
        basis=(
            "synchronized"
            if assume_synchronized
            else "user_offset"
            if offset_ms is not None
            else "unverified"
        ),
        right_offset_ns=nanoseconds(offset_ms) if offset_ms is not None else 0,
        tolerance_ns=nanoseconds(tolerance_ms),
    )


@app.command()
def compare(
    left: Annotated[
        Path, typer.Argument(help="Capture at the LEFT observation point.")
    ],
    right: Annotated[
        Path, typer.Argument(help="Capture at the RIGHT observation point.")
    ],
    left_label: Annotated[
        str, typer.Option(help="Label for LEFT; no topology inferred.")
    ] = "left",
    right_label: Annotated[
        str, typer.Option(help="Label for RIGHT; no topology inferred.")
    ] = "right",
    assume_synchronized: Annotated[
        bool, typer.Option(help="Assert independently verified synchronized clocks.")
    ] = False,
    clock_offset_ms: Annotated[
        str | None,
        typer.Option(help="Milliseconds added to RIGHT timestamps; may be negative."),
    ] = None,
    tolerance_ms: Annotated[
        str, typer.Option(help="Inclusive matching tolerance in milliseconds.")
    ] = "1",
    record_limit: Annotated[
        int,
        typer.Option(
            min=1, max=100_000, help="Maximum retained TCP headers per capture."
        ),
    ] = 100_000,
    json_output: Annotated[
        bool, typer.Option("--json", help="Emit only machine-readable JSON.")
    ] = False,
) -> None:
    """Compare two offline captures with explicit clock assumptions."""
    try:
        alignment = _alignment_from_options(
            assume_synchronized, clock_offset_ms, tolerance_ms
        )
        CaptureHeaders(label=left_label, records=())
        CaptureHeaders(label=right_label, records=())
        if left_label == right_label:
            raise ValueError("observation labels must be distinct")
    except (ValueError, ValidationError) as error:
        raise typer.BadParameter(
            "Invalid comparison options. Use distinct, nonblank labels without control "
            "characters, valid clock numbers, and only one clock assurance option."
        ) from error
    try:
        report = compare_capture_files(
            left,
            right,
            left_label=left_label,
            right_label=right_label,
            alignment=alignment,
            record_limit=record_limit,
        )
    except CaptureInspectionError as error:
        message = _safe_capture_error(error, left)
        message = _safe_capture_error(CaptureInspectionError(message), right)
        typer.echo(f"Error: {message}", err=True)
        raise typer.Exit(code=_exit_code(error)) from error
    if json_output:
        typer.echo(report.model_dump_json(indent=2))
    else:
        render_capture_comparison_rich(report)
    raise typer.Exit(code=report.exit_code)


@app.command()
def inspect(
    capture_path: Annotated[
        Path,
        typer.Argument(help="Path to a .pcap or .pcapng capture file."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit only machine-readable JSON."),
    ] = False,
) -> None:
    """Inspect basic capture and packet-boundary metadata."""
    try:
        metadata = inspect_capture(capture_path)
    except CaptureInspectionError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=_exit_code(error)) from error

    if json_output:
        typer.echo(metadata.model_dump_json())
        return

    _render_inspection(metadata)


@app.command()
def quality(
    capture_path: Annotated[
        Path,
        typer.Argument(help="Path to a .pcap or .pcapng capture file."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit only machine-readable JSON."),
    ] = False,
) -> None:
    """Assess whether a capture is suitable for further investigation."""
    try:
        metadata = inspect_capture(capture_path)
        collection = collect_capture_quality(capture_path)
    except CaptureInspectionError as error:
        typer.echo(f"Error: {error}", err=True)
        raise typer.Exit(code=_exit_code(error)) from error

    assessment = analyze_capture_quality(metadata, collection)
    if json_output:
        typer.echo(render_capture_quality_json(assessment))
    else:
        render_capture_quality_rich(assessment)

    raise typer.Exit(code=_quality_exit_code(assessment.status))


@app.command()
def tcp(
    capture_path: Annotated[
        Path,
        typer.Argument(help="Path to a .pcap or .pcapng capture file."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit only machine-readable JSON."),
    ] = False,
) -> None:
    """Analyze deterministic TCP conversation evidence in a capture."""
    try:
        metadata = inspect_capture(capture_path)
        quality_collection = collect_capture_quality(capture_path)
        quality_assessment = analyze_capture_quality(metadata, quality_collection)
        tcp_collection = collect_tcp_conversation_evidence(capture_path)
    except CaptureInspectionError as error:
        typer.echo(f"Error: {_safe_capture_error(error, capture_path)}", err=True)
        raise typer.Exit(code=_exit_code(error)) from error

    report = analyze_tcp_conversations(
        tcp_collection,
        capture=quality_assessment.capture,
        capture_quality_status=quality_assessment.status,
        capture_quality_limitation_codes=tuple(
            limitation.code for limitation in quality_assessment.limitations
        ),
    )
    if json_output:
        typer.echo(render_tcp_conversations_json(report))
    else:
        render_tcp_conversations_rich(report)

    raise typer.Exit(code=_tcp_exit_code(report.status))


@app.command()
def dns(
    capture_path: Annotated[
        Path,
        typer.Argument(help="Path to a .pcap or .pcapng capture file."),
    ],
    json_output: Annotated[
        bool,
        typer.Option("--json", help="Emit only machine-readable JSON."),
    ] = False,
    details: Annotated[
        bool,
        typer.Option(
            "--details",
            help="Include per-transaction DNS evidence (up to 100 transactions).",
        ),
    ] = False,
) -> None:
    """Analyze deterministic classic DNS transaction evidence in a capture."""
    try:
        metadata = inspect_capture(capture_path)
        quality_collection = collect_capture_quality(capture_path)
        quality_assessment = analyze_capture_quality(metadata, quality_collection)
        dns_collection = collect_dns_transaction_evidence(capture_path)
    except CaptureInspectionError as error:
        typer.echo(f"Error: {_safe_capture_error(error, capture_path)}", err=True)
        raise typer.Exit(code=_exit_code(error)) from error

    report = analyze_dns_transactions(
        dns_collection,
        capture=quality_assessment.capture,
        capture_quality_status=quality_assessment.status,
        capture_quality_limitation_codes=tuple(
            limitation.code for limitation in quality_assessment.limitations
        ),
    )
    if json_output:
        typer.echo(render_dns_transactions_json(report), nl=False)
    else:
        render_dns_transactions_rich(report, details=details)

    raise typer.Exit(code=_dns_exit_code(report.status))


def _render_inspection(metadata: CaptureMetadata) -> None:
    console = Console()
    table = Table(
        title="Packet Investigator — Capture Inspection",
        show_header=False,
        box=None,
        pad_edge=False,
    )
    table.add_column("Field", style="bold")
    table.add_column("Value")
    table.add_row("Path:", str(metadata.path))
    table.add_row("Filename:", metadata.filename)
    table.add_row("Format:", metadata.capture_format)
    table.add_row(
        "File size:",
        f"{format_file_size(metadata.size_bytes)} ({metadata.size_bytes:,} bytes)",
    )
    table.add_row("Packets:", f"{metadata.packet_count:,}")
    table.add_row("Start:", _format_timestamp(metadata.start_time))
    table.add_row("End:", _format_timestamp(metadata.end_time))
    table.add_row(
        "Duration:",
        (
            f"{metadata.duration_seconds:.6f} seconds"
            if metadata.duration_seconds is not None
            else "Not available"
        ),
    )
    table.add_row(
        "Interface IDs:",
        ", ".join(metadata.interface_ids) or "Not available",
    )
    table.add_row("TShark:", metadata.tshark_version)
    table.add_row("Status:", metadata.status)
    console.print(table)
    console.print()
    console.print(
        "Metadata inspection only. Next: use 'packet-investigator quality' to assess "
        "capture suitability, 'packet-investigator tcp' for TCP conversation evidence, "
        "or 'packet-investigator dns' for classic DNS transaction evidence. "
        "Each command requires a capture path."
    )


def _format_timestamp(timestamp: datetime | None) -> str:
    if timestamp is None:
        return "Not available"
    return timestamp.isoformat()


def _exit_code(error: CaptureInspectionError) -> int:
    return 2 if isinstance(error, CaptureValidationError) else 1


def _quality_exit_code(status: CaptureQualityStatus) -> int:
    if status in {
        CaptureQualityStatus.USABLE,
        CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
    }:
        return 0
    if status is CaptureQualityStatus.LIMITED:
        return 1
    return 2


def _tcp_exit_code(status: TCPAnalysisStatus) -> int:
    if status in {
        TCPAnalysisStatus.ANALYZED,
        TCPAnalysisStatus.ANALYZED_WITH_FINDINGS,
    }:
        return 0
    if status is TCPAnalysisStatus.LIMITED:
        return 1
    return 2


def _dns_exit_code(status: DNSAnalysisStatus) -> int:
    if status in {
        DNSAnalysisStatus.ANALYZED,
        DNSAnalysisStatus.ANALYZED_WITH_FINDINGS,
    }:
        return 0
    if status is DNSAnalysisStatus.LIMITED:
        return 1
    return 2


def _safe_capture_error(error: CaptureInspectionError, capture_path: Path) -> str:
    """Remove resolved source-path disclosure from protocol command errors."""
    message = str(error)
    resolved = str(capture_path.expanduser().resolve(strict=False))
    return message.replace(resolved, capture_path.name)
