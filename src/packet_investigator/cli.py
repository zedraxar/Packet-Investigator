"""Command-line interface for Packet Investigator."""

from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from packet_investigator import __version__
from packet_investigator.analyzers import (
    analyze_capture_quality,
    analyze_dns_transactions,
    analyze_tcp_conversations,
)
from packet_investigator.models.capture import CaptureMetadata
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
from packet_investigator.utils.formatting import format_file_size

app = typer.Typer(
    help="Evidence-driven offline packet capture investigation.",
    epilog=(
        "Start with packet-investigator inspect CAPTURE_PATH for metadata, then "
        "packet-investigator quality CAPTURE_PATH for capture suitability. "
        "Use packet-investigator tcp CAPTURE_PATH or packet-investigator dns "
        "CAPTURE_PATH for protocol evidence.\n\n"
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
        "and deterministic classic DNS transaction analysis. It does not provide "
        "root-cause or ownership conclusions."
    )


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
        render_dns_transactions_rich(report)

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
