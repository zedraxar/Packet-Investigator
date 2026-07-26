"""Command-line interface for Packet Investigator."""

from datetime import datetime
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from packet_investigator import __version__
from packet_investigator.analyzers import analyze_capture_quality
from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.parsers import collect_capture_quality
from packet_investigator.parsers.tshark import (
    CaptureInspectionError,
    CaptureValidationError,
    inspect_capture,
)
from packet_investigator.renderers import (
    render_capture_quality_json,
    render_capture_quality_rich,
)
from packet_investigator.utils.formatting import format_file_size

app = typer.Typer(
    help="Evidence-driven offline packet capture investigation.",
    no_args_is_help=True,
)


@app.command()
def version() -> None:
    """Display the Packet Investigator version."""
    typer.echo(__version__)


@app.command()
def info() -> None:
    """Describe the current implementation status."""
    typer.echo(
        "Packet Investigator is currently an initial scaffold; "
        "packet analysis is not implemented."
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
        "Metadata inspection only. Diagnostic packet analysis is not implemented yet."
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
