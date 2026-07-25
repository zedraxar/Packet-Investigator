"""Command-line interface for Packet Investigator."""

import typer

from packet_investigator import __version__

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
