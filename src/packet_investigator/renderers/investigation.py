"""Render the combined workflow using the existing evidence renderers."""

from rich.console import Console
from rich.text import Text

from packet_investigator.investigation import InvestigationReport
from packet_investigator.renderers.capture_quality import render_capture_quality_rich
from packet_investigator.renderers.dns_transactions import render_dns_transactions_rich
from packet_investigator.renderers.tcp_conversations import (
    render_tcp_conversations_rich,
)


def render_investigation_rich(
    report: InvestigationReport,
    *,
    details: bool = False,
    console: Console | None = None,
) -> None:
    """Show completeness followed by the unmodified component evidence."""
    output = console if console is not None else Console()
    output.print(
        Text("Packet Investigator — Single-capture Investigation", style="bold")
    )
    output.print(Text(f"Capture: {report.quality.capture.filename}"))
    output.print(Text(f"Capture quality: {report.quality.status.value}"))
    output.print(Text(f"TCP: {report.tcp.status.value}"))
    output.print(Text(f"Classic DNS: {report.dns.status.value}"))
    output.print(
        Text(
            "Scope: one capture. Sections retain their own evidence and limitations. "
            "This report does not correlate DNS with TCP, establish root cause, "
            "or assign ownership."
        )
    )
    output.print()
    render_capture_quality_rich(report.quality, console=output)
    output.print()
    render_tcp_conversations_rich(report.tcp, console=output)
    output.print()
    render_dns_transactions_rich(report.dns, console=output, details=details)
