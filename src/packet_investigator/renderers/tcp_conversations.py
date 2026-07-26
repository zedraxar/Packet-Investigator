"""Rich terminal and JSON rendering for TCP conversation reports."""

from __future__ import annotations

import json
from collections.abc import Iterable

from rich.console import Console
from rich.table import Table
from rich.text import Text

from packet_investigator.models.tcp_conversations import (
    Endpoint,
    TCPAnalysisReport,
    TCPAnalysisStatus,
    TCPConversationAssessment,
    TCPConversationFinding,
    TCPConversationLimitation,
    TCPConversationRecommendation,
    TCPConversationStatus,
    TCPDirectionalStatistics,
)
from packet_investigator.utils.formatting import format_file_size

_SUMMARY_LIMIT = 20
_DETAIL_LIMIT = 5
_NARROW_CONSOLE_WIDTH = 100
_Scalar = int | float | str | bool | None
_CONVERSATION_STATUS_RANK = {
    TCPConversationStatus.INSUFFICIENT: 0,
    TCPConversationStatus.LIMITED: 1,
    TCPConversationStatus.PARTIAL: 2,
    TCPConversationStatus.COMPLETE_WITH_FINDINGS: 3,
    TCPConversationStatus.COMPLETE: 4,
}


def render_tcp_conversations_rich(
    report: TCPAnalysisReport,
    *,
    console: Console | None = None,
) -> None:
    """Render an immutable TCP report to a Rich console."""
    output = console if console is not None else Console()
    selected = _ranked_conversations(report)
    summaries = selected[:_SUMMARY_LIMIT]
    details = selected[:_DETAIL_LIMIT]

    output.print(Text("Packet Investigator — TCP Conversation Analysis", style="bold"))
    output.print(Text(f"Capture: {report.capture.filename}", style="bold"))
    if report.capture.path is not None:
        output.print(Text(f"Path: {report.capture.path}"))
    output.print(
        Text(
            f"Overall status: {_label(report.status.value)}",
            style=_status_style(report.status),
        )
    )
    output.print(Text(report.summary))

    _print_capture_summary(output, report)
    if report.limitations:
        _print_section(output, "Analysis limitations")
        for limitation in report.limitations:
            _print_limitation(output, limitation)

    if report.conversations:
        _print_section(output, "Conversation summary")
        if output.width < _NARROW_CONSOLE_WIDTH:
            _print_compact_summaries(output, summaries)
        else:
            output.print(_conversation_summary_table(summaries))
        if len(summaries) < len(report.conversations):
            output.print(
                f"Showing {len(summaries)} of "
                f"{len(report.conversations)} conversations."
            )

        _print_section(output, "Conversation details")
        for index, conversation in enumerate(details):
            if index:
                output.print()
            _print_conversation_detail(output, conversation)
        if len(details) < len(report.conversations):
            output.print(
                f"Showing detail for {len(details)} of "
                f"{len(report.conversations)} conversations."
            )

    _print_section(output, "Aggregate statistics")
    output.print(_analysis_statistics_table(report))

    if report.recommendations:
        _print_section(output, "Recommendations")
        for recommendation in report.recommendations:
            _print_recommendation(output, recommendation)

    output.print()
    output.print(
        "Scope: TCP evidence only. This report does not establish root cause "
        "or technical ownership."
    )


def render_tcp_conversations_json(
    report: TCPAnalysisReport,
    *,
    indent: int | None = 2,
) -> str:
    """Return deterministic TCP report JSON without a trailing newline."""
    _validate_indent(indent)
    separators = (",", ":") if indent is None else None
    return json.dumps(
        report.model_dump(mode="json"),
        ensure_ascii=False,
        indent=indent,
        separators=separators,
        sort_keys=True,
    )


def _ranked_conversations(
    report: TCPAnalysisReport,
) -> tuple[TCPConversationAssessment, ...]:
    return tuple(
        sorted(
            report.conversations,
            key=lambda conversation: (
                _CONVERSATION_STATUS_RANK[conversation.status],
                conversation.statistics.first_frame,
                conversation.identity.conversation_id,
            ),
        )
    )


def _print_capture_summary(console: Console, report: TCPAnalysisReport) -> None:
    capture = report.capture
    rows: list[tuple[str, str]] = [
        ("Filename", capture.filename),
        ("Format", capture.capture_format),
        (
            "File size",
            f"{format_file_size(capture.size_bytes)} ({capture.size_bytes:,} bytes)",
        ),
        ("Packets", f"{capture.packet_count:,}"),
        ("Capture quality", _label(report.capture_quality_status.value)),
        ("TShark version", capture.tshark_version),
    ]
    if capture.path is not None:
        rows.insert(1, ("Path", str(capture.path)))
    _print_section(console, "Capture summary")
    console.print(_key_value_table(rows))


def _conversation_summary_table(
    conversations: tuple[TCPConversationAssessment, ...],
) -> Table:
    table = Table(show_lines=False, expand=False)
    for label in (
        "ID",
        "Endpoints",
        "Initiator",
        "Packets A→B / B→A",
        "Payload A→B / B→A",
        "Duration",
        "Handshake",
        "Closure",
        "RST",
        "Retrans.",
        "Status",
    ):
        table.add_column(label)
    for conversation in conversations:
        statistics = conversation.statistics
        table.add_row(
            conversation.identity.conversation_id,
            _endpoint_pair(conversation),
            _endpoint_reference(conversation.roles.observed_initiator),
            f"{statistics.a_to_b.packets:,} / {statistics.b_to_a.packets:,}",
            (
                f"{statistics.a_to_b.payload_bytes:,} / "
                f"{statistics.b_to_a.payload_bytes:,}"
            ),
            _format_duration(statistics.duration_seconds),
            _label(conversation.handshake.state.value),
            _label(conversation.closure.state.value),
            f"{conversation.closure.reset_count:,}",
            f"{conversation.symptoms.retransmission_indicator_frames:,}",
            _label(conversation.status.value),
        )
    return table


def _print_compact_summaries(
    console: Console,
    conversations: tuple[TCPConversationAssessment, ...],
) -> None:
    for conversation in conversations:
        statistics = conversation.statistics
        console.print(
            Text(
                f"{conversation.identity.conversation_id} — "
                f"{_endpoint_pair(conversation)}",
                style="bold",
            )
        )
        console.print(
            "  "
            f"Status: {_label(conversation.status.value)}; "
            f"Initiator: {_endpoint_reference(conversation.roles.observed_initiator)}"
        )
        console.print(
            "  "
            f"Packets A→B / B→A: {statistics.a_to_b.packets:,} / "
            f"{statistics.b_to_a.packets:,}; "
            f"Payload bytes: {statistics.a_to_b.payload_bytes:,} / "
            f"{statistics.b_to_a.payload_bytes:,}"
        )
        console.print(
            "  "
            f"Duration: {_format_duration(statistics.duration_seconds)}; "
            f"Handshake: {_label(conversation.handshake.state.value)}; "
            f"Closure: {_label(conversation.closure.state.value)}; "
            f"RST: {conversation.closure.reset_count:,}; "
            "Retransmission indicators: "
            f"{conversation.symptoms.retransmission_indicator_frames:,}"
        )


def _print_conversation_detail(
    console: Console,
    conversation: TCPConversationAssessment,
) -> None:
    console.print(
        Text(
            f"{conversation.identity.conversation_id} — {_endpoint_pair(conversation)}",
            style="bold",
        )
    )
    console.print(Text(f"Status: {_label(conversation.status.value)}"))
    console.print(Text(conversation.status_summary))
    console.print(
        _key_value_table(
            (
                (
                    "Observed initiator",
                    _endpoint_reference(conversation.roles.observed_initiator),
                ),
                (
                    "Inferred client",
                    _endpoint_reference(conversation.roles.inferred_client),
                ),
                (
                    "Inferred server",
                    _endpoint_reference(conversation.roles.inferred_server),
                ),
                ("Role evidence", conversation.roles.strength.value),
                ("Role observation", conversation.roles.observation),
                ("Handshake", _label(conversation.handshake.state.value)),
                ("Closure", _label(conversation.closure.state.value)),
                ("First frame", str(conversation.statistics.first_frame)),
                ("Last frame", str(conversation.statistics.last_frame)),
                (
                    "Observed duration",
                    _format_duration(
                        conversation.timings.conversation_duration_seconds
                    ),
                ),
            )
        )
    )
    _print_direction(console, "A→B", conversation.statistics.a_to_b)
    _print_direction(console, "B→A", conversation.statistics.b_to_a)
    _print_timing(console, conversation)

    if conversation.findings:
        console.print(Text("Findings:", style="bold"))
        for finding in conversation.findings:
            _print_finding(console, finding)
    if conversation.limitations:
        console.print(Text("Conversation limitations:", style="bold"))
        for limitation in conversation.limitations:
            _print_limitation(console, limitation)
    if conversation.recommendation_codes:
        console.print(
            Text(
                "Recommendation references: "
                + ", ".join(conversation.recommendation_codes)
            )
        )


def _print_direction(
    console: Console,
    label: str,
    statistics: TCPDirectionalStatistics,
) -> None:
    console.print(Text(f"Direction {label}:", style="bold"))
    console.print(
        "  "
        f"Packets: {statistics.packets:,}; "
        f"captured bytes: {statistics.captured_bytes:,}; "
        f"reported bytes: {statistics.original_frame_bytes:,}; "
        f"payload bytes: {statistics.payload_bytes:,}"
    )


def _print_timing(
    console: Console,
    conversation: TCPConversationAssessment,
) -> None:
    timing = conversation.timings
    console.print(Text("Timing observations:", style="bold"))
    rows = (
        (
            "Conversation duration",
            _format_duration(timing.conversation_duration_seconds),
        ),
        ("SYN to SYN/ACK", _format_duration(timing.syn_to_syn_ack_seconds)),
        (
            "SYN/ACK to final ACK",
            _format_duration(timing.syn_ack_to_final_ack_seconds),
        ),
        ("TShark initial RTT", _format_duration(timing.tshark_initial_rtt_seconds)),
        (
            "First payload A→B",
            _format_duration(timing.time_to_first_payload_a_to_b_seconds),
        ),
        (
            "First payload B→A",
            _format_duration(timing.time_to_first_payload_b_to_a_seconds),
        ),
        (
            "Availability",
            ", ".join(item.value for item in timing.availability) or "Not available",
        ),
    )
    console.print(_key_value_table(rows))


def _print_finding(console: Console, finding: TCPConversationFinding) -> None:
    console.print(
        Text(
            f"  {finding.code} — {finding.severity.value} — "
            f"{finding.evidence_strength.value}",
            style="bold",
        )
    )
    console.print(Text(f"    Observed: {finding.observation}"))
    if finding.interpretation is not None:
        console.print(Text(f"    Interpretation: {finding.interpretation}"))
    console.print(Text(f"    Provenance: {finding.evidence.provenance.value}"))
    if finding.evidence.values:
        console.print(Text("    Evidence:"))
        for key, value in sorted(finding.evidence.values.items()):
            console.print(Text(f"      {key}: {_format_scalar(value)}"))
    console.print(
        Text(
            "    Representative frames: "
            + (
                ", ".join(
                    str(frame) for frame in finding.evidence.representative_frames
                )
                or "None"
            )
        )
    )
    if finding.limitations:
        console.print(
            Text("    Finding limitations: " + ", ".join(finding.limitations))
        )
    if finding.recommendation_codes:
        console.print(
            Text(
                "    Recommendation references: "
                + ", ".join(finding.recommendation_codes)
            )
        )


def _analysis_statistics_table(report: TCPAnalysisReport) -> Table:
    statistics = report.analysis_statistics
    rows: list[tuple[str, str]] = [
        ("Rows processed", f"{statistics.rows_processed:,}"),
        ("Usable TCP rows", f"{statistics.usable_tcp_rows:,}"),
        ("Unusable TCP rows", f"{statistics.unusable_tcp_rows:,}"),
        ("Malformed optional fields", f"{statistics.malformed_optional_fields:,}"),
        ("TCP conversations", f"{statistics.tcp_conversations:,}"),
        ("Tracked conversation limit", f"{statistics.tracked_conversation_limit:,}"),
        (
            "Conversation tracking",
            "Complete" if statistics.conversation_tracking_complete else "Incomplete",
        ),
        ("Untracked conversation rows", f"{statistics.untracked_conversation_rows:,}"),
        ("Stream/tuple conflicts", f"{statistics.stream_tuple_conflicts:,}"),
        (
            "Ambiguous encapsulation rows",
            f"{statistics.ambiguous_encapsulation_rows:,}",
        ),
        ("Complete conversations", f"{statistics.complete_conversations:,}"),
        (
            "Complete with findings",
            f"{statistics.complete_with_findings_conversations:,}",
        ),
        ("Partial conversations", f"{statistics.partial_conversations:,}"),
        ("Limited conversations", f"{statistics.limited_conversations:,}"),
        ("Insufficient conversations", f"{statistics.insufficient_conversations:,}"),
        ("Parser warnings retained", f"{statistics.retained_parser_warnings:,}"),
        ("Parser warnings total", f"{statistics.total_parser_warnings:,}"),
        (
            "Supported derived capabilities",
            ", ".join(statistics.supported_derived_capabilities) or "None",
        ),
        (
            "Unsupported derived capabilities",
            ", ".join(statistics.unsupported_derived_capabilities) or "None",
        ),
        (
            "Interface IDs observed",
            ", ".join(statistics.interface_ids_observed) or "None",
        ),
    ]
    for code, count in statistics.finding_counts.items():
        rows.append((f"Finding count — {code}", f"{count:,}"))
    return _key_value_table(rows)


def _print_limitation(
    console: Console,
    limitation: TCPConversationLimitation,
) -> None:
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
    recommendation: TCPConversationRecommendation,
) -> None:
    console.print(
        Text(f"{recommendation.priority}. {recommendation.code}", style="bold")
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


def _endpoint_pair(conversation: TCPConversationAssessment) -> str:
    return (
        f"{_format_endpoint(conversation.identity.endpoint_a)} ↔ "
        f"{_format_endpoint(conversation.identity.endpoint_b)}"
    )


def _format_endpoint(endpoint: Endpoint) -> str:
    address = str(endpoint.address)
    return (
        f"[{address}]:{endpoint.port}"
        if endpoint.ip_version == 6
        else (f"{address}:{endpoint.port}")
    )


def _endpoint_reference(value: str | None) -> str:
    return f"Endpoint {value.upper()}" if value is not None else "Unknown"


def _format_duration(value: float | None) -> str:
    return f"{value:.6f} seconds" if value is not None else "Not available"


def _format_scalar(value: _Scalar) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _label(value: str) -> str:
    return value.replace("_", " ").upper()


def _status_style(status: TCPAnalysisStatus) -> str:
    if status is TCPAnalysisStatus.ANALYZED:
        return "bold green"
    if status is TCPAnalysisStatus.ANALYZED_WITH_FINDINGS:
        return "bold yellow"
    if status is TCPAnalysisStatus.LIMITED:
        return "bold bright_yellow"
    return "bold red"


def _validate_indent(indent: int | None) -> None:
    if indent is None:
        return
    if isinstance(indent, bool) or not isinstance(indent, int):
        raise TypeError("indent must be a non-negative integer or None")
    if indent < 0:
        raise ValueError("indent must be greater than or equal to zero")


__all__ = ["render_tcp_conversations_json", "render_tcp_conversations_rich"]
