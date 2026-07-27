"""Rich terminal and deterministic JSON rendering for DNS analysis reports."""

from __future__ import annotations

import json
from collections.abc import Iterable

from rich.console import Console
from rich.table import Table
from rich.text import Text

from packet_investigator.models.dns_transactions import (
    DNSAnalysisReport,
    DNSAnalysisStatus,
    DNSAnswerSummary,
    DNSEndpoint,
    DNSLimitation,
    DNSRecommendation,
    DNSTransactionAssessment,
    DNSTransactionFinding,
)
from packet_investigator.utils.formatting import format_file_size

_TRANSACTION_LIMIT = 100
_FINDING_LIMIT = 50
_LIMITATION_LIMIT = 50
_RECOMMENDATION_LIMIT = 25
_NARROW_CONSOLE_WIDTH = 100
_RCODE_LABELS = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def render_dns_transactions_rich(
    report: DNSAnalysisReport,
    *,
    console: Console | None = None,
) -> None:
    """Render an immutable DNS analysis report to a Rich console."""
    output = console if console is not None else Console()
    transactions = report.transactions[:_TRANSACTION_LIMIT]

    output.print(Text("Packet Investigator — DNS Transaction Analysis", style="bold"))
    output.print(Text(f"Capture: {report.capture.filename}", style="bold"))
    output.print(
        Text(
            f"Overall status: {_label(report.status.value)}",
            style=_status_style(report.status),
        )
    )
    output.print(Text(report.status_summary))
    _print_capture_summary(output, report)
    _print_report_summary(output, report, len(transactions))

    if transactions:
        _print_section(output, "Transaction summary")
        if output.width < _NARROW_CONSOLE_WIDTH:
            _print_compact_transactions(output, transactions)
        else:
            output.print(_transaction_table(transactions))
        if len(transactions) < len(report.transactions):
            output.print(
                f"Showing {len(transactions)} of "
                f"{len(report.transactions)} transactions; "
                f"{len(report.transactions) - len(transactions)} omitted."
            )

        _print_section(output, "Transaction details")
        for index, transaction in enumerate(transactions):
            if index:
                output.print()
            _print_transaction(output, transaction)

    if report.findings:
        _print_section(output, "Aggregate findings")
        for finding in report.findings[:_FINDING_LIMIT]:
            _print_finding(output, finding)
        _print_omitted(output, "findings", len(report.findings), _FINDING_LIMIT)

    if report.limitations:
        _print_section(output, "Analysis limitations")
        for limitation in report.limitations[:_LIMITATION_LIMIT]:
            _print_limitation(output, limitation)
        _print_omitted(
            output,
            "limitations",
            len(report.limitations),
            _LIMITATION_LIMIT,
        )

    if report.recommendations:
        _print_section(output, "Recommendations")
        for recommendation in report.recommendations[:_RECOMMENDATION_LIMIT]:
            _print_recommendation(output, recommendation)
        _print_omitted(
            output,
            "recommendations",
            len(report.recommendations),
            _RECOMMENDATION_LIMIT,
        )

    output.print()
    output.print(
        "Sensitive metadata: DNS names, endpoint addresses and ports, and bounded "
        "A, AAAA, and CNAME summaries may appear in this report."
    )
    output.print(
        "Scope: visible classic unicast DNS evidence only. This report does not "
        "establish root cause, endpoint ownership, or fault."
    )


def render_dns_transactions_json(report: DNSAnalysisReport) -> str:
    """Return deterministic complete DNS report JSON with one trailing newline."""
    return (
        json.dumps(
            report.model_dump(mode="json"),
            ensure_ascii=False,
            indent=2,
        )
        + "\n"
    )


def _print_capture_summary(console: Console, report: DNSAnalysisReport) -> None:
    capture = report.capture
    _print_section(console, "Capture summary")
    console.print(
        _key_value_table(
            (
                ("Filename", capture.filename),
                ("Format", capture.capture_format),
                (
                    "File size",
                    f"{format_file_size(capture.size_bytes)} "
                    f"({capture.size_bytes:,} bytes)",
                ),
                ("Packets", f"{capture.packet_count:,}"),
                ("Capture quality", _label(report.capture_quality_status.value)),
                ("TShark version", capture.tshark_version),
            )
        )
    )


def _print_report_summary(
    console: Console,
    report: DNSAnalysisReport,
    displayed_transactions: int,
) -> None:
    statistics = report.statistics
    analyzed = sum(
        transaction.status.value
        in {"complete", "complete_with_findings", "partial", "limited"}
        for transaction in report.transactions
    )
    transaction_findings = sum(
        len(transaction.findings) for transaction in report.transactions
    )
    _print_section(console, "Analysis summary")
    console.print(
        _key_value_table(
            (
                ("Transactions", f"{len(report.transactions):,}"),
                ("Analyzed transactions", f"{analyzed:,}"),
                ("Displayed transactions", f"{displayed_transactions:,}"),
                ("Transaction findings", f"{transaction_findings:,}"),
                ("Aggregate findings", f"{len(report.findings):,}"),
                ("Limitations", f"{len(report.limitations):,}"),
                ("Recommendations", f"{len(report.recommendations):,}"),
                ("DNS messages", f"{statistics.dns_messages:,}"),
                ("Queries", f"{statistics.query_messages:,}"),
                ("Responses", f"{statistics.response_messages:,}"),
                ("Matched transactions", f"{statistics.matched_transactions:,}"),
                (
                    "Unmatched queries",
                    f"{statistics.unmatched_query_messages:,}",
                ),
                (
                    "Unmatched responses",
                    f"{statistics.unmatched_response_messages:,}",
                ),
                (
                    "Retry indicators",
                    f"{statistics.retry_indicator_messages:,}",
                ),
                (
                    "Truncated responses",
                    f"{statistics.truncated_response_messages:,}",
                ),
                (
                    "Response codes",
                    _response_code_counts(statistics.response_code_counts),
                ),
                (
                    "Answers observed / retained",
                    f"{statistics.answer_records_observed:,} / "
                    f"{statistics.answer_records_retained:,}",
                ),
            )
        )
    )


def _transaction_table(
    transactions: tuple[DNSTransactionAssessment, ...],
) -> Table:
    table = Table(show_lines=False, expand=False)
    for label in (
        "ID",
        "Requester → responder",
        "Transport",
        "DNS ID",
        "Query",
        "Type/class",
        "Responses",
        "Timing",
        "Status",
    ):
        table.add_column(label)
    for transaction in transactions:
        identity = transaction.identity
        evidence = transaction.evidence
        table.add_row(
            identity.transaction_id,
            f"{_endpoint(identity.requester)} → {_endpoint(identity.responder)}",
            identity.transport.value.upper(),
            str(identity.dns_id),
            identity.query.display_name,
            f"{identity.query.query_type}/{identity.query.query_class}",
            _response_code_counts(evidence.response_code_counts),
            _duration(evidence.elapsed_to_first_response_seconds),
            _label(transaction.status.value),
        )
    return table


def _print_compact_transactions(
    console: Console,
    transactions: tuple[DNSTransactionAssessment, ...],
) -> None:
    for transaction in transactions:
        identity = transaction.identity
        evidence = transaction.evidence
        console.print(
            Text(
                f"{identity.transaction_id} — {identity.query.display_name}",
                style="bold",
            )
        )
        console.print(
            f"  {_endpoint(identity.requester)} → {_endpoint(identity.responder)}; "
            f"{identity.transport.value.upper()}; DNS ID {identity.dns_id}"
        )
        console.print(
            f"  Type/class: {identity.query.query_type}/"
            f"{identity.query.query_class}; "
            f"responses: {_response_code_counts(evidence.response_code_counts)}; "
            f"timing: {_duration(evidence.elapsed_to_first_response_seconds)}; "
            f"status: {_label(transaction.status.value)}"
        )


def _print_transaction(
    console: Console,
    transaction: DNSTransactionAssessment,
) -> None:
    identity = transaction.identity
    evidence = transaction.evidence
    console.print(
        Text(
            f"{identity.transaction_id} — {identity.query.display_name}",
            style="bold",
        )
    )
    console.print(
        _key_value_table(
            (
                ("Status", _label(transaction.status.value)),
                ("Requester", _endpoint(identity.requester)),
                ("Responder", _endpoint(identity.responder)),
                ("Transport", identity.transport.value.upper()),
                ("DNS transaction ID", str(identity.dns_id)),
                ("Match basis", _label(identity.match_basis.value)),
                ("Query name", identity.query.display_name),
                ("Query type", str(identity.query.query_type)),
                ("Query class", str(identity.query.query_class)),
                ("Query observations", f"{evidence.request_count:,}"),
                ("Response observations", f"{evidence.response_count:,}"),
                ("First query frame", _optional_int(evidence.first_request_frame)),
                (
                    "First response frame",
                    _optional_int(evidence.first_response_frame),
                ),
                (
                    "Response codes",
                    _response_code_counts(evidence.response_code_counts),
                ),
                (
                    "Truncated responses",
                    f"{evidence.truncated_response_count:,}",
                ),
                (
                    "Retry indicators",
                    ", ".join(
                        f"{provenance.value}={count}"
                        for provenance, count in evidence.retry_indicator_counts
                    )
                    or "None",
                ),
                (
                    "Unsolicited indicators",
                    f"{evidence.unsolicited_response_indicator_count:,}",
                ),
                (
                    "Observed response time",
                    _duration(evidence.elapsed_to_first_response_seconds),
                ),
                (
                    "Representative frames",
                    _frames(evidence.representative_frames),
                ),
            )
        )
    )
    if evidence.answers:
        console.print(Text("Approved answer summaries:", style="bold"))
        for answer in evidence.answers:
            console.print(f"  {_answer(answer)}")
    if transaction.findings:
        console.print(Text("Findings:", style="bold"))
        for finding in transaction.findings:
            _print_finding(console, finding)
    if transaction.limitations:
        console.print(Text("Transaction limitations:", style="bold"))
        for limitation in transaction.limitations:
            _print_limitation(console, limitation)
    if transaction.recommendations:
        console.print(Text("Transaction recommendations:", style="bold"))
        for recommendation in transaction.recommendations:
            _print_recommendation(console, recommendation)


def _print_finding(console: Console, finding: DNSTransactionFinding) -> None:
    console.print(
        Text(
            f"{finding.code} — {finding.severity.value} — "
            f"observations: {finding.observation_count:,}",
            style="bold",
        )
    )
    console.print(Text(f"  Observed: {finding.observation}"))
    if finding.interpretation is not None:
        console.print(Text(f"  Interpretation: {finding.interpretation}"))
    console.print(
        Text(
            "  Provenance: "
            + (", ".join(item.value for item in finding.provenance) or "None")
        )
    )
    console.print(
        Text(f"  Representative frames: {_frames(finding.representative_frames)}")
    )
    if finding.evidence:
        console.print(Text("  Evidence:"))
        for key, value in finding.evidence.items():
            console.print(Text(f"    {key}: {_scalar(value)}"))


def _print_limitation(console: Console, limitation: DNSLimitation) -> None:
    console.print(Text(limitation.code, style="bold"))
    console.print(Text(f"  Description: {limitation.description}"))
    if limitation.transaction_id is not None:
        console.print(Text(f"  Transaction: {limitation.transaction_id}"))
    console.print(
        Text(
            "  Affected capabilities: "
            + (", ".join(limitation.affected_capabilities) or "None")
        )
    )
    console.print(
        Text(f"  Representative frames: {_frames(limitation.representative_frames)}")
    )


def _print_recommendation(
    console: Console,
    recommendation: DNSRecommendation,
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


def _print_omitted(
    console: Console,
    label: str,
    count: int,
    limit: int,
) -> None:
    if count > limit:
        console.print(f"Showing {limit} of {count} {label}; {count - limit} omitted.")


def _endpoint(endpoint: DNSEndpoint) -> str:
    address = str(endpoint.address)
    return (
        f"[{address}]:{endpoint.port}"
        if endpoint.ip_version == 6
        else f"{address}:{endpoint.port}"
    )


def _answer(answer: DNSAnswerSummary) -> str:
    label = {1: "A", 5: "CNAME", 28: "AAAA"}[answer.record_type]
    owner = answer.owner_name or "owner unavailable"
    value = answer.value or "value unavailable"
    ttl = (
        f"{answer.ttl_seconds} seconds"
        if answer.ttl_seconds is not None
        else "unavailable"
    )
    return f"{label} {owner} → {value}; TTL {ttl}; frame {answer.representative_frame}"


def _response_code_counts(counts: tuple[tuple[int, int], ...]) -> str:
    if not counts:
        return "Not observed"
    return ", ".join(
        f"{_RCODE_LABELS.get(code, f'RCODE {code}')} ({code}) × {count:,}"
        for code, count in counts
    )


def _duration(value: float | None) -> str:
    return f"{value:.6f} seconds" if value is not None else "Not available"


def _optional_int(value: int | None) -> str:
    return str(value) if value is not None else "Not observed"


def _frames(frames: tuple[int, ...]) -> str:
    return ", ".join(str(frame) for frame in frames) or "None"


def _scalar(value: int | float | str | bool | None) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _label(value: str) -> str:
    return value.replace("_", " ").upper()


def _status_style(status: DNSAnalysisStatus) -> str:
    if status is DNSAnalysisStatus.ANALYZED:
        return "bold green"
    if status is DNSAnalysisStatus.ANALYZED_WITH_FINDINGS:
        return "bold yellow"
    if status is DNSAnalysisStatus.LIMITED:
        return "bold bright_yellow"
    return "bold red"


__all__ = ["render_dns_transactions_json", "render_dns_transactions_rich"]
