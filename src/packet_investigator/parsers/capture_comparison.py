"""Minimal, bounded offline TCP header projection for two-point comparison."""

from collections.abc import Iterable
from dataclasses import dataclass
from decimal import Decimal, DecimalException, localcontext
from ipaddress import ip_address
from pathlib import Path

from packet_investigator.models.capture_comparison import (
    CaptureHeaders,
    TCPHeaderRecord,
)
from packet_investigator.models.capture_file_comparison import HeaderCollectionSummary
from packet_investigator.parsers.tshark import (
    DEFAULT_TIMEOUT_SECONDS,
    TsharkOutputError,
    find_tshark,
    get_tshark_field_capabilities,
    stream_tshark_fields,
    validate_capture_path,
)

FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.interface_id",
    "frame.cap_len",
    "frame.len",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.flags",
    "tcp.len",
)
_SEPARATOR = "\x1e"


@dataclass(frozen=True)
class TCPHeaderCollection:
    headers: CaptureHeaders
    summary: HeaderCollectionSummary


def _record(columns: list[str]) -> TCPHeaderRecord:
    if len(columns) != len(FIELDS) or any(_SEPARATOR in value for value in columns):
        raise ValueError("ambiguous or incomplete field projection")
    # All-occurrence collection rejects nested/repeated IP/TCP layers rather
    # than silently choosing one layer from an encapsulated packet.
    if bool(columns[5] or columns[6]) == bool(columns[7] or columns[8]):
        raise ValueError("exactly one complete IP address family is required")
    source, destination = columns[5:7] if columns[5] else columns[7:9]
    if len(columns[1]) > 64:
        raise ValueError("oversized timestamp")
    epoch = Decimal(columns[1])
    if not epoch.is_finite() or not 0 <= epoch <= Decimal(2**63 - 1) / 10**9:
        raise ValueError("timestamp outside supported range")
    with localcontext() as context:
        context.prec = 80
        ns = epoch * 10**9
    if (epoch and not ns) or ns != ns.to_integral_value():
        raise ValueError("timestamp exceeds nanosecond resolution")
    captured, original = int(columns[3]), int(columns[4])
    if captured < 0 or original < captured:
        raise ValueError("invalid frame lengths")
    return TCPHeaderRecord(
        frame_number=int(columns[0]),
        timestamp_ns=int(ns),
        interface_id=columns[2],
        source_address=ip_address(source),
        destination_address=ip_address(destination),
        source_port=int(columns[9]),
        destination_port=int(columns[10]),
        sequence=int(columns[11]),
        acknowledgment=int(columns[12]),
        flags=int(columns[13], 0),
        payload_length=int(columns[14]),
        truncated=captured < original,
    )


def collect_header_rows(
    rows: Iterable[str],
    *,
    label: str,
    record_limit: int = 100_000,
    quality_limited: bool = False,
) -> TCPHeaderCollection:
    """Consume projected rows without retaining raw output or packet bodies."""
    if (
        isinstance(record_limit, bool)
        or not isinstance(record_limit, int)
        or not 1 <= record_limit <= 100_000
    ):
        raise ValueError("record_limit must be between 1 and 100000")
    CaptureHeaders(label=label, records=())  # Validate before consuming untrusted rows.
    records: list[TCPHeaderRecord] = []
    seen: set[int] = set()
    observed = malformed = duplicates = capacity = 0
    for row in rows:
        if not row.rstrip("\r\n"):
            continue
        observed += 1
        if len(records) >= record_limit:
            capacity += 1
            continue
        try:
            if len(row) > 4096:
                raise ValueError("oversized header projection")
            record = _record(row.rstrip("\r\n").split("\t"))
        except (ValueError, DecimalException):
            malformed += 1
            continue
        if record.frame_number in seen:
            duplicates += 1
            continue
        seen.add(record.frame_number)
        records.append(record)
    omitted = malformed + duplicates + capacity
    return TCPHeaderCollection(
        headers=CaptureHeaders(
            label=label,
            records=tuple(records),
            tracking_complete=omitted == 0,
            omitted_records=omitted,
            quality_limited=quality_limited,
        ),
        summary=HeaderCollectionSummary(
            rows_observed=observed,
            records_retained=len(records),
            malformed_rows=malformed,
            duplicate_frame_rows=duplicates,
            capacity_omissions=capacity,
        ),
    )


def collect_tcp_headers(
    capture_path: Path,
    *,
    label: str,
    record_limit: int = 100_000,
    quality_limited: bool = False,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
) -> TCPHeaderCollection:
    """Collect only approved header fields from a local capture with real TShark."""
    if timeout <= 0:
        raise ValueError("timeout must be positive")
    CaptureHeaders(label=label, records=())
    path, _ = validate_capture_path(capture_path)
    executable = find_tshark()
    fields = get_tshark_field_capabilities(executable, timeout, FIELDS)
    if not set(FIELDS).issubset(fields):
        raise TsharkOutputError("TShark lacks required TCP comparison header fields.")
    return stream_tshark_fields(
        executable,
        path,
        FIELDS,
        timeout,
        lambda rows: collect_header_rows(
            rows,
            label=label,
            record_limit=record_limit,
            quality_limited=quality_limited,
        ),
        operation="TCP header comparison collection",
        display_filter="tcp",
        field_occurrence="a",
        aggregator=_SEPARATOR,
    )
