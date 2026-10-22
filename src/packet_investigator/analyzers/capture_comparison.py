"""Bounded, indexed TCP header candidates; never match application payloads."""

from bisect import bisect_left, bisect_right
from collections import defaultdict
from dataclasses import dataclass
from heapq import nsmallest
from typing import Literal

from packet_investigator.models.capture_comparison import (
    CaptureComparisonReport,
    CaptureHeaders,
    ClockAlignment,
    ComparisonStatus,
    HeaderComparison,
    TCPHeaderRecord,
)

type _Key = tuple[str, str, int, int, int, int, int, int]


def _key(record: TCPHeaderRecord) -> _Key:
    return (
        str(record.source_address),
        str(record.destination_address),
        record.source_port,
        record.destination_port,
        record.sequence,
        record.acknowledgment,
        record.flags,
        record.payload_length,
    )


@dataclass(frozen=True)
class _Group:
    records: tuple[TCPHeaderRecord, ...]
    times: tuple[int, ...]


def _index(records: tuple[TCPHeaderRecord, ...], offset: int) -> dict[_Key, _Group]:
    groups: dict[_Key, list[TCPHeaderRecord]] = defaultdict(list)
    for record in records:
        if not record.truncated:
            groups[_key(record)].append(record)
    result: dict[_Key, _Group] = {}
    for key, values in groups.items():
        ordered = tuple(sorted(values, key=lambda x: (x.timestamp_ns, x.frame_number)))
        result[key] = _Group(ordered, tuple(x.timestamp_ns + offset for x in ordered))
    return result


def _range(group: _Group | None, time: int, tolerance: int) -> tuple[int, int]:
    if group is None:
        return 0, 0
    return (
        bisect_left(group.times, time - tolerance),
        bisect_right(group.times, time + tolerance),
    )


def _regresses(records: tuple[TCPHeaderRecord, ...]) -> bool:
    return any(
        a.timestamp_ns > b.timestamp_ns
        for a, b in zip(records, records[1:], strict=False)
    )


def compare_tcp_headers(
    left: CaptureHeaders,
    right: CaptureHeaders,
    *,
    alignment: ClockAlignment,
    record_limit: int = 100_000,
) -> CaptureComparisonReport:
    """Return header candidates over caller-supplied, already-normalized records.

    Output anchors every retained left frame, plus right frames with no eligible
    left candidate. Unverified clocks or incomplete tracking disable matching.
    """
    if (
        not isinstance(record_limit, int)
        or isinstance(record_limit, bool)
        or not 1 <= record_limit <= 100_000
    ):
        raise ValueError("record_limit must be an integer between 1 and 100000")
    if left.label == right.label:
        raise ValueError("observation labels must be distinct")
    left_records = tuple(
        nsmallest(record_limit, left.records, key=lambda x: x.frame_number)
    )
    right_records = tuple(
        nsmallest(record_limit, right.records, key=lambda x: x.frame_number)
    )
    left_omitted = len(left.records) - len(left_records) + left.omitted_records
    right_omitted = len(right.records) - len(right_records) + right.omitted_records
    complete = (
        left.tracking_complete
        and right.tracking_complete
        and not left_omitted
        and not right_omitted
    )
    limitations = [
        "HEADER_CORRESPONDENCE_IS_NOT_PACKET_OR_PAYLOAD_IDENTITY",
        "ONE_SIDED_OBSERVATION_IS_NOT_PROVEN_LOSS",
        "NAT_PROXY_AND_SEGMENTATION_NOT_NORMALIZED",
        "CLOCK_OFFSET_DOES_NOT_CORRECT_DRIFT_OR_ESTABLISH_LATENCY",
    ]
    if alignment.basis == "unverified":
        limitations.append("TIME_ALIGNMENT_UNVERIFIED")
    if not complete:
        limitations.append("TRACKING_INCOMPLETE")
    if left.quality_limited or right.quality_limited:
        limitations.append("CAPTURE_QUALITY_LIMITED")
    if _regresses(left_records) or _regresses(right_records):
        limitations.append("TIMESTAMP_REGRESSION")
    truncated = any(x.truncated for x in (*left_records, *right_records))
    if truncated:
        limitations.append("TRUNCATED_RECORDS_NOT_COMPARABLE")
    matching_enabled = complete and not truncated and alignment.basis != "unverified"
    left_index = _index(left_records, 0) if matching_enabled else {}
    right_index = (
        _index(right_records, alignment.right_offset_ns) if matching_enabled else {}
    )
    comparisons: list[HeaderComparison] = []

    def uncomparable(side: Literal["left", "right"], header: TCPHeaderRecord) -> None:
        comparisons.append(
            HeaderComparison(
                observation=side,
                header=header,
                status=ComparisonStatus.NOT_COMPARABLE,
                candidate_count=0,
                candidates=(),
                reason="Clock assurance and full untruncated evidence required.",
            )
        )

    for header in left_records:
        if not matching_enabled or header.truncated:
            uncomparable("left", header)
            continue
        group = right_index.get(_key(header))
        lo, hi = _range(group, header.timestamp_ns, alignment.tolerance_ns)
        count = hi - lo
        reverse_count = None
        candidates = group.records[lo : min(hi, lo + 8)] if group else ()
        if count == 0:
            status = ComparisonStatus.LEFT_ONLY
            reason = (
                "No eligible header counterpart observed at RIGHT within the window."
            )
        else:
            if count == 1:
                a, b = _range(
                    left_index.get(_key(header)),
                    candidates[0].timestamp_ns + alignment.right_offset_ns,
                    alignment.tolerance_ns,
                )
                reverse_count = b - a
            status = (
                ComparisonStatus.UNIQUE
                if count == reverse_count == 1
                else ComparisonStatus.AMBIGUOUS
            )
            reason = (
                "One-to-one header candidate."
                if status is ComparisonStatus.UNIQUE
                else "Multiple eligible headers on one or both sides; no tie chosen."
            )
        comparisons.append(
            HeaderComparison(
                observation="left",
                header=header,
                status=status,
                candidate_count=count,
                omitted_candidates=count - len(candidates),
                reverse_candidate_count=reverse_count,
                candidates=candidates,
                reason=reason,
            )
        )
    for header in right_records:
        if not matching_enabled or header.truncated:
            uncomparable("right", header)
            continue
        lo, hi = _range(
            left_index.get(_key(header)),
            header.timestamp_ns + alignment.right_offset_ns,
            alignment.tolerance_ns,
        )
        if lo == hi:
            comparisons.append(
                HeaderComparison(
                    observation="right",
                    header=header,
                    status=ComparisonStatus.RIGHT_ONLY,
                    candidate_count=0,
                    candidates=(),
                    reason="No eligible header observed at LEFT in the window.",
                )
            )
    return CaptureComparisonReport(
        left_label=left.label,
        right_label=right.label,
        alignment=alignment,
        record_limit=record_limit,
        left_supplied_records=len(left.records),
        right_supplied_records=len(right.records),
        left_retained_records=len(left_records),
        right_retained_records=len(right_records),
        left_omitted_records=left_omitted,
        right_omitted_records=right_omitted,
        tracking_complete=complete,
        left_quality_limited=left.quality_limited,
        right_quality_limited=right.quality_limited,
        limitations=tuple(limitations),
        recommendations=(
            "Collect simultaneous, untruncated captures at both observation points.",
            "Verify clock offset and drift; align capture windows and filters.",
            "Check NAT, proxy, offload and capture-drop telemetry before conclusions.",
        ),
        comparisons=tuple(comparisons),
    )
