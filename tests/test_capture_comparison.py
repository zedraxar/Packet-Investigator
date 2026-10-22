"""Evidence-boundary and ambiguity tests for the pure TCP header matcher."""

from ipaddress import IPv4Address, IPv6Address

import pytest
from pydantic import ValidationError

from packet_investigator.analyzers.capture_comparison import compare_tcp_headers
from packet_investigator.models.capture_comparison import (
    CaptureComparisonReport,
    CaptureHeaders,
    ClockAlignment,
    ComparisonStatus,
    TCPHeaderRecord,
)


def header(frame: int = 1, time: int = 1000, **changes: object) -> TCPHeaderRecord:
    values: dict[str, object] = {
        "frame_number": frame,
        "timestamp_ns": time,
        "source_address": IPv4Address("192.0.2.10"),
        "destination_address": IPv4Address("198.51.100.20"),
        "source_port": 49152,
        "destination_port": 443,
        "sequence": 0xFFFFFFFF,
        "acknowledgment": 99,
        "flags": 16,
        "payload_length": 20,
    }
    return TCPHeaderRecord.model_validate(values | changes)


def compare(
    left: tuple[TCPHeaderRecord, ...],
    right: tuple[TCPHeaderRecord, ...],
    alignment: ClockAlignment | None = None,
    limit: int = 100_000,
) -> CaptureComparisonReport:
    return compare_tcp_headers(
        CaptureHeaders(label="client", records=left),
        CaptureHeaders(label="server", records=right),
        alignment=alignment or ClockAlignment(basis="synchronized"),
        record_limit=limit,
    )


def test_unique_candidate_is_header_evidence_and_round_trips() -> None:
    report = compare((header(),), (header(frame=20),))
    (row,) = report.comparisons
    assert row.status is ComparisonStatus.UNIQUE
    assert row.header.frame_number == 1
    assert row.candidates[0].frame_number == 20
    assert row.reverse_candidate_count == 1
    assert (
        "HEADER_CORRESPONDENCE_IS_NOT_PACKET_OR_PAYLOAD_IDENTITY" in report.limitations
    )
    assert report.recommendations
    assert (
        CaptureComparisonReport.model_validate_json(report.model_dump_json()) == report
    )
    assert report == compare((header(),), (header(frame=20),))


@pytest.mark.parametrize("left_count,right_count", [(1, 2), (2, 1), (3, 4), (20, 20)])
def test_repeated_headers_remain_ambiguous(left_count: int, right_count: int) -> None:
    left = tuple(header(i) for i in range(1, left_count + 1))
    right = tuple(header(i) for i in range(1, right_count + 1))
    report = compare(left, right)
    assert len(report.comparisons) == left_count
    for row in report.comparisons:
        assert row.status is ComparisonStatus.AMBIGUOUS
        assert row.candidate_count == right_count
        assert len(row.candidates) == min(right_count, 8)
        assert row.omitted_candidates == max(0, right_count - 8)
        if right_count == 1:
            assert row.reverse_candidate_count == left_count
    assert report == compare(tuple(reversed(left)), tuple(reversed(right)))


@pytest.mark.parametrize(
    "field,value",
    [
        ("source_address", IPv4Address("192.0.2.11")),
        ("source_port", 49153),
        ("destination_port", 8443),
        ("sequence", 0),
        ("acknowledgment", 100),
        ("flags", 20),
        ("payload_length", 40),
    ],
)
def test_nat_reuse_segmentation_or_header_differences_are_not_forced(
    field: str,
    value: object,
) -> None:
    rows = compare((header(),), (header(**{field: value}),)).comparisons
    assert [x.status for x in rows] == [
        ComparisonStatus.LEFT_ONLY,
        ComparisonStatus.RIGHT_ONLY,
    ]
    assert all(not x.candidates for x in rows)


def test_direction_and_ipv6_are_preserved() -> None:
    a = header(
        source_address=IPv6Address("2001:db8::1"),
        destination_address=IPv6Address("2001:db8::2"),
    )
    b = header(
        source_address=a.destination_address,
        destination_address=a.source_address,
        source_port=a.destination_port,
        destination_port=a.source_port,
    )
    report = compare(
        (a, b.model_copy(update={"frame_number": 2})),
        (b.model_copy(update={"frame_number": 8}), a),
    )
    assert all(x.status is ComparisonStatus.UNIQUE for x in report.comparisons)
    assert [x.candidates[0].frame_number for x in report.comparisons] == [1, 8]


@pytest.mark.parametrize(
    "delta,expected", [(9, True), (10, True), (11, False), (-10, True)]
)
def test_offset_sign_and_inclusive_window(delta: int, expected: bool) -> None:
    report = compare(
        (header(time=1000),),
        (header(time=2000 + delta),),
        ClockAlignment(basis="user_offset", right_offset_ns=-1000, tolerance_ns=10),
    )
    assert (report.comparisons[0].status is ComparisonStatus.UNIQUE) == expected
    assert report.alignment.right_offset_ns == -1000


def test_unknown_clocks_never_match_or_assert_absence() -> None:
    rows = compare((header(),), (header(),), ClockAlignment()).comparisons
    assert len(rows) == 2
    assert all(x.status is ComparisonStatus.NOT_COMPARABLE for x in rows)


def test_capacity_and_external_tracking_limits_disable_conclusions() -> None:
    report = compare((header(1), header(2)), (header(),), limit=1)
    assert report.left_omitted_records == 1
    assert not report.tracking_complete
    assert all(x.status is ComparisonStatus.NOT_COMPARABLE for x in report.comparisons)
    external = compare_tcp_headers(
        CaptureHeaders(
            label="left",
            records=(header(),),
            tracking_complete=False,
            omitted_records=12,
        ),
        CaptureHeaders(label="right", records=(header(),)),
        alignment=ClockAlignment(basis="synchronized"),
    )
    assert external.left_omitted_records == 12
    assert "TRACKING_INCOMPLETE" in external.limitations


def test_truncation_disables_unique_and_one_sided_claims() -> None:
    report = compare((header(),), (header(truncated=True),))
    assert all(x.status is ComparisonStatus.NOT_COMPARABLE for x in report.comparisons)


def test_regression_is_reported_and_drift_is_not_corrected() -> None:
    report = compare(
        (header(1, 1000), header(2, 900)), (header(1, 1000), header(2, 4000))
    )
    assert "TIMESTAMP_REGRESSION" in report.limitations
    assert (
        "CLOCK_OFFSET_DOES_NOT_CORRECT_DRIFT_OR_ESTABLISH_LATENCY" in report.limitations
    )
    assert any(x.status is ComparisonStatus.LEFT_ONLY for x in report.comparisons)
    assert any(x.status is ComparisonStatus.RIGHT_ONLY for x in report.comparisons)


def test_empty_captures_do_not_create_evidence() -> None:
    assert compare((), ()).comparisons == ()
    assert compare((), (header(),)).comparisons[0].status is ComparisonStatus.RIGHT_ONLY


def test_quality_context_and_large_ambiguous_group() -> None:
    records = tuple(header(frame=i) for i in range(1, 2001))
    report = compare_tcp_headers(
        CaptureHeaders(label="left", records=(header(),), quality_limited=True),
        CaptureHeaders(label="right", records=records),
        alignment=ClockAlignment(basis="synchronized"),
    )
    assert report.left_quality_limited and not report.right_quality_limited
    assert "CAPTURE_QUALITY_LIMITED" in report.limitations
    assert report.comparisons[0].candidate_count == 2000
    assert len(report.comparisons[0].candidates) == 8
    assert report.comparisons[0].omitted_candidates == 1992


def test_records_are_immutable_and_labels_distinct() -> None:
    record = header()
    with pytest.raises(ValidationError, match="frozen"):
        record.sequence = 0
    with pytest.raises(ValueError, match="distinct"):
        compare_tcp_headers(
            CaptureHeaders(label="same", records=()),
            CaptureHeaders(label="same", records=()),
            alignment=ClockAlignment(),
        )


@pytest.mark.parametrize(
    "values",
    [
        {"sequence": -1},
        {"sequence": 2**32},
        {"source_port": 65536},
        {"timestamp_ns": float("nan")},
        {"timestamp_ns": -1},
        {"destination_address": IPv6Address("2001:db8::1")},
        {"payload": "private"},
        {"path": "/private/capture.pcapng"},
    ],
)
def test_invalid_or_unapproved_header_fields_are_rejected(
    values: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        header(**values)


def test_model_privacy_duplicates_and_clock_provenance() -> None:
    for label in ("", " ", "client\x1b[31m", "client\nserver"):
        with pytest.raises(ValidationError):
            CaptureHeaders(label=label, records=())
    with pytest.raises(ValidationError, match="unique"):
        CaptureHeaders(label="client", records=(header(), header()))
    with pytest.raises(ValidationError):
        ClockAlignment(basis="synchronized", right_offset_ns=1)
    with pytest.raises(ValidationError):
        ClockAlignment(tolerance_ns=-1)
    with pytest.raises(ValidationError):
        CaptureHeaders(label="client", records=(), omitted_records=1)


@pytest.mark.parametrize("limit", [0, -1, 100001, True, 1.5])
def test_invalid_record_limits(limit: int) -> None:
    with pytest.raises(ValueError, match="record_limit"):
        compare((), (), limit=limit)
