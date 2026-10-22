"""Tests for deterministic capture-quality assessment."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from packet_investigator import __version__
from packet_investigator.analyzers.capture_quality import analyze_capture_quality
from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.models.capture_quality import (
    CaptureQualityAssessment,
    CaptureQualityStatistics,
    CaptureQualityStatus,
)
from packet_investigator.parsers.capture_quality import (
    CaptureQualityCollection,
    ChecksumCapabilities,
)


def _metadata(
    *,
    packet_count: int = 20,
    duration_seconds: float | None = 2.0,
) -> CaptureMetadata:
    start_time = (
        None
        if duration_seconds is None
        else datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC)
    )
    end_time = (
        None if start_time is None else start_time + timedelta(seconds=duration_seconds)
    )
    return CaptureMetadata(
        path=(Path.cwd() / "synthetic/example.pcapng").resolve(),
        filename="example.pcapng",
        capture_format="PCAPNG",
        size_bytes=4096,
        packet_count=packet_count,
        start_time=start_time,
        end_time=end_time,
        duration_seconds=duration_seconds,
        interface_ids=("0",),
        tshark_version="4.6.6",
        status="Inspection complete",
    )


def _collection(
    *,
    rows_processed: int = 20,
    tcp_packets: int = 0,
    tcp_syn_packets: int = 0,
    tracked_tcp_flows: int = 0,
    flow_tracking_complete: bool = True,
    candidate_midstream_flows: int = 0,
    truncated_frames: int = 0,
    checksum_warning_frames: int = 0,
    checksum_rule_enabled: bool = True,
    supported_checksum_protocols: tuple[str, ...] = ("tcp", "udp", "ipv4"),
    unsupported_checksum_protocols: tuple[str, ...] = (),
) -> CaptureQualityCollection:
    return CaptureQualityCollection(
        statistics=CaptureQualityStatistics(
            rows_processed=rows_processed,
            tcp_packets=tcp_packets,
            tcp_syn_packets=tcp_syn_packets,
            tracked_tcp_flows=tracked_tcp_flows,
            flow_tracking_limit=50_000,
            flow_tracking_complete=flow_tracking_complete,
            candidate_midstream_flows=candidate_midstream_flows,
            incomplete_handshake_flows=0,
            truncated_frames=truncated_frames,
            checksum_warning_frames=checksum_warning_frames,
            checksum_rule_enabled=checksum_rule_enabled,
            timestamp_regressions=0,
            interface_ids_observed=1 if rows_processed else 0,
        ),
        interface_ids=("0",) if rows_processed else (),
        first_timestamp=(
            datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC) if rows_processed else None
        ),
        final_timestamp=(
            datetime(2026, 7, 25, 14, 3, 20, tzinfo=UTC) if rows_processed else None
        ),
        checksum_capabilities=ChecksumCapabilities(
            supported_protocols=supported_checksum_protocols,
            unsupported_protocols=unsupported_checksum_protocols,
        ),
    )


def _analyze(
    *,
    packet_count: int = 20,
    duration_seconds: float | None = 2.0,
    collection: CaptureQualityCollection | None = None,
    **options: object,
) -> CaptureQualityAssessment:
    metadata = _metadata(
        packet_count=packet_count,
        duration_seconds=duration_seconds,
    )
    selected_collection = collection or _collection(rows_processed=packet_count)
    return analyze_capture_quality(metadata, selected_collection, **options)


def _finding(
    assessment: CaptureQualityAssessment,
    code: str,
) -> object:
    return next(finding for finding in assessment.findings if finding.code == code)


def _codes(models: object) -> tuple[str, ...]:
    return tuple(model.code for model in models)


def test_empty_capture_is_insufficient_without_short_finding() -> None:
    assessment = _analyze(
        packet_count=0,
        duration_seconds=None,
        collection=_collection(rows_processed=0),
    )

    assert assessment.status is CaptureQualityStatus.INSUFFICIENT
    assert _codes(assessment.findings) == ("EMPTY_CAPTURE",)
    assert assessment.findings[0].evidence == {
        "packet_count": 0,
        "rows_processed": 0,
    }


@pytest.mark.parametrize(
    ("packet_count", "expected_status", "expect_short"),
    [
        (1, CaptureQualityStatus.LIMITED, True),
        (2, CaptureQualityStatus.USABLE_WITH_LIMITATIONS, True),
        (9, CaptureQualityStatus.USABLE_WITH_LIMITATIONS, True),
        (10, CaptureQualityStatus.USABLE, False),
    ],
)
def test_packet_count_short_boundaries(
    packet_count: int,
    expected_status: CaptureQualityStatus,
    expect_short: bool,
) -> None:
    assessment = _analyze(packet_count=packet_count)

    assert assessment.status is expected_status
    assert ("VERY_SHORT_CAPTURE" in _codes(assessment.findings)) is expect_short


@pytest.mark.parametrize(
    ("duration", "expect_short"),
    [
        (0.999, True),
        (1.0, False),
    ],
)
def test_duration_short_boundary(duration: float, expect_short: bool) -> None:
    assessment = _analyze(packet_count=10, duration_seconds=duration)

    assert ("VERY_SHORT_CAPTURE" in _codes(assessment.findings)) is expect_short


def test_threshold_overrides_are_reflected_in_evidence() -> None:
    assessment = _analyze(
        packet_count=12,
        duration_seconds=3.0,
        short_packet_count=15,
        short_duration_seconds=4.0,
    )
    finding = _finding(assessment, "VERY_SHORT_CAPTURE")

    assert finding.evidence["effective_packet_count_threshold"] == 15
    assert finding.evidence["effective_duration_threshold_seconds"] == 4.0


@pytest.mark.parametrize(
    ("options", "error_type"),
    [
        ({"short_packet_count": 0}, ValueError),
        ({"short_packet_count": -1}, ValueError),
        ({"short_packet_count": True}, TypeError),
        ({"short_packet_count": 1.5}, TypeError),
        ({"short_duration_seconds": -0.1}, ValueError),
        ({"short_duration_seconds": float("inf")}, ValueError),
        ({"short_duration_seconds": float("nan")}, ValueError),
        ({"short_duration_seconds": True}, TypeError),
    ],
)
def test_invalid_thresholds_are_rejected(
    options: dict[str, object],
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        _analyze(**options)


def test_tcp_without_syn_produces_broad_finding() -> None:
    assessment = _analyze(
        collection=_collection(
            tcp_packets=10,
            tcp_syn_packets=0,
            tracked_tcp_flows=5,
        )
    )

    finding = _finding(assessment, "NO_TCP_SYN_OBSERVED")
    assert finding.evidence["tcp_packets"] == 10
    assert "definitely" not in (finding.interpretation or "").lower()


def test_complete_midstream_finding_suppresses_broad_no_syn() -> None:
    assessment = _analyze(
        collection=_collection(
            tcp_packets=20,
            tcp_syn_packets=0,
            tracked_tcp_flows=20,
            candidate_midstream_flows=5,
        )
    )

    assert _codes(assessment.findings) == ("MIDSTREAM_TCP_OBSERVED",)
    assert assessment.statistics.tcp_syn_packets == 0


def test_incomplete_tracking_keeps_broad_no_syn_finding() -> None:
    assessment = _analyze(
        collection=_collection(
            tcp_packets=20,
            tcp_syn_packets=0,
            tracked_tcp_flows=20,
            flow_tracking_complete=False,
            candidate_midstream_flows=5,
        )
    )

    assert _codes(assessment.findings)[:2] == (
        "NO_TCP_SYN_OBSERVED",
        "MIDSTREAM_TCP_OBSERVED",
    )


@pytest.mark.parametrize(
    (
        "tracked_flows",
        "candidate_flows",
        "tracking_complete",
        "expected_status",
    ),
    [
        (19, 10, True, CaptureQualityStatus.USABLE_WITH_LIMITATIONS),
        (20, 4, True, CaptureQualityStatus.USABLE_WITH_LIMITATIONS),
        (20, 5, True, CaptureQualityStatus.LIMITED),
        (20, 5, False, CaptureQualityStatus.USABLE_WITH_LIMITATIONS),
    ],
)
def test_midstream_status_boundaries(
    tracked_flows: int,
    candidate_flows: int,
    tracking_complete: bool,
    expected_status: CaptureQualityStatus,
) -> None:
    assessment = _analyze(
        collection=_collection(
            tcp_packets=20,
            tcp_syn_packets=1,
            tracked_tcp_flows=tracked_flows,
            flow_tracking_complete=tracking_complete,
            candidate_midstream_flows=candidate_flows,
        )
    )

    assert assessment.status is expected_status
    assert "MIDSTREAM_TCP_OBSERVED" in _codes(assessment.findings)


def test_midstream_evidence_contains_effective_values() -> None:
    assessment = _analyze(
        collection=_collection(
            tcp_packets=20,
            tcp_syn_packets=1,
            tracked_tcp_flows=20,
            candidate_midstream_flows=5,
        )
    )
    evidence = _finding(assessment, "MIDSTREAM_TCP_OBSERVED").evidence

    assert evidence == {
        "candidate_midstream_flows": 5,
        "tracked_tcp_flows": 20,
        "candidate_midstream_percentage": 25.0,
        "percentage_escalation_threshold": 25,
        "percentage_escalation_minimum_tracked_flows": 20,
        "flow_tracking_complete": True,
        "flow_tracking_limit": 50_000,
    }


def test_flow_cap_limitation_appears_exactly_once() -> None:
    assessment = _analyze(
        collection=_collection(
            tcp_packets=50_000,
            tracked_tcp_flows=50_000,
            flow_tracking_complete=False,
            candidate_midstream_flows=1,
        )
    )

    assert _codes(assessment.limitations).count("FLOW_TRACKING_LIMIT_REACHED") == 1


@pytest.mark.parametrize(
    ("rows", "truncated", "expected_status"),
    [
        (11, 1, CaptureQualityStatus.USABLE_WITH_LIMITATIONS),
        (10, 1, CaptureQualityStatus.LIMITED),
        (1, 1, CaptureQualityStatus.LIMITED),
    ],
)
def test_truncation_status_boundaries(
    rows: int,
    truncated: int,
    expected_status: CaptureQualityStatus,
) -> None:
    assessment = _analyze(
        packet_count=rows,
        collection=_collection(
            rows_processed=rows,
            truncated_frames=truncated,
        ),
    )

    assert assessment.status is expected_status
    assert "PACKET_TRUNCATION_OBSERVED" in _codes(assessment.findings)


def test_truncation_evidence_contains_threshold() -> None:
    assessment = _analyze(collection=_collection(rows_processed=20, truncated_frames=2))
    evidence = _finding(assessment, "PACKET_TRUNCATION_OBSERVED").evidence

    assert evidence == {
        "truncated_frames": 2,
        "rows_processed": 20,
        "truncated_frame_percentage": 10.0,
        "limited_status_threshold_percentage": 10,
    }


def test_checksum_warnings_produce_cautious_finding() -> None:
    assessment = _analyze(collection=_collection(checksum_warning_frames=2))
    finding = _finding(assessment, "CHECKSUM_OFFLOAD_POSSIBLE")
    wording = f"{finding.observation} {finding.interpretation}".lower()

    assert "may result from checksum offload" in wording
    assert "do not by themselves prove on-wire corruption" in wording


def test_no_checksum_capability_adds_limitation_without_finding() -> None:
    assessment = _analyze(
        collection=_collection(
            checksum_rule_enabled=False,
            supported_checksum_protocols=(),
            unsupported_checksum_protocols=("tcp", "udp", "ipv4"),
        )
    )

    assert "CHECKSUM_OFFLOAD_POSSIBLE" not in _codes(assessment.findings)
    assert "CHECKSUM_FIELDS_UNAVAILABLE" in _codes(assessment.limitations)
    assert assessment.status is CaptureQualityStatus.USABLE_WITH_LIMITATIONS


def test_partial_checksum_capability_adds_limitation() -> None:
    assessment = _analyze(
        collection=_collection(
            supported_checksum_protocols=("tcp",),
            unsupported_checksum_protocols=("udp", "ipv4"),
        )
    )

    assert "CHECKSUM_FIELDS_PARTIAL" in _codes(assessment.limitations)


def test_recommendations_are_deduplicated_and_resolve() -> None:
    assessment = _analyze(
        collection=_collection(
            tcp_packets=20,
            tcp_syn_packets=0,
            tracked_tcp_flows=20,
            flow_tracking_complete=False,
            candidate_midstream_flows=5,
        )
    )
    recommendation_codes = _codes(assessment.recommendations)

    assert len(recommendation_codes) == len(set(recommendation_codes))
    assert {
        code for finding in assessment.findings for code in finding.recommendation_codes
    } == set(recommendation_codes)


def test_findings_and_limitations_have_deterministic_order() -> None:
    assessment = _analyze(
        packet_count=9,
        duration_seconds=0.5,
        collection=_collection(
            rows_processed=9,
            tcp_packets=9,
            tcp_syn_packets=0,
            tracked_tcp_flows=9,
            flow_tracking_complete=False,
            candidate_midstream_flows=2,
            truncated_frames=1,
            checksum_warning_frames=1,
            supported_checksum_protocols=("tcp",),
            unsupported_checksum_protocols=("udp", "ipv4"),
        ),
    )

    assert _codes(assessment.findings) == (
        "VERY_SHORT_CAPTURE",
        "NO_TCP_SYN_OBSERVED",
        "MIDSTREAM_TCP_OBSERVED",
        "PACKET_TRUNCATION_OBSERVED",
        "CHECKSUM_OFFLOAD_POSSIBLE",
    )
    assert _codes(assessment.limitations) == (
        "FLOW_TRACKING_LIMIT_REACHED",
        "MIDSTREAM_PERCENTAGE_NOT_APPLIED",
        "CHECKSUM_FIELDS_PARTIAL",
    )


def test_assessment_serialization_and_analysis_are_deterministic() -> None:
    metadata = _metadata()
    collection = _collection(
        tcp_packets=20,
        tcp_syn_packets=1,
        tracked_tcp_flows=20,
        candidate_midstream_flows=4,
    )

    first = analyze_capture_quality(metadata, collection)
    second = analyze_capture_quality(metadata, collection)

    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.tool_version == __version__


def test_path_privacy_is_explicit() -> None:
    metadata = _metadata()
    collection = _collection()

    private = analyze_capture_quality(metadata, collection)
    disclosed = analyze_capture_quality(metadata, collection, include_path=True)
    private_json = json.loads(private.model_dump_json())
    disclosed_json = json.loads(disclosed.model_dump_json())

    assert "path" not in private_json["capture"]
    assert disclosed_json["capture"]["path"] == str(metadata.path)


def test_existing_metadata_contract_and_inputs_are_unchanged() -> None:
    metadata = _metadata()
    collection = _collection(
        tcp_packets=20,
        tcp_syn_packets=1,
        tracked_tcp_flows=20,
        candidate_midstream_flows=4,
    )
    metadata_json = metadata.model_dump_json()
    statistics = collection.statistics
    capabilities = collection.checksum_capabilities

    analyze_capture_quality(metadata, collection)

    assert metadata.model_dump_json() == metadata_json
    assert collection.statistics == statistics
    assert collection.checksum_capabilities == capabilities
    assert "status" in json.loads(metadata_json)
    assert "inspection_status" not in json.loads(metadata_json)
