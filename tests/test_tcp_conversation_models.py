"""Tests for immutable TCP conversation-analysis domain models."""

from __future__ import annotations

import json
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from ipaddress import IPv4Address, IPv6Address
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.tcp_conversations import (
    Endpoint,
    TCPAnalysisReport,
    TCPAnalysisStatistics,
    TCPAnalysisStatus,
    TCPClosureAssessment,
    TCPClosureState,
    TCPConversationAssessment,
    TCPConversationEvidence,
    TCPConversationFinding,
    TCPConversationIdentity,
    TCPConversationLimitation,
    TCPConversationRecommendation,
    TCPConversationStatistics,
    TCPConversationStatus,
    TCPConversationTiming,
    TCPDirection,
    TCPDirectionalStatistics,
    TCPEvidenceProvenance,
    TCPFindingCategory,
    TCPFindingSeverity,
    TCPGroupingBasis,
    TCPHandshakeAssessment,
    TCPHandshakeState,
    TCPRole,
    TCPRoleEvidence,
    TCPRoleEvidenceBasis,
    TCPRoleEvidenceStrength,
    TCPSymptomCounters,
    TCPTimingAvailability,
)

_START = datetime(2026, 8, 1, 14, 0, tzinfo=UTC)
_END = _START + timedelta(seconds=1)


def _endpoint_a() -> Endpoint:
    return Endpoint(ip_version=4, address=IPv4Address("192.0.2.10"), port=443)


def _endpoint_b() -> Endpoint:
    return Endpoint(ip_version=4, address=IPv4Address("198.51.100.20"), port=49_152)


def _directional(
    direction: TCPDirection,
    *,
    first_frame: int,
    last_frame: int,
) -> TCPDirectionalStatistics:
    return TCPDirectionalStatistics(
        direction=direction,
        packets=5,
        captured_bytes=500,
        original_frame_bytes=500,
        payload_bytes=128,
        first_frame=first_frame,
        last_frame=last_frame,
        first_time=_START,
        last_time=_END,
        first_payload_frame=4,
        first_payload_time=_START + timedelta(milliseconds=300),
        minimum_window_value=1024,
        maximum_window_value=65_535,
        minimum_effective_window=1024,
        maximum_effective_window=131_070,
    )


def _identity() -> TCPConversationIdentity:
    return TCPConversationIdentity(
        conversation_id="tcp-000001",
        endpoint_a=_endpoint_a(),
        endpoint_b=_endpoint_b(),
        protocol="tcp",
        epoch=1,
        grouping_basis=TCPGroupingBasis.STREAM_AND_TUPLE,
    )


def _roles() -> TCPRoleEvidence:
    return TCPRoleEvidence(
        observed_initiator="b",
        inferred_client="b",
        inferred_server="a",
        endpoint_a_role=TCPRole.SERVER,
        endpoint_b_role=TCPRole.CLIENT,
        strength=TCPRoleEvidenceStrength.SUPPORTED,
        basis=(
            TCPRoleEvidenceBasis.SYN_WITHOUT_ACK,
            TCPRoleEvidenceBasis.SYN_ACK_RESPONSE,
        ),
        observation="Endpoint B sent the first observed SYN without ACK.",
    )


def _statistics() -> TCPConversationStatistics:
    return TCPConversationStatistics(
        first_frame=1,
        last_frame=10,
        first_time=_START,
        last_time=_END,
        duration_seconds=1.0,
        a_to_b=_directional(TCPDirection.A_TO_B, first_frame=2, last_frame=10),
        b_to_a=_directional(TCPDirection.B_TO_A, first_frame=1, last_frame=9),
        interfaces=("0",),
        rows_with_optional_parse_errors=0,
    )


def _handshake() -> TCPHandshakeAssessment:
    return TCPHandshakeAssessment(
        state=TCPHandshakeState.COMPLETE,
        syn_frame=1,
        syn_ack_frame=2,
        final_ack_frame=3,
        syn_time=_START,
        syn_ack_time=_START + timedelta(milliseconds=50),
        final_ack_time=_START + timedelta(milliseconds=100),
        syn_retries=0,
        syn_ack_retries=0,
        syn_to_syn_ack_seconds=0.05,
        syn_ack_to_ack_seconds=0.05,
        sequence_matching_available=True,
        evidence_strength=TCPRoleEvidenceStrength.SUPPORTED,
        limitations=(),
    )


def _closure() -> TCPClosureAssessment:
    return TCPClosureAssessment(
        state=TCPClosureState.ORDERLY,
        first_fin_a_to_b_frame=7,
        first_fin_a_to_b_time=_START + timedelta(milliseconds=700),
        first_fin_b_to_a_frame=9,
        first_fin_b_to_a_time=_START + timedelta(milliseconds=900),
        fin_a_to_b_ack_frame=8,
        fin_b_to_a_ack_frame=10,
        first_reset_frame=None,
        first_reset_time=None,
        first_reset_direction=None,
        reset_count=0,
        limitations=(),
    )


def _symptoms() -> TCPSymptomCounters:
    return TCPSymptomCounters(
        retransmission_indicator_frames=0,
        fast_retransmission_indicator_frames=0,
        spurious_retransmission_indicator_frames=0,
        lost_segment_indicator_frames=0,
        ack_lost_segment_indicator_frames=0,
        duplicate_ack_indicator_frames=0,
        out_of_order_indicator_frames=0,
        zero_window_indicator_frames=0,
        window_full_indicator_frames=0,
        keepalive_indicator_frames=0,
        keepalive_ack_indicator_frames=0,
    )


def _timings() -> TCPConversationTiming:
    return TCPConversationTiming(
        conversation_duration_seconds=1.0,
        syn_to_syn_ack_seconds=0.05,
        syn_ack_to_final_ack_seconds=0.05,
        tshark_initial_rtt_seconds=0.1,
        time_to_first_payload_a_to_b_seconds=0.3,
        time_to_first_payload_b_to_a_seconds=0.4,
        availability=(
            TCPTimingAvailability.TIMING_OBSERVED,
            TCPTimingAvailability.TIMING_TSHARK_DERIVED,
        ),
    )


def _evidence(
    values: dict[str, int | float | str | bool | None] | None = None,
) -> TCPConversationEvidence:
    return TCPConversationEvidence(
        provenance=TCPEvidenceProvenance.TSHARK_DERIVED,
        values={"marked_frames": 2} if values is None else values,
        representative_frames=(5, 6),
    )


def _finding() -> TCPConversationFinding:
    return TCPConversationFinding(
        code="TCP_RETRANSMISSION_INDICATORS_OBSERVED",
        category=TCPFindingCategory.DELIVERY,
        severity=TCPFindingSeverity.WARNING,
        observation="TShark marked two frames with retransmission indicators.",
        interpretation=None,
        evidence_strength=TCPRoleEvidenceStrength.SUPPORTED,
        evidence=_evidence(),
        limitations=("TCP_TSHARK_ANALYSIS_DEPENDENCY",),
        recommendation_codes=("COMPARE_CAPTURE_POINTS",),
    )


def _limitation() -> TCPConversationLimitation:
    return TCPConversationLimitation(
        code="TCP_TSHARK_ANALYSIS_DEPENDENCY",
        description="The indicator depends on TShark sequence analysis.",
        affected_capabilities=("delivery_indicator_interpretation",),
    )


def _recommendation() -> TCPConversationRecommendation:
    return TCPConversationRecommendation(
        code="COMPARE_CAPTURE_POINTS",
        priority=1,
        action="Compare the same conversation at another capture point.",
        rationale="Comparison can distinguish observation-point effects.",
    )


def _conversation() -> TCPConversationAssessment:
    return TCPConversationAssessment(
        identity=_identity(),
        roles=_roles(),
        statistics=_statistics(),
        handshake=_handshake(),
        closure=_closure(),
        symptoms=_symptoms(),
        timings=_timings(),
        status=TCPConversationStatus.COMPLETE_WITH_FINDINGS,
        status_summary="The conversation is complete with one TCP finding.",
        findings=(_finding(),),
        limitations=(_limitation(),),
        recommendation_codes=("COMPARE_CAPTURE_POINTS",),
    )


def _analysis_statistics(
    finding_counts: dict[str, int] | None = None,
) -> TCPAnalysisStatistics:
    return TCPAnalysisStatistics(
        rows_processed=10,
        usable_tcp_rows=10,
        unusable_tcp_rows=0,
        malformed_optional_fields=0,
        tcp_conversations=1,
        tracked_conversation_limit=50_000,
        conversation_tracking_complete=True,
        untracked_conversation_rows=0,
        stream_tuple_conflicts=0,
        ambiguous_encapsulation_rows=0,
        complete_conversations=0,
        complete_with_findings_conversations=1,
        partial_conversations=0,
        limited_conversations=0,
        insufficient_conversations=0,
        finding_counts=(
            {"TCP_RETRANSMISSION_INDICATORS_OBSERVED": 1}
            if finding_counts is None
            else finding_counts
        ),
        retained_parser_warnings=0,
        total_parser_warnings=0,
        supported_derived_capabilities=("retransmission_indicators",),
        unsupported_derived_capabilities=(),
        interface_ids_observed=("0",),
    )


def _capture(*, path: Path | None = None) -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename="synthetic-handshake-close.pcapng",
        path=path,
        capture_format="PCAPNG",
        size_bytes=2048,
        packet_count=10,
        start_time=_START,
        end_time=_END,
        duration_seconds=1.0,
        interface_ids=("0",),
        tshark_version="4.6.6",
        inspection_status="Inspection complete",
    )


def _report(*, path: Path | None = None) -> TCPAnalysisReport:
    return TCPAnalysisReport(
        schema_version="1.0",
        tool_version="0.5.0",
        capture=_capture(path=path),
        capture_quality_status=CaptureQualityStatus.USABLE,
        capture_quality_limitation_codes=(),
        status=TCPAnalysisStatus.ANALYZED_WITH_FINDINGS,
        summary="One TCP conversation was analyzed with one finding.",
        analysis_statistics=_analysis_statistics(),
        limitations=(_limitation(),),
        conversations=(_conversation(),),
        recommendations=(_recommendation(),),
    )


@pytest.mark.parametrize(
    ("enum_type", "expected_values"),
    [
        (TCPGroupingBasis, ["stream_and_tuple", "tuple_epoch"]),
        (TCPDirection, ["a_to_b", "b_to_a", "unknown"]),
        (TCPRole, ["client", "server", "unknown", "ambiguous"]),
        (
            TCPRoleEvidenceStrength,
            ["observed", "supported", "suggested", "unknown"],
        ),
        (
            TCPRoleEvidenceBasis,
            [
                "syn_without_ack",
                "syn_ack_response",
                "system_to_dynamic_port",
                "simultaneous_open",
                "midstream",
            ],
        ),
        (
            TCPHandshakeState,
            [
                "complete",
                "incomplete",
                "midstream",
                "simultaneous_open",
                "not_observed",
                "ambiguous",
            ],
        ),
        (
            TCPClosureState,
            ["orderly", "reset", "fin_incomplete", "not_observed", "ambiguous"],
        ),
        (
            TCPTimingAvailability,
            [
                "timing_observed",
                "timing_not_available",
                "timing_limited_by_midstream_capture",
                "timing_limited_by_missing_direction",
                "timing_limited_by_timestamp_quality",
                "timing_tshark_derived",
            ],
        ),
        (
            TCPEvidenceProvenance,
            ["raw_header", "tshark_derived", "packet_investigator_derived"],
        ),
        (
            TCPFindingCategory,
            ["handshake", "termination", "delivery", "flow_control", "activity"],
        ),
        (TCPFindingSeverity, ["informational", "warning"]),
        (
            TCPConversationStatus,
            [
                "complete",
                "complete_with_findings",
                "partial",
                "limited",
                "insufficient",
            ],
        ),
        (
            TCPAnalysisStatus,
            ["analyzed", "analyzed_with_findings", "limited", "insufficient"],
        ),
    ],
)
def test_enum_values_match_schema(
    enum_type: type[StrEnum],
    expected_values: list[str],
) -> None:
    assert [member.value for member in enum_type] == expected_values


@pytest.mark.parametrize(
    "model",
    [
        _endpoint_a(),
        _identity(),
        _roles(),
        _directional(TCPDirection.A_TO_B, first_frame=1, last_frame=10),
        _statistics(),
        _handshake(),
        _closure(),
        _symptoms(),
        _timings(),
        _evidence(),
        _finding(),
        _limitation(),
        _recommendation(),
        _conversation(),
        _analysis_statistics(),
        _report(),
    ],
)
def test_public_models_are_immutable(model: BaseModel) -> None:
    field_name = next(iter(type(model).model_fields))

    with pytest.raises(ValidationError):
        setattr(model, field_name, None)


def test_endpoint_validates_version_port_and_canonical_serialization() -> None:
    endpoint = Endpoint(
        ip_version=6,
        address=IPv6Address("2001:0db8:0000::1"),
        port=65_535,
    )

    assert json.loads(endpoint.model_dump_json()) == {
        "ip_version": 6,
        "address": "2001:db8::1",
        "port": 65_535,
    }
    with pytest.raises(ValidationError, match="must match"):
        Endpoint(ip_version=4, address=IPv6Address("2001:db8::1"), port=443)
    with pytest.raises(ValidationError):
        Endpoint(ip_version=4, address=IPv4Address("192.0.2.1"), port=65_536)
    with pytest.raises(ValidationError):
        Endpoint(ip_version=4, address=IPv4Address("192.0.2.1"), port=True)


@pytest.mark.parametrize("conversation_id", ["tcp-00001", "tcp-abcdef", "TCP-000001"])
def test_identity_rejects_invalid_conversation_id(conversation_id: str) -> None:
    values = _identity().model_dump()
    values["conversation_id"] = conversation_id

    with pytest.raises(ValidationError):
        TCPConversationIdentity.model_validate(values)


def test_identity_requires_canonical_endpoint_order() -> None:
    with pytest.raises(ValidationError, match="canonical order"):
        TCPConversationIdentity(
            conversation_id="tcp-000001",
            endpoint_a=_endpoint_b(),
            endpoint_b=_endpoint_a(),
            protocol="tcp",
            epoch=1,
            grouping_basis=TCPGroupingBasis.STREAM_AND_TUPLE,
        )


@pytest.mark.parametrize(
    ("model_type", "factory", "field_name"),
    [
        (
            TCPDirectionalStatistics,
            lambda: _directional(
                TCPDirection.A_TO_B,
                first_frame=1,
                last_frame=2,
            ),
            "packets",
        ),
        (TCPHandshakeAssessment, _handshake, "syn_retries"),
        (TCPClosureAssessment, _closure, "reset_count"),
        (TCPSymptomCounters, _symptoms, "duplicate_ack_indicator_frames"),
        (TCPAnalysisStatistics, _analysis_statistics, "rows_processed"),
    ],
)
def test_counter_fields_reject_negative_and_boolean_values(
    model_type: type[BaseModel],
    factory: Callable[[], BaseModel],
    field_name: str,
) -> None:
    values = factory().model_dump()
    for invalid_value in (-1, True):
        values[field_name] = invalid_value
        with pytest.raises(ValidationError):
            model_type.model_validate(values)


def test_timestamp_fields_require_timezone_awareness() -> None:
    values = _statistics().model_dump()
    values["first_time"] = datetime(2026, 8, 1, 14, 0)

    with pytest.raises(ValidationError):
        TCPConversationStatistics.model_validate(values)


def test_structural_ranges_must_be_ordered() -> None:
    values = _statistics().model_dump()
    values["last_frame"] = 1
    values["first_frame"] = 2

    with pytest.raises(ValidationError, match="must not precede"):
        TCPConversationStatistics.model_validate(values)


def test_timestamp_regression_can_be_represented_for_limited_timing_analysis() -> None:
    values = _statistics().model_dump()
    values["last_time"] = values["first_time"] - timedelta(milliseconds=1)
    values["duration_seconds"] = None

    statistics = TCPConversationStatistics.model_validate(values)

    assert statistics.last_time < statistics.first_time
    assert statistics.duration_seconds is None


def test_timestamp_regression_rejects_a_derived_duration() -> None:
    values = _statistics().model_dump()
    values["last_time"] = values["first_time"] - timedelta(milliseconds=1)

    with pytest.raises(ValidationError, match="duration_seconds must be absent"):
        TCPConversationStatistics.model_validate(values)


def test_directional_timestamp_regression_can_be_represented() -> None:
    values = _directional(
        TCPDirection.A_TO_B,
        first_frame=1,
        last_frame=2,
    ).model_dump()
    values["last_time"] = values["first_time"] - timedelta(milliseconds=1)

    statistics = TCPDirectionalStatistics.model_validate(values)

    assert statistics.last_time < statistics.first_time


@pytest.mark.parametrize(
    "frames",
    [
        (1, 1),
        (2, 1),
        tuple(range(1, 10)),
        (0,),
    ],
)
def test_representative_frames_require_positive_sorted_unique_bound(
    frames: tuple[int, ...],
) -> None:
    values = _evidence().model_dump()
    values["representative_frames"] = frames

    with pytest.raises(ValidationError):
        TCPConversationEvidence.model_validate(values)


def test_evidence_is_defensively_copied_and_serializes_as_object() -> None:
    values: dict[str, int | float | str | bool | None] = {"marked_frames": 2}
    evidence = _evidence(values)
    values["marked_frames"] = 99

    assert evidence.values["marked_frames"] == 2
    assert json.loads(evidence.model_dump_json())["values"] == {"marked_frames": 2}
    with pytest.raises(TypeError):
        evidence.values["new"] = 1  # type: ignore[index]


def test_finding_counts_are_defensively_copied_and_validated() -> None:
    counts = {"FUTURE_FINDING": 2}
    statistics = _analysis_statistics(counts)
    counts["FUTURE_FINDING"] = 99

    assert statistics.finding_counts["FUTURE_FINDING"] == 2
    assert json.loads(statistics.model_dump_json())["finding_counts"] == {
        "FUTURE_FINDING": 2
    }
    with pytest.raises(ValidationError):
        _analysis_statistics({"lowercase": 1})
    with pytest.raises(ValidationError):
        _analysis_statistics({"FUTURE_FINDING": True})


def test_unknown_valid_finding_code_is_preserved() -> None:
    values = _finding().model_dump()
    values["code"] = "TCP_FUTURE_VALID_FINDING"

    finding = TCPConversationFinding.model_validate(values)

    assert finding.code == "TCP_FUTURE_VALID_FINDING"


@pytest.mark.parametrize("code", ["", "lowercase", "HAS-HYPHEN", "_PREFIX"])
def test_machine_codes_are_validated(code: str) -> None:
    values = _finding().model_dump()
    values["code"] = code

    with pytest.raises(ValidationError):
        TCPConversationFinding.model_validate(values)


@pytest.mark.parametrize("priority", [0, -1, True])
def test_recommendation_priority_is_a_strict_positive_integer(
    priority: int,
) -> None:
    values = _recommendation().model_dump()
    values["priority"] = priority

    with pytest.raises(ValidationError):
        TCPConversationRecommendation.model_validate(values)


def test_optional_measurements_and_interpretation_serialize_as_null() -> None:
    directional = TCPDirectionalStatistics(
        direction=TCPDirection.A_TO_B,
        packets=0,
        captured_bytes=0,
        original_frame_bytes=0,
        payload_bytes=0,
        first_frame=None,
        last_frame=None,
        first_time=None,
        last_time=None,
        first_payload_frame=None,
        first_payload_time=None,
        minimum_window_value=None,
        maximum_window_value=None,
        minimum_effective_window=None,
        maximum_effective_window=None,
    )
    serialized_directional = json.loads(directional.model_dump_json())
    serialized_finding = json.loads(_finding().model_dump_json())

    assert serialized_directional["first_time"] is None
    assert serialized_directional["minimum_window_value"] is None
    assert serialized_finding["interpretation"] is None


def test_collections_serialize_as_json_arrays_in_stored_order() -> None:
    serialized = json.loads(_report().model_dump_json())

    assert serialized["conversations"][0]["roles"]["basis"] == [
        "syn_without_ack",
        "syn_ack_response",
    ]
    assert serialized["conversations"][0]["findings"][0]["evidence"][
        "representative_frames"
    ] == [5, 6]
    assert isinstance(serialized["recommendations"], list)


def test_report_omits_absent_capture_path() -> None:
    assert "path" not in json.loads(_report().model_dump_json())["capture"]


def test_report_includes_explicit_capture_path(tmp_path: Path) -> None:
    capture_path = (tmp_path / "synthetic.pcapng").resolve()

    serialized = json.loads(_report(path=capture_path).model_dump_json())

    assert serialized["capture"]["path"] == str(capture_path)


def test_report_rejects_unknown_schema_version() -> None:
    values = _report().model_dump()
    values["schema_version"] = "2.0"

    with pytest.raises(ValidationError):
        TCPAnalysisReport.model_validate(values)


def test_report_json_schema_exposes_required_contract_fields() -> None:
    schema = TCPAnalysisReport.model_json_schema()

    assert schema["properties"]["schema_version"]["const"] == "1.0"
    assert schema["properties"]["capture"]["$ref"].endswith("/CaptureQualityCapture")
    assert schema["properties"]["conversations"]["type"] == "array"
    assert set(schema["required"]) == {
        "schema_version",
        "tool_version",
        "capture",
        "capture_quality_status",
        "capture_quality_limitation_codes",
        "status",
        "summary",
        "analysis_statistics",
        "limitations",
        "conversations",
        "recommendations",
    }


def test_complete_schema_example_is_deterministic_and_round_trips() -> None:
    report = _report()
    first_json = report.model_dump_json()
    second_json = report.model_dump_json()

    restored = TCPAnalysisReport.model_validate_json(first_json)
    serialized = json.loads(first_json)

    assert first_json == second_json
    assert restored == report
    assert serialized["schema_version"] == "1.0"
    assert serialized["capture"]["filename"] == "synthetic-handshake-close.pcapng"
    assert serialized["capture_quality_status"] == "usable"
    assert serialized["status"] == "analyzed_with_findings"
    assert serialized["analysis_statistics"]["tracked_conversation_limit"] == 50_000
    assert serialized["conversations"][0]["identity"] == {
        "conversation_id": "tcp-000001",
        "endpoint_a": {
            "ip_version": 4,
            "address": "192.0.2.10",
            "port": 443,
        },
        "endpoint_b": {
            "ip_version": 4,
            "address": "198.51.100.20",
            "port": 49_152,
        },
        "protocol": "tcp",
        "epoch": 1,
        "grouping_basis": "stream_and_tuple",
    }
