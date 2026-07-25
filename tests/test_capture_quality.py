"""Tests for immutable capture-quality domain models."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path

import pytest
from pydantic import BaseModel, ValidationError

from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.models.capture_quality import (
    CaptureLimitation,
    CaptureQualityAssessment,
    CaptureQualityCapture,
    CaptureQualityFinding,
    CaptureQualityStatistics,
    CaptureQualityStatus,
    CaptureRecommendation,
    ConfidenceLevel,
    QualitySeverity,
)


def _capture(*, path: Path | None = None) -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename="synthetic.pcapng",
        path=path,
        capture_format="PCAPNG",
        size_bytes=4096,
        packet_count=20,
        start_time=datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC),
        end_time=datetime(2026, 7, 25, 14, 3, 20, tzinfo=UTC),
        duration_seconds=2.0,
        interface_ids=("0", "1"),
        tshark_version="4.6.6",
        inspection_status="Inspection complete",
    )


def _finding(
    *,
    evidence: dict[str, int | float | str | bool | None] | None = None,
) -> CaptureQualityFinding:
    return CaptureQualityFinding(
        code="MIDSTREAM_TCP_OBSERVED",
        severity=QualitySeverity.WARNING,
        confidence=ConfidenceLevel.HIGH,
        observation="TCP payload preceded an observed SYN for one flow.",
        interpretation="The flow may have been established before capture start.",
        limitations=("Only traffic visible at this capture point was evaluated.",),
        evidence=({"candidate_midstream_flows": 1} if evidence is None else evidence),
        recommendation_codes=("CAPTURE_BEFORE_REPRODUCTION",),
    )


def _statistics() -> CaptureQualityStatistics:
    return CaptureQualityStatistics(
        rows_processed=20,
        tcp_packets=18,
        tcp_syn_packets=4,
        tracked_tcp_flows=5,
        flow_tracking_limit=50_000,
        flow_tracking_complete=True,
        candidate_midstream_flows=1,
        incomplete_handshake_flows=0,
        truncated_frames=0,
        checksum_warning_frames=0,
        checksum_rule_enabled=True,
        timestamp_regressions=0,
        interface_ids_observed=2,
    )


def _assessment(*, path: Path | None = None) -> CaptureQualityAssessment:
    return CaptureQualityAssessment(
        schema_version="1.0",
        tool_version="0.2.0",
        capture=_capture(path=path),
        status=CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
        findings=(_finding(),),
        limitations=(
            CaptureLimitation(
                code="TCP_FLOW_START_NOT_OBSERVED",
                description="Handshake-dependent analysis is limited.",
                affected_capabilities=("tcp_handshake_analysis",),
            ),
        ),
        recommendations=(
            CaptureRecommendation(
                code="CAPTURE_BEFORE_REPRODUCTION",
                priority=1,
                action="Start capture before reproducing the issue.",
                rationale="This improves visibility of flow establishment.",
            ),
        ),
        statistics=_statistics(),
        status_summary="The capture is usable with explicit limitations.",
    )


@pytest.mark.parametrize(
    ("member", "expected"),
    [
        (CaptureQualityStatus.USABLE, "usable"),
        (
            CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
            "usable_with_limitations",
        ),
        (CaptureQualityStatus.LIMITED, "limited"),
        (CaptureQualityStatus.INSUFFICIENT, "insufficient"),
        (QualitySeverity.INFORMATIONAL, "informational"),
        (QualitySeverity.WARNING, "warning"),
        (QualitySeverity.CRITICAL, "critical"),
        (ConfidenceLevel.HIGH, "high"),
        (ConfidenceLevel.MODERATE, "moderate"),
        (ConfidenceLevel.LOW, "low"),
    ],
)
def test_enum_values_serialize_to_lowercase(member: StrEnum, expected: str) -> None:
    assert json.loads(json.dumps(member)) == expected


@pytest.mark.parametrize(
    "model",
    [
        _capture(),
        _finding(),
        CaptureLimitation(
            code="LIMITED_VISIBILITY",
            description="Visibility is limited.",
            affected_capabilities=("tcp_analysis",),
        ),
        CaptureRecommendation(
            code="CAPTURE_AGAIN",
            priority=1,
            action="Capture again.",
            rationale="More evidence is required.",
        ),
        _statistics(),
        _assessment(),
    ],
)
def test_public_models_are_immutable(model: BaseModel) -> None:
    field_name = next(iter(type(model).model_fields))

    with pytest.raises(ValidationError):
        setattr(model, field_name, None)


@pytest.mark.parametrize(
    "field_name",
    [
        "rows_processed",
        "tcp_packets",
        "tcp_syn_packets",
        "tracked_tcp_flows",
        "flow_tracking_limit",
        "candidate_midstream_flows",
        "incomplete_handshake_flows",
        "truncated_frames",
        "checksum_warning_frames",
        "timestamp_regressions",
        "interface_ids_observed",
    ],
)
def test_statistics_reject_negative_counters(field_name: str) -> None:
    values = _statistics().model_dump()
    values[field_name] = -1

    with pytest.raises(ValidationError):
        CaptureQualityStatistics.model_validate(values)


@pytest.mark.parametrize(
    "field_name",
    [
        "rows_processed",
        "tcp_packets",
        "tcp_syn_packets",
        "tracked_tcp_flows",
        "flow_tracking_limit",
        "candidate_midstream_flows",
        "incomplete_handshake_flows",
        "truncated_frames",
        "checksum_warning_frames",
        "timestamp_regressions",
        "interface_ids_observed",
    ],
)
def test_statistics_reject_boolean_counters(field_name: str) -> None:
    values = _statistics().model_dump()
    values[field_name] = True

    with pytest.raises(ValidationError):
        CaptureQualityStatistics.model_validate(values)


@pytest.mark.parametrize("priority", [0, -1])
def test_recommendation_requires_positive_priority(priority: int) -> None:
    with pytest.raises(ValidationError):
        CaptureRecommendation(
            code="CAPTURE_AGAIN",
            priority=priority,
            action="Capture again.",
            rationale="More evidence is required.",
        )


def test_capture_rejects_naive_timestamp() -> None:
    values = _capture().model_dump()
    values["start_time"] = datetime(2026, 7, 25, 14, 3, 18)

    with pytest.raises(ValidationError):
        CaptureQualityCapture.model_validate(values)


def test_capture_rejects_end_before_start() -> None:
    start = datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC)

    with pytest.raises(ValidationError, match="must not precede"):
        CaptureQualityCapture(
            filename="synthetic.pcap",
            path=None,
            capture_format="PCAP",
            size_bytes=24,
            packet_count=1,
            start_time=start,
            end_time=start - timedelta(seconds=1),
            duration_seconds=1.0,
            interface_ids=(),
            tshark_version="4.6.6",
            inspection_status="Inspection complete",
        )


def test_empty_capture_accepts_absent_boundaries() -> None:
    capture = CaptureQualityCapture(
        filename="empty.pcapng",
        path=None,
        capture_format="PCAPNG",
        size_bytes=24,
        packet_count=0,
        start_time=None,
        end_time=None,
        duration_seconds=None,
        interface_ids=(),
        tshark_version="4.6.6",
        inspection_status="Inspection complete",
    )

    assert capture.start_time is None
    assert capture.end_time is None
    assert capture.duration_seconds is None


def test_non_empty_capture_requires_complete_boundaries() -> None:
    values = _capture().model_dump()
    values["end_time"] = None

    with pytest.raises(ValidationError, match="provided together"):
        CaptureQualityCapture.model_validate(values)


def test_interpretation_serializes_as_null() -> None:
    finding = _finding()
    finding_without_interpretation = finding.model_copy(update={"interpretation": None})

    assert (
        json.loads(finding_without_interpretation.model_dump_json())["interpretation"]
        is None
    )


def test_capture_path_is_omitted_when_absent() -> None:
    serialized = json.loads(_assessment().model_dump_json())

    assert "path" not in serialized["capture"]


def test_capture_path_is_included_when_explicit(tmp_path: Path) -> None:
    capture_path = (tmp_path / "synthetic.pcapng").resolve()
    serialized = json.loads(_assessment(path=capture_path).model_dump_json())

    assert serialized["capture"]["path"] == str(capture_path)


def test_tuples_serialize_as_json_arrays() -> None:
    serialized = json.loads(_assessment().model_dump_json())

    assert isinstance(serialized["findings"], list)
    assert isinstance(serialized["capture"]["interface_ids"], list)
    assert isinstance(serialized["findings"][0]["limitations"], list)


def test_evidence_is_immutable_and_serializes_as_object() -> None:
    evidence = {"candidate_midstream_flows": 1}
    finding = _finding(evidence=evidence)
    evidence["candidate_midstream_flows"] = 99

    assert finding.evidence["candidate_midstream_flows"] == 1
    assert json.loads(finding.model_dump_json())["evidence"] == {
        "candidate_midstream_flows": 1
    }
    with pytest.raises(TypeError):
        finding.evidence["new_value"] = 2  # type: ignore[index]


def test_unknown_valid_finding_code_is_preserved() -> None:
    values = _finding().model_dump()
    values["code"] = "FUTURE_VALID_CODE"
    finding = CaptureQualityFinding.model_validate(values)

    assert finding.code == "FUTURE_VALID_CODE"


@pytest.mark.parametrize("code", ["", "lowercase", "HAS-HYPHEN", "_PREFIX"])
def test_invalid_machine_codes_are_rejected(code: str) -> None:
    values = _finding().model_dump()
    values["code"] = code

    with pytest.raises(ValidationError):
        CaptureQualityFinding.model_validate(values)


def test_filename_must_be_base_filename() -> None:
    values = _capture().model_dump()
    values["filename"] = "captures/synthetic.pcapng"

    with pytest.raises(ValidationError, match="base filename"):
        CaptureQualityCapture.model_validate(values)


def test_capture_path_must_be_absolute_and_resolved() -> None:
    values = _capture().model_dump()
    values["path"] = Path("synthetic.pcapng")

    with pytest.raises(ValidationError, match="absolute and resolved"):
        CaptureQualityCapture.model_validate(values)


def test_assessment_serialization_is_deterministic() -> None:
    assessment = _assessment()

    assert assessment.model_dump_json() == assessment.model_dump_json()


def test_complete_schema_example_round_trips() -> None:
    assessment = _assessment()

    restored = CaptureQualityAssessment.model_validate_json(
        assessment.model_dump_json()
    )

    assert restored == assessment
    assert restored.schema_version == "1.0"


def test_capture_quality_models_do_not_change_capture_metadata_contract() -> None:
    serialized = json.loads(_capture_metadata_json_for_existing_inspect_contract())

    assert serialized["path"] == "/synthetic/example.pcapng"
    assert serialized["status"] == "Inspection complete"
    assert "inspection_status" not in serialized


def _capture_metadata_json_for_existing_inspect_contract() -> str:
    metadata = CaptureMetadata(
        path=Path("/synthetic/example.pcapng"),
        filename="example.pcapng",
        capture_format="PCAPNG",
        size_bytes=24,
        packet_count=0,
        start_time=None,
        end_time=None,
        duration_seconds=None,
        interface_ids=(),
        tshark_version="4.6.6",
        status="Inspection complete",
    )
    return metadata.model_dump_json()
