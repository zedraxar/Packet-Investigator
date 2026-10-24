"""Tests for capture-quality Rich and JSON rendering."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from rich.console import Console

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
from packet_investigator.renderers.capture_quality import (
    render_capture_quality_json,
    render_capture_quality_rich,
)


def _capture(*, path: Path | None = None) -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename="synthetic.pcapng",
        path=path,
        capture_format="PCAPNG",
        size_bytes=1536,
        packet_count=20,
        start_time=datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC),
        end_time=datetime(2026, 7, 25, 14, 3, 20, tzinfo=UTC),
        duration_seconds=2.0,
        interface_ids=("0", "1"),
        tshark_version="4.6.6",
        inspection_status="Inspection complete",
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
        truncated_frames=2,
        checksum_warning_frames=3,
        checksum_rule_enabled=True,
        timestamp_regressions=1,
        interface_ids_observed=2,
    )


def _finding(
    code: str,
    *,
    interpretation: str | None = "Stored interpretation.",
) -> CaptureQualityFinding:
    return CaptureQualityFinding(
        code=code,
        severity=QualitySeverity.WARNING,
        confidence=ConfidenceLevel.MODERATE,
        observation=f"Stored observation for {code}.",
        interpretation=interpretation,
        limitations=(f"Finding limitation for {code}.",),
        evidence={
            "first_key": 1,
            "enabled": True,
            "missing_value": None,
            "text_value": "stored text",
        },
        recommendation_codes=("SECOND_ACTION", "FIRST_ACTION"),
    )


def _assessment(
    *,
    status: CaptureQualityStatus = CaptureQualityStatus.USABLE,
    path: Path | None = None,
    detailed: bool = False,
) -> CaptureQualityAssessment:
    findings = (
        (
            _finding("FIRST_FINDING"),
            _finding("SECOND_FINDING", interpretation=None),
        )
        if detailed
        else ()
    )
    limitations = (
        (
            CaptureLimitation(
                code="ASSESSMENT_LIMITATION",
                description="Stored assessment limitation.",
                affected_capabilities=("tcp_analysis", "timing_analysis"),
            ),
        )
        if detailed
        else ()
    )
    recommendations = (
        (
            CaptureRecommendation(
                code="SECOND_ACTION",
                priority=2,
                action="Perform the second stored action.",
                rationale="Stored second rationale.",
            ),
            CaptureRecommendation(
                code="FIRST_ACTION",
                priority=1,
                action="Perform the first stored action.",
                rationale="Stored first rationale.",
            ),
        )
        if detailed
        else ()
    )
    return CaptureQualityAssessment(
        schema_version="1.0",
        tool_version="0.3.0",
        capture=_capture(path=path),
        status=status,
        findings=findings,
        limitations=limitations,
        recommendations=recommendations,
        statistics=_statistics(),
        status_summary=f"Stored summary for {status.value}.",
    )


def _render_plain(assessment: CaptureQualityAssessment) -> str:
    stream = io.StringIO()
    console = Console(
        file=stream,
        force_terminal=False,
        color_system=None,
        width=180,
    )
    render_capture_quality_rich(assessment, console=console)
    return stream.getvalue()


def test_usable_output_has_identity_status_and_exact_summary() -> None:
    assessment = _assessment()

    output = _render_plain(assessment)

    assert "Capture: synthetic.pcapng" in output
    assert "Overall status: USABLE" in output
    assert assessment.status_summary in output
    assert "Findings" not in output
    assert "Assessment-wide limitations" not in output
    assert "Recommendations" not in output


@pytest.mark.parametrize(
    ("status", "label"),
    [
        (CaptureQualityStatus.USABLE_WITH_LIMITATIONS, "USABLE WITH LIMITATIONS"),
        (CaptureQualityStatus.LIMITED, "LIMITED"),
        (CaptureQualityStatus.INSUFFICIENT, "INSUFFICIENT"),
    ],
)
def test_textual_status_is_always_rendered(
    status: CaptureQualityStatus,
    label: str,
) -> None:
    output = _render_plain(_assessment(status=status, detailed=True))

    assert f"Overall status: {label}" in output


def test_capture_metadata_has_deterministic_field_order() -> None:
    output = _render_plain(_assessment())
    labels = (
        "Filename:",
        "Format:",
        "File size:",
        "Packet count:",
        "Start time:",
        "End time:",
        "Duration:",
        "Interface IDs:",
        "TShark version:",
        "Inspection status:",
    )

    positions = tuple(output.index(label) for label in labels)

    assert positions == tuple(sorted(positions))
    assert "1.50 KiB (1,536 bytes)" in output


def test_statistics_have_deterministic_field_order() -> None:
    output = _render_plain(_assessment())
    labels = (
        "Rows processed:",
        "TCP packets:",
        "TCP SYN packets:",
        "Tracked TCP flows:",
        "Candidate midstream flows:",
        "Incomplete handshake flows:",
        "Truncated frames:",
        "Checksum warning frames:",
        "Timestamp regressions:",
        "Interface IDs observed:",
        "Flow tracking status:",
        "Flow tracking limit:",
        "Checksum rule enabled:",
    )

    positions = tuple(output.index(label) for label in labels)

    assert positions == tuple(sorted(positions))
    assert "50,000" in output
    assert "true" in output


def test_finding_content_and_order_are_preserved() -> None:
    assessment = _assessment(detailed=True)

    output = _render_plain(assessment)

    assert output.index("FIRST_FINDING") < output.index("SECOND_FINDING")
    assert "Severity: warning" in output
    assert "Confidence: moderate" in output
    assert assessment.findings[0].observation in output
    assert "Interpretation: Stored interpretation." in output
    assert output.count("Interpretation:") == 1
    assert "Recommendation references: SECOND_ACTION, FIRST_ACTION" in output


def test_finding_and_assessment_limitations_remain_separate() -> None:
    output = _render_plain(_assessment(detailed=True))

    finding_heading = output.index("Finding limitations:")
    finding_text = output.index("Finding limitation for FIRST_FINDING.")
    assessment_heading = output.index("Assessment-wide limitations")
    assessment_text = output.index("Stored assessment limitation.")

    assert finding_heading < finding_text < assessment_heading < assessment_text
    assert "Affected capabilities: tcp_analysis, timing_analysis" in output


def test_evidence_values_and_insertion_order_are_preserved() -> None:
    output = _render_plain(_assessment(detailed=True))
    evidence_positions = tuple(
        output.index(value)
        for value in (
            "first_key: 1",
            "enabled: true",
            "missing_value: null",
            "text_value: stored text",
        )
    )

    assert evidence_positions == tuple(sorted(evidence_positions))


def test_recommendation_model_order_is_preserved() -> None:
    output = _render_plain(_assessment(detailed=True))
    recommendations_section = output.index("Recommendations")
    second_action = output.index("2. SECOND_ACTION", recommendations_section)
    first_action = output.index("1. FIRST_ACTION", recommendations_section)

    assert second_action < first_action
    assert "Action: Perform the second stored action." in output
    assert "Rationale: Stored first rationale." in output


def test_path_is_not_derived_when_absent() -> None:
    output = _render_plain(_assessment())

    assert "Path:" not in output
    assert "/synthetic/" not in output


def test_existing_path_is_displayed_without_resolution() -> None:
    path = (Path.cwd() / "synthetic/private/example.pcapng").resolve()

    output = _render_plain(_assessment(path=path))

    assert "Path:" in output
    assert str(path) in output


def test_plain_output_has_no_terminal_escape_sequences() -> None:
    output = _render_plain(_assessment(detailed=True))

    assert "\x1b[" not in output
    assert "Packet Investigator — Capture Quality" in output


def test_rich_rendering_is_deterministic_and_does_not_mutate() -> None:
    assessment = _assessment(detailed=True)
    serialized_before = assessment.model_dump_json()

    first = _render_plain(assessment)
    second = _render_plain(assessment)

    assert first == second
    assert assessment.model_dump_json() == serialized_before


def test_json_is_complete_indented_and_has_no_trailing_newline() -> None:
    assessment = _assessment(detailed=True)

    rendered = render_capture_quality_json(assessment)
    parsed = json.loads(rendered)

    assert parsed == assessment.model_dump(mode="json")
    assert '\n  "schema_version"' in rendered
    assert not rendered.endswith("\n")


def test_compact_json_is_valid_and_deterministic() -> None:
    assessment = _assessment(detailed=True)

    first = render_capture_quality_json(assessment, indent=None)
    second = render_capture_quality_json(assessment, indent=None)

    assert json.loads(first)["status"] == assessment.status.value
    assert "\n" not in first
    assert first == second
    assert first == assessment.model_dump_json()


@pytest.mark.parametrize(
    ("indent", "error_type"),
    [
        (-1, ValueError),
        (True, TypeError),
        (1.5, TypeError),
        ("2", TypeError),
    ],
)
def test_invalid_json_indent_is_rejected(
    indent: object,
    error_type: type[Exception],
) -> None:
    with pytest.raises(error_type):
        render_capture_quality_json(_assessment(), indent=indent)


def test_json_path_privacy_matches_assessment() -> None:
    private = json.loads(render_capture_quality_json(_assessment()))
    path = (Path.cwd() / "synthetic/private/example.pcapng").resolve()
    disclosed = json.loads(render_capture_quality_json(_assessment(path=path)))

    assert "path" not in private["capture"]
    assert disclosed["capture"]["path"] == str(path)


def test_json_rendering_does_not_mutate_model_serialization() -> None:
    assessment = _assessment(detailed=True)
    serialized_before = assessment.model_dump_json()

    render_capture_quality_json(assessment)

    assert assessment.model_dump_json() == serialized_before


def test_unassessed_handshake_statistic_is_explicit_without_json_schema_change() -> (
    None
):
    assessment = _assessment()
    output = _render_plain(assessment)
    row = next(
        line for line in output.splitlines() if "Incomplete handshake flows:" in line
    )
    assert "Not assessed" in row
    document = json.loads(render_capture_quality_json(assessment))
    assert document["statistics"]["incomplete_handshake_flows"] == 0
    assert assessment.statistics.incomplete_handshake_flows == 0
