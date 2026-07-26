"""CLI orchestration tests for capture-quality assessment."""

from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.testing import CliRunner

from packet_investigator import cli
from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.models.capture_quality import (
    CaptureQualityAssessment,
    CaptureQualityCapture,
    CaptureQualityStatistics,
    CaptureQualityStatus,
)
from packet_investigator.parsers.capture_quality import (
    CaptureQualityCollection,
    ChecksumCapabilities,
)
from packet_investigator.parsers.tshark import (
    CaptureValidationError,
    TsharkExecutionError,
)

runner = CliRunner()


def _metadata(tmp_path: Path) -> CaptureMetadata:
    path = (tmp_path / "sample.pcapng").resolve()
    start = datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC)
    end = datetime(2026, 7, 25, 14, 3, 20, tzinfo=UTC)
    return CaptureMetadata(
        path=path,
        filename=path.name,
        capture_format="PCAPNG",
        size_bytes=1536,
        packet_count=10,
        start_time=start,
        end_time=end,
        duration_seconds=2.0,
        interface_ids=("0",),
        tshark_version="4.6.6",
        status="Inspection complete",
    )


def _statistics() -> CaptureQualityStatistics:
    return CaptureQualityStatistics(
        rows_processed=10,
        tcp_packets=10,
        tcp_syn_packets=2,
        tracked_tcp_flows=2,
        flow_tracking_limit=50_000,
        flow_tracking_complete=True,
        candidate_midstream_flows=0,
        incomplete_handshake_flows=0,
        truncated_frames=0,
        checksum_warning_frames=0,
        checksum_rule_enabled=True,
        timestamp_regressions=0,
        interface_ids_observed=1,
    )


def _collection() -> CaptureQualityCollection:
    start = datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC)
    end = datetime(2026, 7, 25, 14, 3, 20, tzinfo=UTC)
    return CaptureQualityCollection(
        statistics=_statistics(),
        interface_ids=("0",),
        first_timestamp=start,
        final_timestamp=end,
        checksum_capabilities=ChecksumCapabilities(
            supported_protocols=("tcp", "udp", "ipv4"),
            unsupported_protocols=(),
        ),
    )


def _assessment(
    metadata: CaptureMetadata,
    status: CaptureQualityStatus = CaptureQualityStatus.USABLE,
) -> CaptureQualityAssessment:
    return CaptureQualityAssessment(
        schema_version="1.0",
        tool_version="0.2.0",
        capture=CaptureQualityCapture(
            filename=metadata.filename,
            path=None,
            capture_format=metadata.capture_format,
            size_bytes=metadata.size_bytes,
            packet_count=metadata.packet_count,
            start_time=metadata.start_time,
            end_time=metadata.end_time,
            duration_seconds=metadata.duration_seconds,
            interface_ids=metadata.interface_ids,
            tshark_version=metadata.tshark_version,
            inspection_status=metadata.status,
        ),
        status=status,
        findings=(),
        limitations=(),
        recommendations=(),
        statistics=_statistics(),
        status_summary="The capture is usable for further investigation.",
    )


def _mock_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: CaptureQualityStatus = CaptureQualityStatus.USABLE,
) -> tuple[
    CaptureMetadata,
    CaptureQualityCollection,
    CaptureQualityAssessment,
    Mock,
    Mock,
    Mock,
    Mock,
    Mock,
]:
    metadata = _metadata(tmp_path)
    collection = _collection()
    assessment = _assessment(metadata, status)
    inspect_mock = Mock(return_value=metadata)
    collect_mock = Mock(return_value=collection)
    analyze_mock = Mock(return_value=assessment)
    rich_mock = Mock()
    json_mock = Mock(return_value='{"schema_version":"1.0"}')
    monkeypatch.setattr(cli, "inspect_capture", inspect_mock)
    monkeypatch.setattr(cli, "collect_capture_quality", collect_mock)
    monkeypatch.setattr(cli, "analyze_capture_quality", analyze_mock)
    monkeypatch.setattr(cli, "render_capture_quality_rich", rich_mock)
    monkeypatch.setattr(cli, "render_capture_quality_json", json_mock)
    return (
        metadata,
        collection,
        assessment,
        inspect_mock,
        collect_mock,
        analyze_mock,
        rich_mock,
        json_mock,
    )


def test_quality_runs_pipeline_and_uses_rich_renderer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        metadata,
        collection,
        assessment,
        inspect_mock,
        collect_mock,
        analyze_mock,
        rich_mock,
        json_mock,
    ) = _mock_pipeline(monkeypatch, tmp_path)

    result = runner.invoke(cli.app, ["quality", "sample.pcapng"])

    assert result.exit_code == 0
    inspect_mock.assert_called_once_with(Path("sample.pcapng"))
    collect_mock.assert_called_once_with(Path("sample.pcapng"))
    analyze_mock.assert_called_once_with(metadata, collection)
    rich_mock.assert_called_once_with(assessment)
    json_mock.assert_not_called()
    assert result.stdout == ""


def test_quality_json_uses_only_json_renderer(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        _metadata_result,
        _collection_result,
        assessment,
        _inspect_mock,
        _collect_mock,
        _analyze_mock,
        rich_mock,
        json_mock,
    ) = _mock_pipeline(monkeypatch, tmp_path)

    result = runner.invoke(cli.app, ["quality", "sample.pcapng", "--json"])

    assert result.exit_code == 0
    json_mock.assert_called_once_with(assessment)
    rich_mock.assert_not_called()
    assert result.stdout == '{"schema_version":"1.0"}\n'


@pytest.mark.parametrize(
    ("status", "expected_exit_code"),
    [
        (CaptureQualityStatus.USABLE, 0),
        (CaptureQualityStatus.USABLE_WITH_LIMITATIONS, 0),
        (CaptureQualityStatus.LIMITED, 1),
        (CaptureQualityStatus.INSUFFICIENT, 2),
    ],
)
def test_quality_maps_status_to_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    status: CaptureQualityStatus,
    expected_exit_code: int,
) -> None:
    _mock_pipeline(monkeypatch, tmp_path, status)

    result = runner.invoke(cli.app, ["quality", "sample.pcapng"])

    assert result.exit_code == expected_exit_code


def test_quality_reports_invalid_path_without_running_later_stages(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    inspect_mock = Mock(
        side_effect=CaptureValidationError("Capture file not found: missing.pcapng")
    )
    collect_mock = Mock()
    analyze_mock = Mock()
    rich_mock = Mock()
    json_mock = Mock()
    monkeypatch.setattr(cli, "inspect_capture", inspect_mock)
    monkeypatch.setattr(cli, "collect_capture_quality", collect_mock)
    monkeypatch.setattr(cli, "analyze_capture_quality", analyze_mock)
    monkeypatch.setattr(cli, "render_capture_quality_rich", rich_mock)
    monkeypatch.setattr(cli, "render_capture_quality_json", json_mock)

    result = runner.invoke(cli.app, ["quality", "missing.pcapng"])

    assert result.exit_code == 2
    assert "Capture file not found" in result.output
    assert "Traceback" not in result.output
    inspect_mock.assert_called_once_with(Path("missing.pcapng"))
    collect_mock.assert_not_called()
    analyze_mock.assert_not_called()
    rich_mock.assert_not_called()
    json_mock.assert_not_called()


def test_quality_reports_collector_failure_without_rendering(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    metadata = _metadata(tmp_path)
    monkeypatch.setattr(cli, "inspect_capture", Mock(return_value=metadata))
    collect_mock = Mock(side_effect=TsharkExecutionError("TShark failed"))
    analyze_mock = Mock()
    rich_mock = Mock()
    json_mock = Mock()
    monkeypatch.setattr(cli, "collect_capture_quality", collect_mock)
    monkeypatch.setattr(cli, "analyze_capture_quality", analyze_mock)
    monkeypatch.setattr(cli, "render_capture_quality_rich", rich_mock)
    monkeypatch.setattr(cli, "render_capture_quality_json", json_mock)

    result = runner.invoke(cli.app, ["quality", "sample.pcapng"])

    assert result.exit_code == 1
    assert "Error: TShark failed" in result.output
    assert "Traceback" not in result.output
    collect_mock.assert_called_once_with(Path("sample.pcapng"))
    analyze_mock.assert_not_called()
    rich_mock.assert_not_called()
    json_mock.assert_not_called()


def test_quality_does_not_mutate_assessment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    (
        _metadata_result,
        _collection_result,
        assessment,
        _inspect_mock,
        _collect_mock,
        _analyze_mock,
        _rich_mock,
        _json_mock,
    ) = _mock_pipeline(monkeypatch, tmp_path)
    before = assessment.model_dump_json()

    result = runner.invoke(cli.app, ["quality", "sample.pcapng"])

    assert result.exit_code == 0
    assert assessment.model_dump_json() == before
