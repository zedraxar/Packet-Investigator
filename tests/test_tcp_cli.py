"""CLI orchestration tests for TCP conversation analysis."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from click.utils import strip_ansi
from typer.testing import CliRunner

from packet_investigator import cli
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.models.tcp_conversations import TCPAnalysisStatus
from packet_investigator.parsers.tshark import (
    CaptureValidationError,
    TsharkExecutionError,
    TsharkNotFoundError,
    TsharkTimeoutError,
)
from tests.tcp_report_samples import make_limitation, make_report

runner = CliRunner()


def _mock_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: TCPAnalysisStatus = TCPAnalysisStatus.ANALYZED,
) -> tuple[object, ...]:
    metadata = SimpleNamespace(filename="synthetic.pcapng")
    quality_collection = SimpleNamespace()
    quality_assessment = SimpleNamespace(
        capture=make_report().capture,
        status=CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
        limitations=(make_limitation("TCP_DIRECTION_NOT_VISIBLE"),),
    )
    tcp_collection = object()
    report = make_report(status=status)
    boundaries = (
        Mock(return_value=metadata),
        Mock(return_value=quality_collection),
        Mock(return_value=quality_assessment),
        Mock(return_value=tcp_collection),
        Mock(return_value=report),
        Mock(),
        Mock(return_value=report.model_dump_json()),
    )
    names = (
        "inspect_capture",
        "collect_capture_quality",
        "analyze_capture_quality",
        "collect_tcp_conversation_evidence",
        "analyze_tcp_conversations",
        "render_tcp_conversations_rich",
        "render_tcp_conversations_json",
    )
    for name, boundary in zip(names, boundaries, strict=True):
        monkeypatch.setattr(cli, name, boundary)
    return (
        metadata,
        quality_collection,
        quality_assessment,
        tcp_collection,
        report,
        *boundaries,
    )


def test_tcp_command_appears_in_help_with_exact_initial_options() -> None:
    root = runner.invoke(cli.app, ["--help"])
    command = runner.invoke(cli.app, ["tcp", "--help"])

    assert root.exit_code == 0
    assert "tcp" in root.stdout
    assert command.exit_code == 0
    assert "Analyze deterministic TCP conversation evidence" in command.stdout
    assert "capture_path" in command.stdout
    assert "--json" in strip_ansi(command.stdout)
    assert "--include-path" not in command.stdout
    assert "--timeout" not in command.stdout


def test_tcp_requires_capture_argument() -> None:
    result = runner.invoke(cli.app, ["tcp"])

    assert result.exit_code == 2
    assert "capture_path" in result.output


def test_tcp_human_pipeline_calls_each_public_boundary_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        metadata,
        quality_collection,
        quality_assessment,
        tcp_collection,
        report,
        inspect_mock,
        quality_collect_mock,
        quality_analyze_mock,
        tcp_collect_mock,
        tcp_analyze_mock,
        rich_mock,
        json_mock,
    ) = _mock_pipeline(monkeypatch)
    capture = Path("synthetic.pcapng")

    result = runner.invoke(cli.app, ["tcp", str(capture)])

    assert result.exit_code == 0
    inspect_mock.assert_called_once_with(capture)
    quality_collect_mock.assert_called_once_with(capture)
    quality_analyze_mock.assert_called_once_with(metadata, quality_collection)
    tcp_collect_mock.assert_called_once_with(capture)
    tcp_analyze_mock.assert_called_once_with(
        tcp_collection,
        capture=quality_assessment.capture,
        capture_quality_status=quality_assessment.status,
        capture_quality_limitation_codes=("TCP_DIRECTION_NOT_VISIBLE",),
    )
    rich_mock.assert_called_once_with(report)
    json_mock.assert_not_called()
    assert result.stdout == ""


def test_tcp_json_stdout_contains_only_renderer_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = _mock_pipeline(monkeypatch)
    report = pipeline[4]
    rich_mock = pipeline[-2]
    json_mock = pipeline[-1]
    json_mock.return_value = '{"schema_version":"1.0","status":"analyzed"}'

    result = runner.invoke(cli.app, ["tcp", "synthetic.pcapng", "--json"])

    assert result.exit_code == 0
    assert json.loads(result.stdout)["schema_version"] == "1.0"
    assert result.stdout == '{"schema_version":"1.0","status":"analyzed"}\n'
    json_mock.assert_called_once_with(report)
    rich_mock.assert_not_called()


@pytest.mark.parametrize(
    ("status", "expected_exit_code"),
    [
        (TCPAnalysisStatus.ANALYZED, 0),
        (TCPAnalysisStatus.ANALYZED_WITH_FINDINGS, 0),
        (TCPAnalysisStatus.LIMITED, 1),
        (TCPAnalysisStatus.INSUFFICIENT, 2),
    ],
)
def test_tcp_maps_report_status_to_exit_code(
    monkeypatch: pytest.MonkeyPatch,
    status: TCPAnalysisStatus,
    expected_exit_code: int,
) -> None:
    _mock_pipeline(monkeypatch, status=status)

    result = runner.invoke(cli.app, ["tcp", "synthetic.pcapng"])

    assert result.exit_code == expected_exit_code


@pytest.mark.parametrize(
    ("error", "expected_exit_code"),
    [
        (CaptureValidationError("Capture file not found: private.pcapng"), 2),
        (TsharkNotFoundError("TShark was not found."), 1),
        (TsharkTimeoutError("TShark timed out."), 1),
        (TsharkExecutionError("TShark failed to read the capture."), 1),
    ],
)
def test_tcp_expected_errors_use_stderr_without_traceback_or_json(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected_exit_code: int,
) -> None:
    inspect_mock = Mock(side_effect=error)
    monkeypatch.setattr(cli, "inspect_capture", inspect_mock)
    monkeypatch.setattr(cli, "collect_capture_quality", Mock())
    monkeypatch.setattr(cli, "analyze_capture_quality", Mock())
    monkeypatch.setattr(cli, "collect_tcp_conversation_evidence", Mock())
    monkeypatch.setattr(cli, "analyze_tcp_conversations", Mock())
    monkeypatch.setattr(cli, "render_tcp_conversations_rich", Mock())
    monkeypatch.setattr(cli, "render_tcp_conversations_json", Mock())

    result = runner.invoke(cli.app, ["tcp", "private.pcapng", "--json"])

    assert result.exit_code == expected_exit_code
    assert "Error:" in result.output
    assert "Traceback" not in result.output
    assert not result.output.lstrip().startswith("{")


def test_tcp_real_validation_error_keeps_stdout_clean(
    tmp_path: Path,
) -> None:
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "packet_investigator",
            "tcp",
            "missing.pcapng",
            "--json",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        check=False,
    )

    assert completed.returncode == 2
    assert completed.stdout == ""
    assert "Error:" in completed.stderr
    assert "Traceback" not in completed.stderr


def test_tcp_error_does_not_disclose_resolved_capture_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capture = tmp_path / "private.pcapng"
    monkeypatch.setattr(
        cli,
        "inspect_capture",
        Mock(side_effect=CaptureValidationError(f"Capture file not found: {capture}")),
    )

    result = runner.invoke(cli.app, ["tcp", str(capture)])

    assert result.exit_code == 2
    assert str(tmp_path) not in result.output
    assert "private.pcapng" in result.output


def test_deferred_include_path_and_timeout_options_are_rejected() -> None:
    include_path = runner.invoke(
        cli.app,
        ["tcp", "synthetic.pcapng", "--include-path"],
    )
    timeout = runner.invoke(
        cli.app,
        ["tcp", "synthetic.pcapng", "--timeout", "5"],
    )

    assert include_path.exit_code == 2
    assert timeout.exit_code == 2
