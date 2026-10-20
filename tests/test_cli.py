"""Tests for the Packet Investigator CLI."""

import json
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from packet_investigator import cli
from packet_investigator.analyzers import analyze_dns_transactions
from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.models.dns_transactions import DNSAnalysisStatus
from packet_investigator.parsers.dns_transactions import _collect_dns_rows
from packet_investigator.parsers.tshark import (
    CaptureValidationError,
    TsharkExecutionError,
)
from tests.dns_report_samples import make_limitation, make_report
from tests.test_dns_transaction_collector import _row

runner = CliRunner()


@pytest.mark.parametrize("args, exit_code", [(["--help"], 0), ([], 2)])
def test_root_help_guides_command_discovery_without_capture_processing(
    monkeypatch: pytest.MonkeyPatch, args: list[str], exit_code: int
) -> None:
    capture_calls = Mock(side_effect=AssertionError("Help must not process captures"))
    for name in (
        "inspect_capture",
        "collect_capture_quality",
        "collect_tcp_conversation_evidence",
        "collect_dns_transaction_evidence",
    ):
        monkeypatch.setattr(cli, name, capture_calls)

    result = runner.invoke(cli.app, args)

    assert result.exit_code == exit_code
    output = " ".join(result.output.split())
    for command in ("inspect", "quality", "tcp", "dns"):
        assert f"packet-investigator {command} CAPTURE_PATH" in output
    assert "packet-investigator COMMAND --help" in output
    assert "packet-investigator dns --help" in output
    assert "--json for machine-readable output" in output
    assert "processed locally with TShark" in output
    assert "do not establish root cause or ownership" in output
    capture_calls.assert_not_called()


@pytest.mark.parametrize("command", ("inspect", "quality"))
def test_first_run_metadata_commands_registration_and_help(command: str) -> None:
    """Complement TCP/DNS help coverage for the documented first-run workflow."""
    root = runner.invoke(cli.app, ["--help"])
    result = runner.invoke(cli.app, [command, "--help"])

    assert root.exit_code == 0
    assert command in root.stdout
    assert result.exit_code == 0
    assert "capture_path" in result.stdout
    params = get_command(cli.app).commands[command].params
    assert any("--json" in param.opts for param in params)


def test_version() -> None:
    """The version command reports the package version."""
    result = runner.invoke(cli.app, ["version"])

    assert result.exit_code == 0
    assert result.stdout == "0.5.0\n"


def test_root_version_option() -> None:
    """The conventional root version option reports the package version."""
    result = runner.invoke(cli.app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout == "0.5.0\n"


def test_info() -> None:
    """The info command accurately describes the implemented scope."""
    result = runner.invoke(cli.app, ["info"])

    assert result.exit_code == 0
    assert "deterministic TCP conversation analysis" in result.stdout
    assert "deterministic classic DNS transaction analysis" in result.stdout
    assert "does not provide root-cause or ownership conclusions" in result.stdout


def _metadata(tmp_path: Path) -> CaptureMetadata:
    capture = (tmp_path / "sample.pcapng").resolve()
    return CaptureMetadata(
        path=capture,
        filename=capture.name,
        capture_format="PCAPNG",
        size_bytes=1536,
        packet_count=2,
        start_time=datetime(2026, 7, 25, 14, 3, 18, tzinfo=UTC),
        end_time=datetime(2026, 7, 25, 14, 3, 20, tzinfo=UTC),
        duration_seconds=2.0,
        interface_ids=("0", "1"),
        tshark_version="4.6.6",
        status="Inspection complete",
    )


def test_inspect_success(monkeypatch: object, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "inspect_capture", lambda _path: _metadata(tmp_path))

    result = runner.invoke(cli.app, ["inspect", "sample.pcapng"])

    assert result.exit_code == 0
    assert "Capture Inspection" in result.stdout
    assert "1.50 KiB" in result.stdout
    output = " ".join(result.stdout.split())
    assert "Metadata inspection only." in output
    for command in ("quality", "tcp", "dns"):
        assert f"packet-investigator {command}" in output
    assert "Each command requires a capture path." in output
    assert "not implemented" not in output


def test_inspect_expected_error(monkeypatch: object) -> None:
    def fail(_path: Path) -> CaptureMetadata:
        raise CaptureValidationError("Capture file not found: missing.pcapng")

    monkeypatch.setattr(cli, "inspect_capture", fail)

    result = runner.invoke(cli.app, ["inspect", "missing.pcapng"])

    assert result.exit_code == 2
    assert "Capture file not found" in result.output
    assert "Traceback" not in result.output


def test_inspect_json(monkeypatch: object, tmp_path: Path) -> None:
    monkeypatch.setattr(cli, "inspect_capture", lambda _path: _metadata(tmp_path))

    result = runner.invoke(cli.app, ["inspect", "sample.pcapng", "--json"])

    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["capture_format"] == "PCAPNG"
    assert parsed["packet_count"] == 2
    assert parsed["interface_ids"] == ["0", "1"]
    assert "Metadata inspection only" not in result.stdout
    assert "packet-investigator" not in result.stdout


def _mock_dns_pipeline(
    monkeypatch: pytest.MonkeyPatch,
    *,
    status: DNSAnalysisStatus = DNSAnalysisStatus.ANALYZED,
) -> tuple[object, ...]:
    metadata = SimpleNamespace(filename="synthetic.pcapng")
    quality_collection = SimpleNamespace()
    quality_assessment = SimpleNamespace(
        capture=make_report().capture,
        status=CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
        limitations=(make_limitation("DNS_CAPTURE_POINT_LIMITATION"),),
    )
    dns_collection = object()
    report = make_report(status=status)
    boundaries = (
        Mock(return_value=metadata),
        Mock(return_value=quality_collection),
        Mock(return_value=quality_assessment),
        Mock(return_value=dns_collection),
        Mock(return_value=report),
        Mock(),
        Mock(return_value=report.model_dump_json() + "\n"),
    )
    names = (
        "inspect_capture",
        "collect_capture_quality",
        "analyze_capture_quality",
        "collect_dns_transaction_evidence",
        "analyze_dns_transactions",
        "render_dns_transactions_rich",
        "render_dns_transactions_json",
    )
    for name, boundary in zip(names, boundaries, strict=True):
        monkeypatch.setattr(cli, name, boundary)
    return (
        metadata,
        quality_collection,
        quality_assessment,
        dns_collection,
        report,
        *boundaries,
    )


def test_dns_command_registration_and_help() -> None:
    root = runner.invoke(cli.app, ["--help"])
    command = runner.invoke(cli.app, ["dns", "--help"])
    assert root.exit_code == 0
    assert "dns" in root.stdout
    assert command.exit_code == 0
    assert "Analyze deterministic classic DNS transaction evidence" in command.stdout
    assert "capture_path" in command.stdout
    dns_params = get_command(cli.app).commands["dns"].params
    assert any("--json" in param.opts for param in dns_params)
    assert "--timeout" not in command.stdout
    assert "--include-path" not in command.stdout


def test_dns_requires_capture_argument() -> None:
    result = runner.invoke(cli.app, ["dns"])
    assert result.exit_code == 2
    assert "capture_path" in result.output


def test_dns_rich_pipeline_calls_public_boundaries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    (
        metadata,
        quality_collection,
        quality_assessment,
        dns_collection,
        report,
        inspect_mock,
        quality_collect_mock,
        quality_analyze_mock,
        dns_collect_mock,
        dns_analyze_mock,
        rich_mock,
        json_mock,
    ) = _mock_dns_pipeline(monkeypatch)
    capture = Path("synthetic.pcapng")
    result = runner.invoke(cli.app, ["dns", str(capture)])
    assert result.exit_code == 0
    inspect_mock.assert_called_once_with(capture)
    quality_collect_mock.assert_called_once_with(capture)
    quality_analyze_mock.assert_called_once_with(metadata, quality_collection)
    dns_collect_mock.assert_called_once_with(capture)
    dns_analyze_mock.assert_called_once_with(
        dns_collection,
        capture=quality_assessment.capture,
        capture_quality_status=quality_assessment.status,
        capture_quality_limitation_codes=("DNS_CAPTURE_POINT_LIMITATION",),
    )
    rich_mock.assert_called_once_with(report)
    json_mock.assert_not_called()
    assert result.stdout == ""


def test_dns_pipeline_order(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = _mock_dns_pipeline(monkeypatch)
    order: list[str] = []
    for name, boundary in zip(
        ("inspect", "quality_collect", "quality_analyze", "dns_collect", "dns_analyze"),
        pipeline[5:10],
        strict=True,
    ):
        original = boundary.return_value
        boundary.side_effect = lambda *args, _name=name, _value=original, **kwargs: (
            order.append(_name) or _value
        )
    result = runner.invoke(cli.app, ["dns", "synthetic.pcapng"])
    assert result.exit_code == 0
    assert order == [
        "inspect",
        "quality_collect",
        "quality_analyze",
        "dns_collect",
        "dns_analyze",
    ]


def test_dns_json_stdout_contains_only_one_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = _mock_dns_pipeline(monkeypatch)
    report = pipeline[4]
    rich_mock = pipeline[-2]
    json_mock = pipeline[-1]
    json_mock.return_value = '{"schema_version":"1.0","status":"analyzed"}\n'
    result = runner.invoke(cli.app, ["dns", "synthetic.pcapng", "--json"])
    assert result.exit_code == 0
    assert json.loads(result.stdout)["schema_version"] == "1.0"
    assert result.stdout == '{"schema_version":"1.0","status":"analyzed"}\n'
    json_mock.assert_called_once_with(report)
    rich_mock.assert_not_called()


def test_dns_json_omits_unsupported_answers_without_false_limited_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pipeline = _mock_dns_pipeline(monkeypatch)
    quality_assessment = pipeline[2]
    collection = _collect_dns_rows(
        [
            _row(frame=1, response_in="2"),
            _row(
                frame=2,
                timestamp="1785686400.025",
                response="1",
                source="198.51.100.53",
                destination="192.0.2.10",
                udp_source_port="53",
                udp_destination_port="49152",
                recursion_available="1",
                answer_count="1",
                response_to="1",
                dns_time="0.025",
                answer_names=("private-text.service.example",),
                answer_types=("16",),
                answer_ttls=("86400",),
            ),
        ]
    )
    report = analyze_dns_transactions(
        collection,
        capture=quality_assessment.capture,
        capture_quality_status=CaptureQualityStatus.USABLE,
        capture_quality_limitation_codes=(),
    )
    pipeline[9].return_value = report
    pipeline[-1].return_value = report.model_dump_json() + "\n"

    result = runner.invoke(cli.app, ["dns", "synthetic.pcapng", "--json"])

    parsed = json.loads(result.stdout)
    assert result.exit_code == 0
    assert result.stderr == ""
    assert result.stdout.endswith("\n")
    assert not result.stdout.endswith("\n\n")
    assert parsed["status"] == "analyzed"
    assert parsed["statistics"]["answer_records_observed"] == 1
    assert parsed["statistics"]["answer_records_retained"] == 0
    assert parsed["transactions"][0]["evidence"]["answers"] == []
    assert "private-text.service.example" not in result.stdout
    assert "86400" not in result.stdout
    assert "TYPE16" not in result.stdout
    assert "DNS_ANSWER_RETENTION_LIMIT_REACHED" not in result.stdout


@pytest.mark.parametrize(
    ("status", "expected"),
    (
        (DNSAnalysisStatus.ANALYZED, 0),
        (DNSAnalysisStatus.ANALYZED_WITH_FINDINGS, 0),
        (DNSAnalysisStatus.LIMITED, 1),
        (DNSAnalysisStatus.INSUFFICIENT, 2),
    ),
)
def test_dns_status_exit_mapping(
    monkeypatch: pytest.MonkeyPatch,
    status: DNSAnalysisStatus,
    expected: int,
) -> None:
    _mock_dns_pipeline(monkeypatch, status=status)
    assert runner.invoke(cli.app, ["dns", "synthetic.pcapng"]).exit_code == expected


@pytest.mark.parametrize(
    ("error", "expected"),
    (
        (CaptureValidationError("Capture file not found: private.pcapng"), 2),
        (TsharkExecutionError("TShark failed to read the capture."), 1),
    ),
)
def test_dns_expected_errors_are_sanitized_stderr_only(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    expected: int,
) -> None:
    monkeypatch.setattr(cli, "inspect_capture", Mock(side_effect=error))
    result = runner.invoke(cli.app, ["dns", "private.pcapng", "--json"])
    assert result.exit_code == expected
    assert result.stdout == ""
    assert "Error:" in result.stderr
    assert "Traceback" not in result.output


def test_dns_error_hides_resolved_capture_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    capture = tmp_path / "private.pcapng"
    monkeypatch.setattr(
        cli,
        "inspect_capture",
        Mock(side_effect=CaptureValidationError(f"Capture file not found: {capture}")),
    )
    result = runner.invoke(cli.app, ["dns", str(capture)])
    assert result.exit_code == 2
    assert str(tmp_path) not in result.output
    assert "private.pcapng" in result.output


def test_dns_repeated_json_output_is_deterministic(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _mock_dns_pipeline(monkeypatch)
    first = runner.invoke(cli.app, ["dns", "synthetic.pcapng", "--json"])
    second = runner.invoke(cli.app, ["dns", "synthetic.pcapng", "--json"])
    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
