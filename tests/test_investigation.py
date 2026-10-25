"""Combined workflow contracts, including absent evidence and stage failures."""

import json
import shutil
from pathlib import Path
from unittest.mock import Mock

import pytest
from click.utils import strip_ansi
from pydantic import ValidationError
from typer.testing import CliRunner

from packet_investigator import cli, investigation
from packet_investigator.analyzers import analyze_capture_quality
from packet_investigator.investigation import InvestigationReport, investigate_capture
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.models.dns_transactions import DNSAnalysisStatus
from packet_investigator.parsers.dns_transactions import _collect_dns_rows
from packet_investigator.parsers.tcp_conversations import _collect_tcp_rows
from packet_investigator.parsers.tshark import (
    CaptureValidationError,
    TsharkExecutionError,
)
from tests.dns_report_samples import make_report as dns_report
from tests.fixtures.captures import write_capture_fixtures
from tests.fixtures.dns_captures import write_dns_capture_matrix
from tests.tcp_report_samples import make_report as tcp_report
from tests.test_capture_quality_analyzer import _collection, _metadata

runner = CliRunner()


def _report() -> InvestigationReport:
    quality = analyze_capture_quality(_metadata(), _collection())
    context = {
        "capture": quality.capture,
        "capture_quality_status": quality.status,
        "capture_quality_limitation_codes": tuple(x.code for x in quality.limitations),
    }
    return InvestigationReport(
        quality=quality,
        tcp=tcp_report().model_copy(update=context),
        dns=dns_report().model_copy(update=context),
    )


@pytest.mark.parametrize("json_output", [False, True])
def test_combined_cli_preserves_sections_and_privacy(
    monkeypatch: pytest.MonkeyPatch, json_output: bool
) -> None:
    report = _report()
    run = Mock(return_value=report)
    monkeypatch.setattr(cli, "investigate_capture", run)
    args = ["investigate", "sample.pcapng"] + (["--json"] if json_output else [])
    result = runner.invoke(cli.app, args)
    assert result.exit_code == 0, result.output
    run.assert_called_once_with(Path("sample.pcapng"))
    if json_output:
        assert json.loads(result.stdout) == json.loads(report.model_dump_json())
        for section in ("quality", "tcp", "dns"):
            assert "path" not in json.loads(result.stdout)[section]["capture"]
        assert InvestigationReport.model_validate_json(result.stdout) == report
    else:
        output = " ".join(result.stdout.split())
        assert "Single-capture Investigation" in output
        assert "Capture Quality" in output
        assert "TCP Conversation Analysis" in output
        assert "DNS Transaction Analysis" in output
        assert "does not correlate DNS with TCP" in output


def test_orchestration_shares_one_quality_assessment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    metadata = Mock(return_value=_metadata())
    quality = Mock(return_value=_collection())
    monkeypatch.setattr(investigation, "inspect_capture", metadata)
    monkeypatch.setattr(investigation, "collect_capture_quality", quality)
    monkeypatch.setattr(
        investigation,
        "collect_tcp_conversation_evidence",
        lambda _: _collect_tcp_rows(()),
    )
    monkeypatch.setattr(
        investigation,
        "collect_dns_transaction_evidence",
        lambda _: _collect_dns_rows(()),
    )
    report = investigate_capture(Path("sample.pcapng"))
    metadata.assert_called_once()
    quality.assert_called_once()
    assert report.tcp.capture == report.dns.capture == report.quality.capture
    assert not report.tcp.conversations
    assert not report.dns.transactions
    assert report.exit_code == 0


@pytest.mark.parametrize(
    "stage",
    [
        "inspect_capture",
        "collect_capture_quality",
        "collect_tcp_conversation_evidence",
        "collect_dns_transaction_evidence",
    ],
)
def test_stage_errors_emit_no_partial_json(
    monkeypatch: pytest.MonkeyPatch, stage: str, tmp_path: Path
) -> None:
    path = tmp_path / "private.pcapng"
    monkeypatch.setattr(investigation, "inspect_capture", lambda _: _metadata())
    monkeypatch.setattr(
        investigation, "collect_capture_quality", lambda _: _collection()
    )
    monkeypatch.setattr(
        investigation,
        "collect_tcp_conversation_evidence",
        lambda _: _collect_tcp_rows(()),
    )
    monkeypatch.setattr(
        investigation,
        "collect_dns_transaction_evidence",
        lambda _: _collect_dns_rows(()),
    )
    monkeypatch.setattr(
        investigation,
        stage,
        Mock(side_effect=TsharkExecutionError(f"Unable to read {path.resolve()}")),
    )
    result = runner.invoke(cli.app, ["investigate", str(path), "--json"])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert str(tmp_path) not in result.stderr
    assert "private.pcapng" in result.stderr
    assert "Traceback" not in result.output


@pytest.mark.parametrize("color", [False, True])
def test_validation_error_and_help(
    monkeypatch: pytest.MonkeyPatch, color: bool
) -> None:
    run = Mock(side_effect=CaptureValidationError("Unsupported capture extension"))
    monkeypatch.setattr(cli, "investigate_capture", run)
    help_result = runner.invoke(
        cli.app,
        ["investigate", "--help"],
        color=color,
        env={"FORCE_COLOR": "1"} if color else {},
    )
    assert help_result.exit_code == 0
    assert "--details" in strip_ansi(help_result.stdout)
    run.assert_not_called()
    result = runner.invoke(cli.app, ["investigate", "sample.txt", "--json"])
    assert result.exit_code == 2
    assert result.stdout == ""


@pytest.mark.parametrize(
    "status,expected",
    [
        (CaptureQualityStatus.USABLE, 0),
        (CaptureQualityStatus.USABLE_WITH_LIMITATIONS, 0),
        (CaptureQualityStatus.LIMITED, 1),
        (CaptureQualityStatus.INSUFFICIENT, 2),
    ],
)
def test_quality_exit_codes(status: CaptureQualityStatus, expected: int) -> None:
    report = _report()
    report = InvestigationReport(
        quality=report.quality.model_copy(update={"status": status}),
        tcp=report.tcp.model_copy(update={"capture_quality_status": status}),
        dns=report.dns.model_copy(update={"capture_quality_status": status}),
    )
    assert report.exit_code == expected


def test_protocol_limitations_and_mismatched_context() -> None:
    report = _report()
    limited = report.model_copy(
        update={
            "dns": report.dns.model_copy(update={"status": DNSAnalysisStatus.LIMITED})
        }
    )
    assert limited.exit_code == 1
    insufficient = report.model_copy(
        update={
            "dns": report.dns.model_copy(
                update={"status": DNSAnalysisStatus.INSUFFICIENT, "transactions": ()}
            )
        }
    )
    assert insufficient.exit_code == 1
    with pytest.raises(ValidationError, match="metadata must match"):
        InvestigationReport(quality=report.quality, tcp=tcp_report(), dns=report.dns)
    with pytest.raises(ValidationError, match="quality status must match"):
        InvestigationReport(
            quality=report.quality,
            tcp=report.tcp,
            dns=report.dns.model_copy(
                update={"capture_quality_status": CaptureQualityStatus.LIMITED}
            ),
        )


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires real TShark")
@pytest.mark.parametrize("scenario", ["normal", "midstream", "empty"])
def test_real_combined_cli(tmp_path: Path, scenario: str) -> None:
    path = write_capture_fixtures(tmp_path)[scenario]
    result = runner.invoke(cli.app, ["investigate", str(path), "--json"])
    report = InvestigationReport.model_validate_json(result.stdout)
    assert result.exit_code == report.exit_code
    assert report.quality.capture.filename == path.name
    assert str(tmp_path) not in result.stdout


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires real TShark")
@pytest.mark.parametrize("scenario", ["successful_a_udp", "unanswered_query"])
def test_real_combined_dns(tmp_path: Path, scenario: str) -> None:
    path = write_dns_capture_matrix(tmp_path)[scenario]
    result = runner.invoke(cli.app, ["investigate", str(path), "--json"])
    report = InvestigationReport.model_validate_json(result.stdout)
    assert report.dns.transactions
    assert result.exit_code == report.exit_code
    assert "path" not in json.loads(result.stdout)["dns"]["capture"]


@pytest.mark.parametrize("details", [False, True])
@pytest.mark.parametrize("json_output", [False, True])
def test_combined_details_changes_only_terminal_dns_evidence(
    monkeypatch: pytest.MonkeyPatch,
    details: bool,
    json_output: bool,
) -> None:
    report = _report()
    monkeypatch.setattr(cli, "investigate_capture", Mock(return_value=report))
    args = ["investigate", "sample.pcapng"]
    if details:
        args.append("--details")
    if json_output:
        args.append("--json")
    result = runner.invoke(cli.app, args)
    assert result.exit_code == report.exit_code
    if json_output:
        assert result.stdout == report.model_dump_json(indent=2) + "\n"
    else:
        assert ("Transaction details" in result.stdout) is details
        assert "DNS_RESPONSE_CODE_OBSERVED" in result.stdout
        assert "TCP Conversation Analysis" in result.stdout
