"""Saved output preserves report schemas, privacy, evidence and exit codes."""

import json
import shutil
from pathlib import Path
from unittest.mock import Mock

import pytest
from typer.main import get_command
from typer.testing import CliRunner

from packet_investigator import cli, comparison
from packet_investigator.models.capture_comparison import ClockAlignment
from packet_investigator.models.capture_quality import CaptureQualityStatus
from packet_investigator.models.dns_transactions import (
    DNSAnalysisStatus,
    DNSTransactionStatus,
)
from packet_investigator.models.tcp_conversations import TCPAnalysisStatus
from packet_investigator.parsers.tshark import CaptureValidationError
from tests.dns_report_samples import make_report as dns_report
from tests.dns_report_samples import make_transaction
from tests.fixtures.dns_captures import write_dns_capture_matrix
from tests.test_capture_file_comparison import mocked_pipeline
from tests.test_cli import _metadata
from tests.test_investigation import _report

runner = CliRunner()
COMMANDS = ["investigate", "quality", "tcp", "dns", "inspect", "compare"]


@pytest.fixture
def reports(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    combined = _report()
    left, right = mocked_pipeline(monkeypatch, tmp_path)
    compared = comparison.compare_capture_files(
        left,
        right,
        left_label="left",
        right_label="right",
        alignment=ClockAlignment(basis="synchronized"),
    )
    values = {
        "investigate": combined,
        "quality": combined.quality,
        "tcp": combined.tcp,
        "dns": combined.dns,
        "inspect": _metadata(tmp_path),
        "compare": compared,
    }
    monkeypatch.setattr(cli, "investigate_capture", lambda _: values["investigate"])
    monkeypatch.setattr(cli, "inspect_capture", lambda _: values["inspect"])
    monkeypatch.setattr(cli, "collect_capture_quality", lambda _: object())
    monkeypatch.setattr(cli, "analyze_capture_quality", lambda *args: values["quality"])
    monkeypatch.setattr(cli, "collect_tcp_conversation_evidence", lambda _: object())
    monkeypatch.setattr(
        cli, "analyze_tcp_conversations", lambda *args, **kwargs: values["tcp"]
    )
    monkeypatch.setattr(cli, "collect_dns_transaction_evidence", lambda _: object())
    monkeypatch.setattr(
        cli, "analyze_dns_transactions", lambda *args, **kwargs: values["dns"]
    )
    monkeypatch.setattr(
        cli, "compare_capture_files", lambda *args, **kwargs: values["compare"]
    )
    return values


def arguments(command: str) -> list[str]:
    return (
        [command, "left.pcapng", "right.pcapng", "--assume-synchronized"]
        if command == "compare"
        else [command, "sample.pcapng"]
    )


@pytest.mark.parametrize("command", COMMANDS)
@pytest.mark.parametrize("json_output", [False, True])
def test_all_capture_commands_save_without_duplicate_stdout(
    reports, command: str, json_output: bool, tmp_path: Path
) -> None:
    output = tmp_path / ("résult report.json" if json_output else "résult report.txt")
    args = arguments(command) + (["--json"] if json_output else [])
    baseline = runner.invoke(cli.app, args)
    result = runner.invoke(cli.app, [*args, "--output", str(output)])
    assert result.exit_code == baseline.exit_code == 0, result.output
    assert result.stdout == result.stderr == ""
    raw = output.read_bytes()
    text = raw.decode("utf-8")
    assert raw.endswith(b"\n") and b"\r\n" not in raw
    assert "\x1b[" not in text
    if json_output:
        assert text == baseline.stdout
        assert json.loads(text) == reports[command].model_dump(mode="json")
    else:
        assert "Packet Investigator" in text
        assert len(text.splitlines()) > 2
    if command != "inspect":
        assert str(tmp_path) not in text


@pytest.mark.parametrize("command", COMMANDS)
def test_existing_file_and_input_capture_are_protected(
    reports, command: str, tmp_path: Path
) -> None:
    output = tmp_path / "source.pcapng"
    output.write_bytes(b"capture bytes must survive")
    args = arguments(command)
    args[1] = str(output)
    result = runner.invoke(cli.app, [*args, "--json", "--output", str(output)])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "already exists" in result.stderr
    assert str(tmp_path) not in result.stderr
    assert output.read_bytes() == b"capture bytes must survive"
    assert not list(tmp_path.glob(".packet-investigator-*"))


@pytest.mark.parametrize("command", COMMANDS)
def test_output_help_is_discoverable_without_analysis(command: str) -> None:
    params = get_command(cli.app).commands[command].params
    assert any("--output" in option.opts for option in params)


@pytest.mark.parametrize(
    ("command", "status", "expected"),
    [
        ("quality", CaptureQualityStatus.LIMITED, 1),
        ("quality", CaptureQualityStatus.INSUFFICIENT, 2),
        ("tcp", TCPAnalysisStatus.LIMITED, 1),
        ("tcp", TCPAnalysisStatus.INSUFFICIENT, 2),
        ("dns", DNSAnalysisStatus.LIMITED, 1),
        ("dns", DNSAnalysisStatus.INSUFFICIENT, 2),
        ("compare", "limited", 1),
        ("compare", "insufficient", 2),
    ],
)
def test_saved_reports_keep_analysis_exit_codes(
    reports, command, status, expected, tmp_path: Path
) -> None:
    reports[command] = reports[command].model_copy(update={"status": status})
    output = tmp_path / "limited.json"
    result = runner.invoke(
        cli.app, [*arguments(command), "--json", "--output", str(output)]
    )
    assert result.exit_code == expected
    assert result.stdout == result.stderr == ""
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == status


@pytest.mark.parametrize("json_output", [False, True])
def test_details_option_is_preserved_when_saving(
    reports, json_output: bool, tmp_path: Path
) -> None:
    compact = tmp_path / "compact.txt"
    detailed = tmp_path / "details.txt"
    args = ["investigate", "sample.pcapng"] + (["--json"] if json_output else [])
    first = runner.invoke(cli.app, [*args, "--output", str(compact)])
    second = runner.invoke(cli.app, [*args, "--details", "--output", str(detailed)])
    assert first.exit_code == second.exit_code == 0
    if json_output:
        assert compact.read_bytes() == detailed.read_bytes()
    else:
        assert "Transaction details" not in compact.read_text(encoding="utf-8")
        assert "Transaction details" in detailed.read_text(encoding="utf-8")


def test_complete_json_beyond_terminal_preview_is_saved(
    reports, tmp_path: Path
) -> None:
    transactions = tuple(
        make_transaction(
            i,
            status=DNSTransactionStatus.COMPLETE,
            response_code=0,
            findings=(),
            recommendations=(),
        )
        for i in range(1, 102)
    )
    reports["dns"] = dns_report(transactions=transactions)
    output = tmp_path / "complete.json"
    result = runner.invoke(
        cli.app, ["dns", "sample.pcapng", "--json", "--output", str(output)]
    )
    assert result.exit_code == 0
    assert len(json.loads(output.read_text(encoding="utf-8"))["transactions"]) == 101


def test_analysis_failure_creates_no_report(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        cli,
        "investigate_capture",
        Mock(side_effect=CaptureValidationError("Capture file not found")),
    )
    output = tmp_path / "report.json"
    result = runner.invoke(
        cli.app, ["investigate", "absent.pcapng", "--json", "--output", str(output)]
    )
    assert result.exit_code == 2 and result.stdout == ""
    assert not output.exists()


def test_renderer_failure_creates_no_report(
    reports, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        cli,
        "render_investigation_rich",
        Mock(side_effect=RuntimeError("renderer failure")),
    )
    output = tmp_path / "report.txt"
    result = runner.invoke(
        cli.app, ["investigate", "sample.pcapng", "--output", str(output)]
    )
    assert result.exit_code == 1 and result.stdout == ""
    assert not output.exists()


def test_missing_output_folder_has_clean_error(reports, tmp_path: Path) -> None:
    output = tmp_path / "missing" / "report.txt"
    result = runner.invoke(
        cli.app, ["investigate", "sample.pcapng", "--output", str(output)]
    )
    assert result.exit_code == 1 and result.stdout == ""
    assert "existing writable folder" in result.stderr
    assert str(tmp_path) not in result.stderr
    assert not output.parent.exists()


@pytest.mark.skipif(shutil.which("tshark") is None, reason="requires real TShark")
@pytest.mark.parametrize("json_output", [False, True])
def test_real_generated_capture_saves_and_refuses_overwrite(
    tmp_path: Path, json_output: bool
) -> None:
    capture = write_dns_capture_matrix(tmp_path / "captures")["nxdomain"]
    output = tmp_path / "report.out"
    args = ["investigate", str(capture)] + (["--json"] if json_output else [])
    result = runner.invoke(cli.app, [*args, "--output", str(output)])
    assert result.exit_code == 0, result.output
    saved = output.read_bytes()
    assert saved
    if json_output:
        assert json.loads(saved)["dns"]["transactions"][0]["evidence"][
            "response_code_counts"
        ] == [[3, 1]]
    else:
        assert b"NXDOMAIN" in saved
    again = runner.invoke(cli.app, [*args, "--output", str(output)])
    assert again.exit_code == 1 and "already exists" in again.stderr
    assert output.read_bytes() == saved


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (CaptureQualityStatus.LIMITED, 1),
        (CaptureQualityStatus.INSUFFICIENT, 2),
    ],
)
def test_saved_combined_report_keeps_nonzero_analysis_status(
    reports, status, expected, tmp_path: Path
) -> None:
    report = reports["investigate"]
    quality = report.quality.model_copy(update={"status": status})
    context = {"capture_quality_status": status}
    reports["investigate"] = report.model_copy(
        update={
            "quality": quality,
            "tcp": report.tcp.model_copy(update=context),
            "dns": report.dns.model_copy(update=context),
        }
    )
    output = tmp_path / "combined.json"
    result = runner.invoke(
        cli.app, ["investigate", "sample.pcapng", "--json", "--output", str(output)]
    )
    assert result.exit_code == expected and result.stdout == result.stderr == ""
    assert json.loads(output.read_text(encoding="utf-8"))["quality"]["status"] == status
