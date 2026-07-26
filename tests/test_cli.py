"""Tests for the Packet Investigator CLI."""

import json
from datetime import UTC, datetime
from pathlib import Path

from typer.testing import CliRunner

from packet_investigator import cli
from packet_investigator.models.capture import CaptureMetadata
from packet_investigator.parsers.tshark import CaptureValidationError

runner = CliRunner()


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
    assert "Diagnostic packet analysis is not implemented" in result.stdout


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
