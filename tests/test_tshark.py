"""Tests for capture validation and TShark field parsing."""

from __future__ import annotations

import io
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from packet_investigator.parsers import tshark

if TYPE_CHECKING:
    from pytest import MonkeyPatch


@pytest.mark.parametrize(
    ("filename", "expected_format"),
    [
        ("sample.pcap", "PCAP"),
        ("sample.pcapng", "PCAPNG"),
        ("sample.PCAP", "PCAP"),
        ("sample.PcApNg", "PCAPNG"),
    ],
)
def test_validate_supported_extensions(
    tmp_path: Path,
    filename: str,
    expected_format: str,
) -> None:
    capture = tmp_path / filename
    capture.touch()

    resolved, capture_format = tshark.validate_capture_path(capture)

    assert resolved == capture.resolve()
    assert capture_format == expected_format


def test_validate_unsupported_extension(tmp_path: Path) -> None:
    capture = tmp_path / "sample.txt"
    capture.touch()

    with pytest.raises(tshark.CaptureValidationError, match="expected .pcap"):
        tshark.validate_capture_path(capture)


def test_validate_missing_file(tmp_path: Path) -> None:
    with pytest.raises(tshark.CaptureValidationError, match="not found"):
        tshark.validate_capture_path(tmp_path / "missing.pcapng")


def test_validate_directory(tmp_path: Path) -> None:
    capture_directory = tmp_path / "directory.pcap"
    capture_directory.mkdir()

    with pytest.raises(tshark.CaptureValidationError, match="regular file"):
        tshark.validate_capture_path(capture_directory)


def test_parse_tshark_rows() -> None:
    summary = tshark.parse_tshark_rows(
        [
            "1\t1721923398.123456\t0\n",
            "2\t1721923400.623456\t1\n",
            "3\t1721923401.123456\t0\n",
        ]
    )

    assert summary.packet_count == 3
    assert summary.start_time is not None
    assert summary.start_time.isoformat() == "2024-07-25T16:03:18.123456+00:00"
    assert summary.end_time is not None
    assert summary.duration_seconds == 3.0
    assert summary.interface_ids == ("0", "1")


def test_parse_rows_without_interface_ids() -> None:
    summary = tshark.parse_tshark_rows(["1\t1721923398.0\t\n"])

    assert summary.packet_count == 1
    assert summary.interface_ids == ()


def test_parse_empty_capture() -> None:
    summary = tshark.parse_tshark_rows([])

    assert summary.packet_count == 0
    assert summary.start_time is None
    assert summary.end_time is None
    assert summary.duration_seconds is None
    assert summary.interface_ids == ()


def test_parse_invalid_timestamp() -> None:
    with pytest.raises(tshark.TsharkOutputError, match="Invalid packet timestamp"):
        tshark.parse_tshark_rows(["1\tnot-a-timestamp\t0\n"])


def test_tshark_executable_not_found(monkeypatch: MonkeyPatch) -> None:
    monkeypatch.setattr(tshark.shutil, "which", lambda _executable: None)

    with pytest.raises(tshark.TsharkNotFoundError, match="not found"):
        tshark.find_tshark()


class _FailedProcess:
    """Small process double for a completed, failed TShark invocation."""

    def __init__(self) -> None:
        self.stdout = io.StringIO("")
        self.stderr = io.StringIO("tshark: invalid capture")
        self.returncode = 2

    def poll(self) -> int:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        return self.returncode

    def terminate(self) -> None:
        raise AssertionError("Completed process should not be terminated.")

    def kill(self) -> None:
        raise AssertionError("Completed process should not be killed.")


def test_tshark_nonzero_exit(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    process = _FailedProcess()
    monkeypatch.setattr(tshark.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(tshark.TsharkExecutionError, match="exit 2"):
        tshark.stream_capture_metadata("tshark", tmp_path / "sample.pcap", 1)


def test_field_command_supports_argument_list_display_filter(tmp_path: Path) -> None:
    capture = tmp_path / "synthetic.pcapng"

    command = tshark._build_field_command(
        "/usr/bin/tshark",
        capture,
        ("frame.number", "frame.len"),
        display_filter="frame",
    )

    assert command == [
        "/usr/bin/tshark",
        "-n",
        "-r",
        str(capture),
        "-Y",
        "frame",
        "-T",
        "fields",
        "-E",
        "separator=\t",
        "-E",
        "quote=n",
        "-E",
        "occurrence=f",
        "-e",
        "frame.number",
        "-e",
        "frame.len",
    ]


def test_field_command_supports_multi_occurrence_aggregation(tmp_path: Path) -> None:
    command = tshark._build_field_command(
        "/usr/bin/tshark",
        tmp_path / "dns.pcapng",
        ("dns.resp.type", "dns.a"),
        display_filter="dns",
        field_occurrence="a",
        aggregator="\x1e",
    )

    occurrence_index = command.index("occurrence=a")
    aggregator_index = command.index("aggregator=\x1e")
    assert command[occurrence_index - 1 : occurrence_index + 1] == [
        "-E",
        "occurrence=a",
    ]
    assert command[aggregator_index - 1 : aggregator_index + 1] == [
        "-E",
        "aggregator=\x1e",
    ]
