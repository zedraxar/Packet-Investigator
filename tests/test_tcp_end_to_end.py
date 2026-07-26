"""Real-TShark acceptance tests for the complete TCP command pipeline."""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest
from pytest import TempPathFactory
from typer.testing import CliRunner

from packet_investigator import cli
from packet_investigator.analyzers import (
    analyze_capture_quality,
    analyze_tcp_conversations,
)
from packet_investigator.models.tcp_conversations import (
    TCPAnalysisReport,
    TCPAnalysisStatus,
)
from packet_investigator.parsers import (
    collect_capture_quality,
    collect_tcp_conversation_evidence,
    inspect_capture,
)
from packet_investigator.renderers import render_tcp_conversations_json
from tests.fixtures.captures import write_tcp_capture_matrix

_TSHARK = shutil.which("tshark")
_REQUIRES_TSHARK = pytest.mark.skipif(
    _TSHARK is None,
    reason="Phase 5.6 real-TShark tests require TShark on PATH",
)
_EXPECTED_PACKET_COUNTS = {
    "complete_orderly_close": 11,
    "syn_retries": 10,
    "syn_ack_retries": 10,
    "reset_after_syn": 10,
    "reset_after_establishment": 10,
    "midstream": 10,
    "incomplete_close": 10,
    "zero_window": 14,
    "retransmission": 10,
    "one_way_payload": 11,
    "sequence_wraparound": 10,
    "simultaneous_open": 10,
    "multiple_conversations": 22,
    "ipv6": 11,
    "tuple_reuse": 22,
    "empty": 0,
    "no_tcp": 10,
}
_EXPECTED_FINDINGS = {
    "syn_retries": "TCP_SYN_RETRY_OBSERVED",
    "syn_ack_retries": "TCP_SYN_ACK_RETRY_OBSERVED",
    "reset_after_syn": "TCP_RESET_AFTER_SYN",
    "reset_after_establishment": "TCP_RESET_AFTER_ESTABLISHMENT",
    "midstream": "TCP_MIDSTREAM_CONVERSATION",
    "incomplete_close": "TCP_CLOSE_STATE_INCOMPLETE",
    "zero_window": "TCP_ZERO_WINDOW_OBSERVED",
    "retransmission": "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
    "one_way_payload": "TCP_ONE_WAY_PAYLOAD_OBSERVED",
    "simultaneous_open": "TCP_SIMULTANEOUS_OPEN_OBSERVED",
}

runner = CliRunner()


@pytest.fixture(scope="session")
def tcp_captures(tmp_path_factory: TempPathFactory) -> dict[str, Path]:
    """Generate the complete deterministic TCP matrix once per test session."""
    return write_tcp_capture_matrix(tmp_path_factory.mktemp("tcp-captures"))


def _report(capture_path: Path) -> TCPAnalysisReport:
    metadata = inspect_capture(capture_path)
    quality_collection = collect_capture_quality(capture_path)
    quality = analyze_capture_quality(metadata, quality_collection)
    tcp_collection = collect_tcp_conversation_evidence(capture_path)
    return analyze_tcp_conversations(
        tcp_collection,
        capture=quality.capture,
        capture_quality_status=quality.status,
        capture_quality_limitation_codes=tuple(
            limitation.code for limitation in quality.limitations
        ),
    )


def _finding_codes(report: TCPAnalysisReport) -> set[str]:
    return {
        finding.code
        for conversation in report.conversations
        for finding in conversation.findings
    }


def test_capture_matrix_is_reproducible_and_not_committed(tmp_path: Path) -> None:
    first = write_tcp_capture_matrix(tmp_path / "first")
    second = write_tcp_capture_matrix(tmp_path / "second")

    assert set(first) == set(_EXPECTED_PACKET_COUNTS)
    assert set(first) == set(second)
    assert all(first[name].read_bytes() == second[name].read_bytes() for name in first)
    assert all(
        path.suffix == ".pcapng" and path.stat().st_size > 0 for path in first.values()
    )


@_REQUIRES_TSHARK
@pytest.mark.parametrize(
    ("scenario", "expected_packets"),
    tuple(_EXPECTED_PACKET_COUNTS.items()),
)
def test_generated_capture_is_independently_validated_by_tshark(
    tcp_captures: dict[str, Path],
    scenario: str,
    expected_packets: int,
) -> None:
    assert _TSHARK is not None
    result = subprocess.run(
        [
            _TSHARK,
            "-n",
            "-r",
            str(tcp_captures[scenario]),
            "-T",
            "fields",
            "-e",
            "frame.number",
            "-e",
            "ip.src",
            "-e",
            "ip.dst",
            "-e",
            "ipv6.src",
            "-e",
            "ipv6.dst",
            "-e",
            "tcp.stream",
        ],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )

    rows = result.stdout.splitlines()
    assert result.returncode == 0
    assert result.stderr == ""
    assert len(rows) == expected_packets
    if scenario == "ipv6":
        assert all("2001:db8::" in row for row in rows)
    elif scenario not in {"empty", "no_tcp"}:
        assert all("192.0.2.10" in row or "198.51.100.20" in row for row in rows)


@_REQUIRES_TSHARK
@pytest.mark.parametrize(
    ("scenario", "finding_code"),
    tuple(_EXPECTED_FINDINGS.items()),
)
def test_real_pipeline_produces_expected_public_finding(
    tcp_captures: dict[str, Path],
    scenario: str,
    finding_code: str,
) -> None:
    report = _report(tcp_captures[scenario])

    assert report.schema_version == "1.0"
    assert report.capture.filename == tcp_captures[scenario].name
    assert report.capture.path is None
    assert finding_code in _finding_codes(report)
    assert all(
        len(finding.evidence.representative_frames) <= 8
        for conversation in report.conversations
        for finding in conversation.findings
    )


@_REQUIRES_TSHARK
def test_real_complete_and_multiple_conversation_reports(
    tcp_captures: dict[str, Path],
) -> None:
    complete = _report(tcp_captures["complete_orderly_close"])
    multiple = _report(tcp_captures["multiple_conversations"])

    assert complete.status is TCPAnalysisStatus.ANALYZED
    assert complete.conversations[0].handshake.state.value == "complete"
    assert complete.conversations[0].closure.state.value == "orderly"
    assert complete.conversations[0].findings == ()
    assert [item.identity.conversation_id for item in multiple.conversations] == [
        "tcp-000001",
        "tcp-000002",
    ]
    assert all(
        item.handshake.state.value == "complete" for item in multiple.conversations
    )
    assert all(item.closure.state.value == "orderly" for item in multiple.conversations)


@_REQUIRES_TSHARK
def test_real_ipv6_and_tuple_reuse_identity(
    tcp_captures: dict[str, Path],
) -> None:
    ipv6 = _report(tcp_captures["ipv6"])
    reused = _report(tcp_captures["tuple_reuse"])

    assert ipv6.status is TCPAnalysisStatus.ANALYZED
    assert ipv6.conversations[0].identity.endpoint_a.ip_version == 6
    endpoint = ipv6.conversations[0].identity.endpoint_a
    assert str(endpoint.address).startswith("2001:db8:")
    assert [item.identity.epoch for item in reused.conversations] == [1, 2]
    assert all(item.status.value == "complete" for item in reused.conversations)


@_REQUIRES_TSHARK
def test_real_wraparound_and_no_tcp_reports(
    tcp_captures: dict[str, Path],
) -> None:
    wraparound = _report(tcp_captures["sequence_wraparound"])
    empty = _report(tcp_captures["empty"])
    no_tcp = _report(tcp_captures["no_tcp"])

    assert wraparound.conversations[0].handshake.state.value == "complete"
    assert empty.status is TCPAnalysisStatus.INSUFFICIENT
    assert empty.conversations == ()
    assert no_tcp.status is TCPAnalysisStatus.INSUFFICIENT
    assert no_tcp.conversations == ()


@_REQUIRES_TSHARK
def test_real_zero_window_evidence_is_exact_and_provenanced(
    tcp_captures: dict[str, Path],
) -> None:
    report = _report(tcp_captures["zero_window"])
    finding = next(
        finding
        for finding in report.conversations[0].findings
        if finding.code == "TCP_ZERO_WINDOW_OBSERVED"
    )

    assert finding.evidence.provenance.value == "tshark_derived"
    assert finding.evidence.values["raw_zero_window_frames"] == 3


@_REQUIRES_TSHARK
def test_real_cli_rich_is_private_conservative_and_repeatable(
    tcp_captures: dict[str, Path],
) -> None:
    capture_path = tcp_captures["reset_after_establishment"]
    arguments = ["tcp", str(capture_path)]

    first = runner.invoke(cli.app, arguments, terminal_width=120)
    second = runner.invoke(cli.app, arguments, terminal_width=120)
    narrow = runner.invoke(cli.app, arguments, terminal_width=72)

    assert first.exit_code == second.exit_code == narrow.exit_code == 0
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == narrow.stderr == ""
    assert "Packet Investigator — TCP Conversation Analysis" in first.stdout
    assert capture_path.name in first.stdout
    assert str(capture_path.parent) not in first.stdout
    assert "TCP_RESET_AFTER_ESTABLISHMENT" in first.stdout
    assert "does not establish root cause" in first.stdout
    assert "Overall status:" in narrow.stdout
    assert "TCP_RESET_AFTER_ESTABLISHMENT" in narrow.stdout


@_REQUIRES_TSHARK
def test_real_cli_json_is_complete_private_and_byte_deterministic(
    tcp_captures: dict[str, Path],
) -> None:
    capture_path = tcp_captures["retransmission"]
    arguments = ["tcp", str(capture_path), "--json"]

    first = runner.invoke(cli.app, arguments)
    second = runner.invoke(cli.app, arguments)

    assert first.exit_code == second.exit_code == 0
    assert first.stdout == second.stdout
    assert first.stderr == second.stderr == ""
    assert first.stdout.endswith("\n")
    assert not first.stdout.endswith("\n\n")
    assert "\x1b[" not in first.stdout
    assert str(capture_path.parent) not in first.stdout

    document = json.loads(first.stdout)
    assert document["schema_version"] == "1.0"
    assert document["capture"]["filename"] == capture_path.name
    assert "path" not in document["capture"]
    assert document["conversations"][0]["timings"]["syn_to_syn_ack_seconds"] is not None
    assert "TCP_RETRANSMISSION_INDICATORS_OBSERVED" in {
        finding["code"] for finding in document["conversations"][0]["findings"]
    }


@_REQUIRES_TSHARK
@pytest.mark.parametrize(
    ("scenario", "expected_exit"),
    [
        ("complete_orderly_close", 0),
        ("reset_after_establishment", 0),
        ("syn_retries", 1),
        ("empty", 2),
        ("no_tcp", 2),
    ],
)
def test_real_cli_status_exit_codes(
    tcp_captures: dict[str, Path],
    scenario: str,
    expected_exit: int,
) -> None:
    result = runner.invoke(
        cli.app,
        ["tcp", str(tcp_captures[scenario]), "--json"],
    )

    assert result.exit_code == expected_exit
    assert json.loads(result.stdout)["status"] in {
        "analyzed",
        "analyzed_with_findings",
        "limited",
        "insufficient",
    }
    assert result.stderr == ""


def test_real_cli_validation_error_keeps_json_stdout_clean(tmp_path: Path) -> None:
    capture_path = tmp_path / "missing.pcapng"

    result = runner.invoke(cli.app, ["tcp", str(capture_path), "--json"])

    assert result.exit_code == 2
    assert result.stdout == ""
    assert result.stderr.startswith("Error: Capture file not found:")
    assert capture_path.name in result.stderr
    assert str(capture_path.parent) not in result.stderr
    assert "Traceback" not in result.stderr


@_REQUIRES_TSHARK
def test_public_report_json_round_trips_after_real_collection(
    tcp_captures: dict[str, Path],
) -> None:
    report = _report(tcp_captures["complete_orderly_close"])
    rendered = render_tcp_conversations_json(report)

    assert TCPAnalysisReport.model_validate_json(rendered) == report


@_REQUIRES_TSHARK
def test_real_report_is_independent_of_temporary_directory(tmp_path: Path) -> None:
    first = write_tcp_capture_matrix(tmp_path / "location-a")
    second = write_tcp_capture_matrix(tmp_path / "location-b")

    assert _report(first["complete_orderly_close"]) == _report(
        second["complete_orderly_close"]
    )
