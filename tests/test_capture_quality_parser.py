"""Tests for streaming capture-quality field collection."""

from __future__ import annotations

import io
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import TYPE_CHECKING

import pytest

from packet_investigator.parsers import capture_quality, tshark

if TYPE_CHECKING:
    from pytest import MonkeyPatch


def _row(
    *,
    frame_number: int = 1,
    timestamp: str = "1721923398.0",
    captured_length: str = "64",
    original_length: str = "64",
    interface_id: str = "",
    protocols: str = "eth:ip:tcp",
    ip_version: str = "4",
    ip_source: str = "192.0.2.10",
    ip_destination: str = "192.0.2.20",
    ipv6_version: str = "",
    ipv6_source: str = "",
    ipv6_destination: str = "",
    ip_protocol: str = "6",
    ipv6_next_header: str = "",
    tcp_source_port: str = "49152",
    tcp_destination_port: str = "443",
    tcp_syn: str = "0",
    tcp_ack: str = "1",
    tcp_length: str = "0",
    checksum_fields: frozenset[str] = frozenset(),
    checksum_values: dict[str, str] | None = None,
) -> str:
    projection = capture_quality._build_projection(checksum_fields)
    values = {
        "frame.number": str(frame_number),
        "frame.time_epoch": timestamp,
        "frame.cap_len": captured_length,
        "frame.len": original_length,
        "frame.interface_id": interface_id,
        "frame.protocols": protocols,
        "ip.version": ip_version,
        "ip.src": ip_source,
        "ip.dst": ip_destination,
        "ipv6.version": ipv6_version,
        "ipv6.src": ipv6_source,
        "ipv6.dst": ipv6_destination,
        "ip.proto": ip_protocol,
        "ipv6.nxt": ipv6_next_header,
        "tcp.srcport": tcp_source_port,
        "tcp.dstport": tcp_destination_port,
        "tcp.flags.syn": tcp_syn,
        "tcp.flags.ack": tcp_ack,
        "tcp.len": tcp_length,
    }
    values.update(checksum_values or {})
    return "\t".join(values.get(field, "") for field in projection.fields) + "\n"


def _collect(
    rows: Iterable[str],
    checksum_fields: frozenset[str] = frozenset(),
) -> capture_quality.CaptureQualityCollection:
    return capture_quality._collect_quality_rows(rows, checksum_fields)


def test_empty_stream_produces_zero_statistics() -> None:
    result = _collect(iter(()))

    assert result.statistics.rows_processed == 0
    assert result.statistics.tcp_packets == 0
    assert result.statistics.tracked_tcp_flows == 0
    assert result.statistics.flow_tracking_limit == 50_000
    assert result.statistics.flow_tracking_complete
    assert result.first_timestamp is None
    assert result.final_timestamp is None


@pytest.mark.parametrize("ack", ["0", "1"])
def test_syn_and_syn_ack_count_as_observed_syn(ack: str) -> None:
    result = _collect([_row(tcp_syn="1", tcp_ack=ack)])

    assert result.statistics.tcp_packets == 1
    assert result.statistics.tcp_syn_packets == 1
    assert result.statistics.candidate_midstream_flows == 0


def test_payload_before_syn_counts_flow_once() -> None:
    rows = [
        _row(frame_number=1, tcp_ack="0", tcp_length="20"),
        _row(frame_number=2, timestamp="1721923399.0", tcp_length="40"),
    ]

    result = _collect(rows)

    assert result.statistics.tracked_tcp_flows == 1
    assert result.statistics.candidate_midstream_flows == 1


def test_syn_first_prevents_midstream_count() -> None:
    rows = [
        _row(frame_number=1, tcp_syn="1", tcp_ack="0"),
        _row(frame_number=2, timestamp="1721923399.0", tcp_length="20"),
    ]

    result = _collect(rows)

    assert result.statistics.candidate_midstream_flows == 0


def test_reverse_direction_is_a_distinct_flow() -> None:
    rows = [
        _row(frame_number=1, tcp_length="20"),
        _row(
            frame_number=2,
            ip_source="192.0.2.20",
            ip_destination="192.0.2.10",
            tcp_source_port="443",
            tcp_destination_port="49152",
            tcp_length="20",
        ),
    ]

    result = _collect(rows)

    assert result.statistics.tracked_tcp_flows == 2
    assert result.statistics.candidate_midstream_flows == 2


def test_ipv4_and_ipv6_flows_are_tracked() -> None:
    rows = [
        _row(frame_number=1, tcp_syn="1"),
        _row(
            frame_number=2,
            protocols="eth:ipv6:ipv6.hopopts:tcp",
            ip_version="",
            ip_source="",
            ip_destination="",
            ip_protocol="",
            ipv6_version="6",
            ipv6_source="2001:db8::10",
            ipv6_destination="2001:db8::20",
            ipv6_next_header="0",
            tcp_source_port="50000",
            tcp_syn="1",
        ),
    ]

    result = _collect(rows)

    assert result.statistics.tcp_packets == 2
    assert result.statistics.tracked_tcp_flows == 2


def test_missing_ports_bypass_flow_tracking_but_keep_tcp_counter() -> None:
    result = _collect(
        [_row(tcp_source_port="", tcp_destination_port="", tcp_length="20")]
    )

    assert result.statistics.tcp_packets == 1
    assert result.statistics.tracked_tcp_flows == 0
    assert result.statistics.candidate_midstream_flows == 0


def test_tunnel_uses_outer_identity_and_does_not_track_inner_tcp() -> None:
    result = _collect([_row(protocols="eth:ip:gre:ip:tcp", tcp_length="20")])

    assert result.statistics.tcp_packets == 1
    assert result.statistics.tracked_tcp_flows == 0


@pytest.mark.parametrize(
    ("flow_count", "expected_complete"),
    [
        (49_999, True),
        (50_000, False),
        (50_001, False),
    ],
)
def test_flow_tracking_cap(flow_count: int, expected_complete: bool) -> None:
    def rows() -> Iterable[str]:
        for index in range(flow_count):
            yield _row(
                frame_number=index + 1,
                ip_source=f"192.0.2.{index}",
                tcp_source_port=str(index % 65_536),
                tcp_syn="1",
                tcp_ack="0",
            )

    result = _collect(rows())

    assert result.statistics.tracked_tcp_flows == min(flow_count, 50_000)
    assert result.statistics.flow_tracking_complete is expected_complete
    assert result.statistics.tcp_packets == flow_count


def test_existing_flow_and_stateless_counters_continue_after_cap() -> None:
    def rows() -> Iterable[str]:
        yield _row(frame_number=1, tcp_ack="0", tcp_length="0")
        for index in range(1, 50_000):
            yield _row(
                frame_number=index + 1,
                ip_source=f"192.0.2.{index}",
                tcp_source_port=str(index % 65_536),
                tcp_syn="1",
                tcp_ack="0",
            )
        yield _row(
            frame_number=50_001,
            timestamp="1721923397.0",
            captured_length="60",
            original_length="100",
            ip_source="198.51.100.200",
            tcp_source_port="12345",
            tcp_length="20",
        )
        yield _row(
            frame_number=50_002,
            ip_source="192.0.2.10",
            tcp_source_port="49152",
            tcp_length="20",
        )

    result = _collect(rows())

    assert result.statistics.tracked_tcp_flows == 50_000
    assert not result.statistics.flow_tracking_complete
    assert result.statistics.tcp_packets == 50_002
    assert result.statistics.truncated_frames == 1
    assert result.statistics.timestamp_regressions == 1
    assert result.statistics.candidate_midstream_flows == 1


@pytest.mark.parametrize(
    ("captured_length", "original_length", "expected"),
    [
        ("63", "64", 1),
        ("64", "64", 0),
        ("", "64", 0),
        ("invalid", "64", 0),
        ("64", "", 0),
        ("64", "invalid", 0),
    ],
)
def test_truncation_counting(
    captured_length: str,
    original_length: str,
    expected: int,
) -> None:
    result = _collect(
        [
            _row(
                captured_length=captured_length,
                original_length=original_length,
            )
        ]
    )

    assert result.statistics.truncated_frames == expected


def test_timestamp_regressions_preserve_stream_order() -> None:
    rows = [
        _row(frame_number=1, timestamp="100.0"),
        _row(frame_number=2, timestamp="99.5"),
        _row(frame_number=3, timestamp="101.0"),
    ]

    result = _collect(rows)

    assert result.statistics.timestamp_regressions == 1
    assert result.first_timestamp is not None
    assert result.first_timestamp.timestamp() == 100.0
    assert result.final_timestamp is not None
    assert result.final_timestamp.timestamp() == 101.0


def test_interface_ids_are_deduplicated_and_sorted() -> None:
    rows = [
        _row(frame_number=1, interface_id="10"),
        _row(frame_number=2, interface_id="2"),
        _row(frame_number=3, interface_id="alpha"),
        _row(frame_number=4, interface_id="2"),
        _row(frame_number=5, interface_id=""),
    ]

    result = _collect(rows)

    assert result.interface_ids == ("2", "10", "alpha")
    assert result.statistics.interface_ids_observed == 3


@pytest.mark.parametrize(
    ("supported_fields", "supported_protocols", "unsupported_protocols"),
    [
        (
            frozenset(capture_quality._CHECKSUM_FIELDS.values()),
            ("tcp", "udp", "ipv4"),
            (),
        ),
        (
            frozenset({"tcp.checksum.status"}),
            ("tcp",),
            ("udp", "ipv4"),
        ),
        (frozenset(), (), ("tcp", "udp", "ipv4")),
    ],
)
def test_checksum_capabilities(
    supported_fields: frozenset[str],
    supported_protocols: tuple[str, ...],
    unsupported_protocols: tuple[str, ...],
) -> None:
    result = _collect([], supported_fields)

    assert result.checksum_capabilities.supported_protocols == supported_protocols
    assert result.checksum_capabilities.unsupported_protocols == unsupported_protocols
    assert result.statistics.checksum_rule_enabled is bool(supported_protocols)


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        ("0", 1),
        ("bad", 1),
        ("invalid", 1),
        ("1", 0),
        ("2", 0),
        ("good", 0),
        ("unknown", 0),
        ("", 0),
    ],
)
def test_checksum_warning_normalization(status: str, expected: int) -> None:
    checksum_fields = frozenset({"tcp.checksum.status"})
    result = _collect(
        [
            _row(
                checksum_fields=checksum_fields,
                checksum_values={"tcp.checksum.status": status},
            )
        ],
        checksum_fields,
    )

    assert result.statistics.checksum_warning_frames == expected


def test_missing_checksum_values_do_not_fail_collection() -> None:
    checksum_fields = frozenset(capture_quality._CHECKSUM_FIELDS.values())

    result = _collect([_row(checksum_fields=checksum_fields)], checksum_fields)

    assert result.statistics.rows_processed == 1
    assert result.statistics.checksum_warning_frames == 0


@pytest.mark.parametrize(
    "row",
    [
        "1\t100.0\n",
        _row(timestamp=""),
        _row(timestamp="invalid"),
        _row(frame_number=0),
    ],
)
def test_malformed_required_rows_fail(row: str) -> None:
    with pytest.raises(tshark.TsharkOutputError):
        _collect([row])


def test_malformed_flags_do_not_fail_collection() -> None:
    result = _collect([_row(tcp_syn="not-a-flag", tcp_ack="not-a-flag")])

    assert result.statistics.tcp_packets == 1
    assert result.statistics.tcp_syn_packets == 0
    assert result.statistics.candidate_midstream_flows == 0


def test_parser_stops_at_first_malformed_row() -> None:
    def rows() -> Iterable[str]:
        yield "malformed\n"
        raise AssertionError("collector consumed beyond the malformed row")

    with pytest.raises(tshark.TsharkOutputError):
        _collect(rows())


def test_capability_query_filters_requested_fields(
    monkeypatch: MonkeyPatch,
) -> None:
    completed = subprocess.CompletedProcess(
        args=["tshark", "-G", "fields"],
        returncode=0,
        stdout=(
            "F\tTCP checksum status\ttcp.checksum.status\tFT_UINT8\n"
            "F\tUnrelated\teth.src\tFT_ETHER\n"
        ),
        stderr="",
    )
    monkeypatch.setattr(tshark.subprocess, "run", lambda *_args, **_kwargs: completed)

    available = tshark.get_tshark_field_capabilities(
        "tshark",
        1,
        {"tcp.checksum.status", "udp.checksum.status"},
    )

    assert available == frozenset({"tcp.checksum.status"})


def test_public_collector_requests_only_supported_checksum_fields(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    capture = tmp_path / "synthetic.pcapng"
    capture.touch()
    captured_fields: tuple[str, ...] = ()

    monkeypatch.setattr(
        capture_quality, "find_tshark", lambda executable="tshark": "/usr/bin/tshark"
    )
    monkeypatch.setattr(
        capture_quality,
        "get_tshark_field_capabilities",
        lambda *_args: frozenset({"udp.checksum.status"}),
    )

    def stream(
        _executable: str,
        _path: Path,
        fields: tuple[str, ...],
        _timeout: float,
        consume_rows: Callable[
            [Iterable[str]],
            capture_quality.CaptureQualityCollection,
        ],
        *,
        operation: str,
    ) -> capture_quality.CaptureQualityCollection:
        nonlocal captured_fields
        captured_fields = fields
        assert operation == "quality collection"
        return consume_rows(iter(()))

    monkeypatch.setattr(capture_quality, "stream_tshark_fields", stream)

    result = capture_quality.collect_capture_quality(capture)

    assert "udp.checksum.status" in captured_fields
    assert "tcp.checksum.status" not in captured_fields
    assert "ip.checksum.status" not in captured_fields
    assert result.checksum_capabilities.supported_protocols == ("udp",)


class _ControllableProcess:
    """Process double that can remain alive until explicitly terminated."""

    def __init__(self, stdout: str = "") -> None:
        self.stdout = io.StringIO(stdout)
        self.stderr = io.StringIO("")
        self.returncode: int | None = None
        self.terminated = False
        self.killed = False

    def poll(self) -> int | None:
        return self.returncode

    def wait(self, timeout: float | None = None) -> int:
        if self.returncode is None:
            raise subprocess.TimeoutExpired("tshark", timeout)
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.returncode = -15

    def kill(self) -> None:
        self.killed = True
        self.returncode = -9


def test_timeout_terminates_process(monkeypatch: MonkeyPatch) -> None:
    process = _ControllableProcess()
    monkeypatch.setattr(tshark.subprocess, "Popen", lambda *_args, **_kwargs: process)

    with pytest.raises(tshark.TsharkTimeoutError):
        tshark.stream_tshark_fields(
            "tshark",
            Path("/synthetic.pcap"),
            ("frame.number",),
            1,
            lambda _rows: None,
            operation="quality collection",
        )

    assert process.terminated
    assert process.poll() is not None


def test_parser_failure_terminates_process(monkeypatch: MonkeyPatch) -> None:
    process = _ControllableProcess("malformed\n")
    monkeypatch.setattr(tshark.subprocess, "Popen", lambda *_args, **_kwargs: process)

    def fail(rows: Iterable[str]) -> None:
        next(iter(rows))
        raise tshark.TsharkOutputError("Malformed synthetic row.")

    with pytest.raises(tshark.TsharkOutputError):
        tshark.stream_tshark_fields(
            "tshark",
            Path("/synthetic.pcap"),
            ("frame.number",),
            1,
            fail,
            operation="quality collection",
        )

    assert process.terminated
    assert process.poll() is not None
