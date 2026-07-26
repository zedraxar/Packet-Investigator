"""Narrow in-memory TCP collection, analysis, and rendering tests."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime, timedelta

from rich.console import Console

from packet_investigator.analyzers import analyze_tcp_conversations
from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.tcp_conversations import TCPAnalysisStatus
from packet_investigator.parsers import tcp_conversations
from packet_investigator.renderers import (
    render_tcp_conversations_json,
    render_tcp_conversations_rich,
)

_EPOCH = 1_785_592_800
_START = datetime.fromtimestamp(_EPOCH, tz=UTC)


def _row(
    frame: int,
    *,
    reverse: bool = False,
    sequence: int = 100,
    acknowledgment: int = 0,
    payload_length: int = 0,
    syn: bool = False,
    ack: bool = True,
    fin: bool = False,
    reset: bool = False,
    retransmission: bool = False,
) -> str:
    projection = tcp_conversations._build_projection(
        frozenset(tcp_conversations._ALL_FIELDS)
    )
    source = "198.51.100.20" if reverse else "192.0.2.10"
    destination = "192.0.2.10" if reverse else "198.51.100.20"
    source_port = 443 if reverse else 49_152
    destination_port = 49_152 if reverse else 443
    flags = (
        (0x02 if syn else 0)
        | (0x10 if ack else 0)
        | (0x01 if fin else 0)
        | (0x04 if reset else 0)
    )
    return tcp_conversations._projected_row(
        {
            "frame.number": str(frame),
            "frame.time_epoch": str(_EPOCH + frame / 10),
            "frame.interface_id": "0",
            "frame.cap_len": "64",
            "frame.len": "64",
            "frame.protocols": "eth:ip:tcp",
            "ip.src": source,
            "ip.dst": destination,
            "ipv6.src": "",
            "ipv6.dst": "",
            "tcp.stream": "0",
            "tcp.srcport": str(source_port),
            "tcp.dstport": str(destination_port),
            "tcp.seq_raw": str(sequence),
            "tcp.ack_raw": str(acknowledgment),
            "tcp.len": str(payload_length),
            "tcp.hdr_len": "20",
            "tcp.window_size_value": "64240",
            "tcp.window_size": "64240",
            "tcp.flags": hex(flags),
            "tcp.flags.syn": "1" if syn else "0",
            "tcp.flags.ack": "1" if ack else "0",
            "tcp.flags.fin": "1" if fin else "0",
            "tcp.flags.reset": "1" if reset else "0",
            "tcp.analysis.retransmission": "1" if retransmission else "",
            "tcp.analysis.initial_rtt": "",
        },
        projection,
    )


def _capture() -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename="synthetic-pipeline.pcapng",
        path=None,
        capture_format="PCAPNG",
        size_bytes=1024,
        packet_count=10,
        start_time=_START,
        end_time=_START + timedelta(seconds=1),
        duration_seconds=1.0,
        interface_ids=("0",),
        tshark_version="4.6.6",
        inspection_status="Inspection complete",
    )


def _analyze(rows: list[str]):
    collection = tcp_conversations._collect_tcp_rows(rows)
    return analyze_tcp_conversations(
        collection,
        capture=_capture(),
        capture_quality_status=CaptureQualityStatus.USABLE,
    )


def _rich_text(report) -> str:
    stream = io.StringIO()
    render_tcp_conversations_rich(
        report,
        console=Console(
            file=stream,
            force_terminal=False,
            color_system=None,
            width=140,
        ),
    )
    return stream.getvalue()


def test_complete_conversation_flows_through_analysis_and_both_renderers() -> None:
    rows = [
        _row(1, sequence=100, syn=True, ack=False),
        _row(2, reverse=True, sequence=200, acknowledgment=101, syn=True),
        _row(3, sequence=101, acknowledgment=201),
        _row(4, sequence=101, acknowledgment=201, fin=True),
        _row(5, reverse=True, sequence=201, acknowledgment=102),
        _row(6, reverse=True, sequence=201, acknowledgment=102, fin=True),
        _row(7, sequence=102, acknowledgment=202),
    ]

    report = _analyze(rows)
    human = _rich_text(report)
    parsed = json.loads(render_tcp_conversations_json(report))

    assert report.status is TCPAnalysisStatus.ANALYZED
    assert "tcp-000001" in human
    assert "COMPLETE" in human
    assert parsed["status"] == "analyzed"
    assert parsed["conversations"][0]["closure"]["state"] == "orderly"


def test_conversation_finding_flows_to_human_and_json_deterministically() -> None:
    rows = [
        _row(1, payload_length=20, retransmission=True),
        _row(2, reverse=True, sequence=200, acknowledgment=120),
    ]

    report = _analyze(rows)
    first_human = _rich_text(report)
    second_human = _rich_text(report)
    first_json = render_tcp_conversations_json(report)
    second_json = render_tcp_conversations_json(report)

    assert report.status is TCPAnalysisStatus.ANALYZED_WITH_FINDINGS
    assert "TCP_RETRANSMISSION_INDICATORS_OBSERVED" in first_human
    assert first_human == second_human
    assert first_json == second_json


def test_one_direction_pipeline_produces_limited_report() -> None:
    report = _analyze([_row(1, payload_length=20)])

    assert report.status is TCPAnalysisStatus.LIMITED
    assert "Overall status: LIMITED" in _rich_text(report)
    assert json.loads(render_tcp_conversations_json(report))["status"] == "limited"
