"""Tests for deterministic TCP conversation analysis."""

from __future__ import annotations

from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from packet_investigator.analyzers.tcp_conversations import (
    analyze_tcp_conversations,
)
from packet_investigator.models.capture_quality import (
    CaptureQualityCapture,
    CaptureQualityStatus,
)
from packet_investigator.models.tcp_conversations import (
    TCPAnalysisReport,
    TCPAnalysisStatus,
    TCPClosureState,
    TCPConversationStatus,
    TCPDirection,
    TCPHandshakeState,
    TCPRole,
    TCPRoleEvidenceStrength,
)
from packet_investigator.parsers import tcp_conversations
from packet_investigator.parsers.tcp_conversations import TCPSymptomEvidence

_START_EPOCH = 1_785_592_800
_START = datetime.fromtimestamp(_START_EPOCH, tz=UTC)


def _row(
    frame_number: int,
    *,
    reverse: bool = False,
    timestamp_offset: float | None = None,
    stream_id: str = "0",
    source_port: int | None = None,
    destination_port: int | None = None,
    sequence: int | None = 1000,
    acknowledgment: int | None = 0,
    payload_length: int = 0,
    flags: int = 0x10,
    syn: bool = False,
    ack: bool = True,
    fin: bool = False,
    reset: bool = False,
    window: int = 64_240,
    indicators: dict[str, str] | None = None,
) -> str:
    projection = tcp_conversations._build_projection(
        frozenset(tcp_conversations._ALL_FIELDS)
    )
    if reverse:
        source, destination = "198.51.100.20", "192.0.2.10"
        default_source_port, default_destination_port = 443, 49_152
    else:
        source, destination = "192.0.2.10", "198.51.100.20"
        default_source_port, default_destination_port = 49_152, 443
    source_port = default_source_port if source_port is None else source_port
    destination_port = (
        default_destination_port if destination_port is None else destination_port
    )
    offset = frame_number / 10 if timestamp_offset is None else timestamp_offset
    values = {
        "frame.number": str(frame_number),
        "frame.time_epoch": str(_START_EPOCH + offset),
        "frame.interface_id": "0",
        "frame.cap_len": "64",
        "frame.len": "64",
        "frame.protocols": "eth:ip:tcp",
        "ip.src": source,
        "ip.dst": destination,
        "ipv6.src": "",
        "ipv6.dst": "",
        "tcp.stream": stream_id,
        "tcp.srcport": str(source_port),
        "tcp.dstport": str(destination_port),
        "tcp.seq_raw": "" if sequence is None else str(sequence),
        "tcp.ack_raw": "" if acknowledgment is None else str(acknowledgment),
        "tcp.len": str(payload_length),
        "tcp.hdr_len": "20",
        "tcp.window_size_value": str(window),
        "tcp.window_size": str(window),
        "tcp.flags": hex(flags),
        "tcp.flags.syn": "1" if syn else "0",
        "tcp.flags.ack": "1" if ack else "0",
        "tcp.flags.fin": "1" if fin else "0",
        "tcp.flags.reset": "1" if reset else "0",
        "tcp.analysis.initial_rtt": "",
    }
    values.update(indicators or {})
    return tcp_conversations._projected_row(values, projection)


def _complete_rows() -> list[str]:
    return [
        _row(1, sequence=100, flags=0x02, syn=True, ack=False),
        _row(
            2,
            reverse=True,
            sequence=200,
            acknowledgment=101,
            flags=0x12,
            syn=True,
        ),
        _row(3, sequence=101, acknowledgment=201),
        _row(4, sequence=101, acknowledgment=201, flags=0x11, fin=True),
        _row(5, reverse=True, sequence=201, acknowledgment=102),
        _row(
            6,
            reverse=True,
            sequence=201,
            acknowledgment=102,
            flags=0x11,
            fin=True,
        ),
        _row(7, sequence=102, acknowledgment=202),
    ]


def _collection(rows: list[str]) -> tcp_conversations.TCPConversationCollection:
    return tcp_conversations._collect_tcp_rows(rows)


def _capture(*, path: Path | None = None) -> CaptureQualityCapture:
    return CaptureQualityCapture(
        filename="synthetic-tcp.pcapng",
        path=path,
        capture_format="PCAPNG",
        size_bytes=2048,
        packet_count=10,
        start_time=_START,
        end_time=_START + timedelta(seconds=1),
        duration_seconds=1.0,
        interface_ids=("0",),
        tshark_version="4.6.6",
        inspection_status="Inspection complete",
    )


def _analyze(
    rows: list[str],
    *,
    collection: tcp_conversations.TCPConversationCollection | None = None,
    path: Path | None = None,
    quality_status: CaptureQualityStatus = CaptureQualityStatus.USABLE,
) -> TCPAnalysisReport:
    evidence = _collection(rows) if collection is None else collection
    return analyze_tcp_conversations(
        evidence,
        capture=_capture(path=path),
        capture_quality_status=quality_status,
    )


def _finding_codes(rows: list[str]) -> tuple[str, ...]:
    return tuple(item.code for item in _analyze(rows).conversations[0].findings)


def test_complete_handshake_orderly_close_and_roles() -> None:
    report = _analyze(_complete_rows())
    conversation = report.conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.COMPLETE
    assert conversation.handshake.syn_frame == 1
    assert conversation.handshake.syn_ack_frame == 2
    assert conversation.handshake.final_ack_frame == 3
    assert conversation.closure.state is TCPClosureState.ORDERLY
    assert conversation.roles.observed_initiator == "a"
    assert conversation.roles.inferred_client == "a"
    assert conversation.roles.endpoint_a_role is TCPRole.CLIENT
    assert conversation.roles.strength is TCPRoleEvidenceStrength.SUPPORTED
    assert conversation.status is TCPConversationStatus.COMPLETE
    assert report.status is TCPAnalysisStatus.ANALYZED


def test_unrelated_ack_does_not_complete_handshake() -> None:
    rows = _complete_rows()[:2]
    rows.append(_row(3, sequence=101, acknowledgment=999))

    conversation = _analyze(rows).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.INCOMPLETE
    assert conversation.handshake.final_ack_frame is None
    assert "TCP_HANDSHAKE_INCOMPLETE" in {item.code for item in conversation.findings}


def test_sequence_wraparound_matches_handshake() -> None:
    rows = [
        _row(
            1,
            sequence=0xFFFFFFFF,
            flags=0x02,
            syn=True,
            ack=False,
        ),
        _row(
            2,
            reverse=True,
            sequence=0xFFFFFFFF,
            acknowledgment=0,
            flags=0x12,
            syn=True,
        ),
        _row(3, sequence=0, acknowledgment=0),
    ]

    handshake = _analyze(rows).conversations[0].handshake

    assert handshake.state is TCPHandshakeState.COMPLETE


def test_multiple_syn_ack_sequence_candidates_leave_handshake_ambiguous() -> None:
    rows = [
        _row(1, sequence=100, flags=0x02, syn=True, ack=False),
        _row(
            2,
            reverse=True,
            sequence=200,
            acknowledgment=101,
            flags=0x12,
            syn=True,
        ),
        _row(
            3,
            reverse=True,
            sequence=300,
            acknowledgment=101,
            flags=0x12,
            syn=True,
        ),
        _row(4, sequence=101, acknowledgment=201),
    ]

    conversation = _analyze(rows).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.AMBIGUOUS
    assert conversation.handshake.syn_ack_frame is None
    assert conversation.roles.inferred_client is None
    assert conversation.roles.inferred_server is None


def test_handshake_matching_does_not_depend_on_generic_frame_sampling() -> None:
    rows = [_row(1, sequence=100, flags=0x02, syn=True, ack=False)]
    rows.extend(
        _row(
            frame,
            reverse=True,
            sequence=200 + frame,
            acknowledgment=999 if frame != 6 else 101,
            flags=0x12,
            syn=True,
        )
        for frame in range(2, 12)
    )
    rows.append(_row(12, sequence=101, acknowledgment=207))

    conversation = _analyze(rows).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.COMPLETE
    assert conversation.handshake.syn_ack_frame == 6
    assert conversation.handshake.final_ack_frame == 12


def test_simultaneous_open_detection_does_not_depend_on_frame_sampling() -> None:
    rows = [
        _row(frame, sequence=100, flags=0x02, syn=True, ack=False)
        for frame in range(1, 11)
    ]
    rows[5] = _row(
        6,
        reverse=True,
        sequence=200,
        flags=0x02,
        syn=True,
        ack=False,
    )

    conversation = _analyze(rows).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.SIMULTANEOUS_OPEN
    assert conversation.roles.endpoint_a_role is TCPRole.AMBIGUOUS


def test_syn_only_is_incomplete_with_observed_initiator() -> None:
    conversation = _analyze([_row(1, flags=0x02, syn=True, ack=False)]).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.INCOMPLETE
    assert conversation.roles.observed_initiator == "a"
    assert conversation.roles.inferred_client == "a"
    assert conversation.roles.strength is TCPRoleEvidenceStrength.SUGGESTED


def test_reverse_direction_handshake_preserves_canonical_endpoint_roles() -> None:
    rows = [
        _row(
            1,
            reverse=True,
            sequence=200,
            flags=0x02,
            syn=True,
            ack=False,
        ),
        _row(
            2,
            sequence=100,
            acknowledgment=201,
            flags=0x12,
            syn=True,
        ),
        _row(3, reverse=True, sequence=201, acknowledgment=101),
    ]

    roles = _analyze(rows).conversations[0].roles

    assert roles.observed_initiator == "b"
    assert roles.inferred_client == "b"
    assert roles.endpoint_b_role is TCPRole.CLIENT


def test_syn_ack_without_syn_is_ambiguous() -> None:
    conversation = _analyze(
        [
            _row(
                1,
                reverse=True,
                sequence=200,
                acknowledgment=101,
                flags=0x12,
                syn=True,
            )
        ]
    ).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.AMBIGUOUS
    assert conversation.roles.inferred_client is None


def test_midstream_payload_suppresses_incomplete_handshake() -> None:
    codes = _finding_codes([_row(1, payload_length=20)])

    assert "TCP_MIDSTREAM_CONVERSATION" in codes
    assert "TCP_HANDSHAKE_INCOMPLETE" not in codes


def test_established_behavior_before_later_syn_remains_midstream() -> None:
    rows = [
        _row(1, payload_length=20),
        _row(2, sequence=300, flags=0x02, syn=True, ack=False),
    ]

    conversation = _analyze(rows).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.MIDSTREAM
    assert "TCP_MIDSTREAM_CONVERSATION" in {item.code for item in conversation.findings}


def test_simultaneous_open_is_role_ambiguous() -> None:
    rows = [
        _row(1, sequence=100, flags=0x02, syn=True, ack=False),
        _row(
            2,
            reverse=True,
            sequence=200,
            flags=0x02,
            syn=True,
            ack=False,
        ),
    ]

    conversation = _analyze(rows).conversations[0]

    assert conversation.handshake.state is TCPHandshakeState.SIMULTANEOUS_OPEN
    assert conversation.roles.endpoint_a_role is TCPRole.AMBIGUOUS
    assert "TCP_SIMULTANEOUS_OPEN_OBSERVED" in {
        item.code for item in conversation.findings
    }


def test_syn_retries_count_only_repeated_observations() -> None:
    rows = [
        _row(1, sequence=100, flags=0x02, syn=True, ack=False),
        _row(2, sequence=100, flags=0x02, syn=True, ack=False),
        _row(
            3,
            reverse=True,
            sequence=200,
            acknowledgment=101,
            flags=0x12,
            syn=True,
        ),
        _row(4, sequence=101, acknowledgment=201),
    ]

    conversation = _analyze(rows).conversations[0]
    finding = next(
        item for item in conversation.findings if item.code == "TCP_SYN_RETRY_OBSERVED"
    )

    assert conversation.handshake.syn_retries == 1
    assert finding.evidence.values["retry_count"] == 1
    assert finding.evidence.representative_frames == (1, 2)


def test_syn_ack_retries_are_separate_from_syn_retries() -> None:
    rows = [
        _row(1, sequence=100, flags=0x02, syn=True, ack=False),
        _row(
            2,
            reverse=True,
            sequence=200,
            acknowledgment=101,
            flags=0x12,
            syn=True,
        ),
        _row(
            3,
            reverse=True,
            sequence=200,
            acknowledgment=101,
            flags=0x12,
            syn=True,
        ),
        _row(4, sequence=101, acknowledgment=201),
    ]

    conversation = _analyze(rows).conversations[0]

    assert conversation.handshake.syn_ack_retries == 1
    assert "TCP_SYN_ACK_RETRY_OBSERVED" in {item.code for item in conversation.findings}


def test_retry_counts_remain_exact_when_frame_evidence_is_bounded() -> None:
    rows = [
        _row(frame, sequence=100, flags=0x02, syn=True, ack=False)
        for frame in range(1, 11)
    ]

    conversation = _analyze(rows).conversations[0]
    finding = next(
        item for item in conversation.findings if item.code == "TCP_SYN_RETRY_OBSERVED"
    )

    assert conversation.handshake.syn_retries == 9
    assert finding.evidence.values["retry_count"] == 9
    assert finding.evidence.representative_frames == (1, 2, 3, 4, 7, 8, 9, 10)


@pytest.mark.parametrize(
    ("source_port", "destination_port", "client"),
    [
        (80, 443, None),
        (50_000, 51_000, None),
        (443, 443, None),
        (50_000, 0, "a"),
        (443, 50_000, None),
    ],
)
def test_port_convention_is_only_noncontradictory_secondary_role_evidence(
    source_port: int,
    destination_port: int,
    client: str | None,
) -> None:
    conversation = _analyze(
        [
            _row(
                1,
                source_port=source_port,
                destination_port=destination_port,
                flags=0x02,
                syn=True,
                ack=False,
            )
        ]
    ).conversations[0]

    assert conversation.roles.observed_initiator == "a"
    assert conversation.roles.inferred_client == client


@pytest.mark.parametrize(
    ("rows", "expected_code"),
    [
        (
            [
                _row(1, sequence=100, flags=0x02, syn=True, ack=False),
                _row(2, reverse=True, flags=0x04, ack=False, reset=True),
            ],
            "TCP_RESET_AFTER_SYN",
        ),
        (
            [
                *_complete_rows()[:3],
                _row(4, reverse=True, flags=0x04, ack=False, reset=True),
            ],
            "TCP_RESET_AFTER_ESTABLISHMENT",
        ),
        (
            [_row(1, reverse=True, flags=0x04, ack=False, reset=True)],
            "TCP_RESET_OBSERVED",
        ),
    ],
)
def test_reset_taxonomy_uses_one_most_specific_code(
    rows: list[str],
    expected_code: str,
) -> None:
    conversation = _analyze(rows).conversations[0]
    reset_codes = tuple(
        item.code for item in conversation.findings if "RESET" in item.code
    )

    assert reset_codes == (expected_code,)
    assert conversation.closure.first_reset_direction is TCPDirection.B_TO_A
    assert "firewall" not in conversation.findings[0].observation.lower()


def test_reset_suppresses_incomplete_close() -> None:
    rows = [
        *_complete_rows()[:4],
        _row(5, reverse=True, flags=0x04, ack=False, reset=True),
    ]

    codes = _finding_codes(rows)

    assert "TCP_RESET_AFTER_ESTABLISHMENT" in codes
    assert "TCP_CLOSE_STATE_INCOMPLETE" not in codes


def test_multiple_resets_produce_one_finding_with_exact_count() -> None:
    rows = [
        *_complete_rows()[:3],
        _row(4, reverse=True, flags=0x04, ack=False, reset=True),
        _row(5, reverse=True, flags=0x04, ack=False, reset=True),
    ]

    conversation = _analyze(rows).conversations[0]
    reset_findings = tuple(
        finding for finding in conversation.findings if "RESET" in finding.code
    )

    assert len(reset_findings) == 1
    assert reset_findings[0].code == "TCP_RESET_AFTER_ESTABLISHMENT"
    assert reset_findings[0].evidence.values["reset_count"] == 2


def test_reset_after_syn_preserves_incomplete_handshake_evidence() -> None:
    codes = _finding_codes(
        [
            _row(1, sequence=100, flags=0x02, syn=True, ack=False),
            _row(2, reverse=True, flags=0x04, ack=False, reset=True),
        ]
    )

    assert "TCP_HANDSHAKE_INCOMPLETE" in codes
    assert "TCP_RESET_AFTER_SYN" in codes
    assert "TCP_RESET_OBSERVED" not in codes


def test_one_fin_is_incomplete_close() -> None:
    conversation = _analyze(_complete_rows()[:4]).conversations[0]

    assert conversation.closure.state is TCPClosureState.FIN_INCOMPLETE
    assert "TCP_CLOSE_STATE_INCOMPLETE" in {item.code for item in conversation.findings}


def test_complete_handshake_with_no_close_is_partial_not_unhealthy() -> None:
    report = _analyze(_complete_rows()[:3])
    conversation = report.conversations[0]

    assert conversation.closure.state is TCPClosureState.NOT_OBSERVED
    assert conversation.status is TCPConversationStatus.PARTIAL
    assert report.status is TCPAnalysisStatus.ANALYZED_WITH_FINDINGS
    assert "TCP_CLOSE_STATE_INCOMPLETE" not in {
        item.code for item in conversation.findings
    }


def test_unrelated_ack_does_not_acknowledge_fin() -> None:
    rows = [
        *_complete_rows()[:4],
        _row(5, reverse=True, acknowledgment=999),
        _row(
            6,
            reverse=True,
            sequence=201,
            acknowledgment=999,
            flags=0x11,
            fin=True,
        ),
        _row(7, acknowledgment=202),
    ]

    closure = _analyze(rows).conversations[0].closure

    assert closure.state is TCPClosureState.AMBIGUOUS
    assert closure.fin_a_to_b_ack_frame is None


def test_fin_sequence_wraparound_is_acknowledged() -> None:
    rows = [
        *_complete_rows()[:3],
        _row(
            4,
            sequence=0xFFFFFFFF,
            acknowledgment=201,
            flags=0x11,
            fin=True,
        ),
        _row(5, reverse=True, sequence=201, acknowledgment=0),
    ]

    closure = _analyze(rows).conversations[0].closure

    assert closure.fin_a_to_b_ack_frame == 5


@pytest.mark.parametrize(
    ("indicator", "expected_code"),
    [
        (
            "tcp.analysis.retransmission",
            "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
        ),
        ("tcp.analysis.fast_retransmission", "TCP_RETRANSMISSION_INDICATORS_OBSERVED"),
        (
            "tcp.analysis.spurious_retransmission",
            "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
        ),
        ("tcp.analysis.duplicate_ack", "TCP_DUPLICATE_ACKS_OBSERVED"),
        ("tcp.analysis.out_of_order", "TCP_OUT_OF_ORDER_INDICATORS_OBSERVED"),
        ("tcp.analysis.lost_segment", "TCP_LOST_SEGMENT_INDICATORS_OBSERVED"),
        ("tcp.analysis.ack_lost_segment", "TCP_LOST_SEGMENT_INDICATORS_OBSERVED"),
        ("tcp.analysis.window_full", "TCP_WINDOW_FULL_OBSERVED"),
        ("tcp.analysis.keep_alive", "TCP_KEEPALIVE_ACTIVITY_OBSERVED"),
        ("tcp.analysis.keep_alive_ack", "TCP_KEEPALIVE_ACTIVITY_OBSERVED"),
    ],
)
def test_tshark_symptoms_use_consolidated_stable_findings(
    indicator: str,
    expected_code: str,
) -> None:
    report = _analyze([_row(1, indicators={indicator: "1"})])
    finding = next(
        item for item in report.conversations[0].findings if item.code == expected_code
    )

    assert finding.evidence.provenance.value == "tshark_derived"
    assert "TShark" in finding.observation or "TShark" in (finding.interpretation or "")
    assert "network dropped" not in (finding.interpretation or "").lower()


def test_zero_window_requires_raw_corroboration_when_available() -> None:
    without_raw = _finding_codes(
        [
            _row(
                1,
                indicators={"tcp.analysis.zero_window": "1"},
                window=1024,
            )
        ]
    )
    with_raw = _finding_codes(
        [
            _row(
                1,
                indicators={"tcp.analysis.zero_window": "1"},
                window=0,
            )
        ]
    )

    assert "TCP_ZERO_WINDOW_OBSERVED" not in without_raw
    assert "TCP_ZERO_WINDOW_OBSERVED" in with_raw


def test_zero_window_evidence_count_is_exact_when_frames_are_sampled() -> None:
    rows = [
        _row(
            frame,
            window=0,
            indicators={"tcp.analysis.zero_window": "1"},
        )
        for frame in range(1, 11)
    ]

    finding = next(
        finding
        for finding in _analyze(rows).conversations[0].findings
        if finding.code == "TCP_ZERO_WINDOW_OBSERVED"
    )

    assert finding.evidence.values["raw_zero_window_frames"] == 10
    assert len(finding.evidence.representative_frames) == 8


def test_one_way_payload_requires_both_visible_directions() -> None:
    one_direction = _finding_codes([_row(1, payload_length=20)])
    both_directions = _finding_codes(
        [
            _row(1, payload_length=20),
            _row(2, reverse=True, sequence=200, acknowledgment=102),
        ]
    )

    assert "TCP_ONE_WAY_PAYLOAD_OBSERVED" not in one_direction
    assert "TCP_ONE_WAY_PAYLOAD_OBSERVED" in both_directions


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        (
            [
                _row(1, payload_length=20),
                _row(2, reverse=True, sequence=200, payload_length=10),
            ],
            False,
        ),
        (
            [
                _row(1),
                _row(2, reverse=True, sequence=200, payload_length=10),
            ],
            True,
        ),
        ([_row(1), _row(2, reverse=True, sequence=200)], False),
    ],
)
def test_one_way_payload_directional_cases(
    rows: list[str],
    expected: bool,
) -> None:
    assert ("TCP_ONE_WAY_PAYLOAD_OBSERVED" in _finding_codes(rows)) is expected


def test_one_way_payload_is_suppressed_when_tracking_is_incomplete() -> None:
    evidence = _collection(
        [
            _row(1, payload_length=20),
            _row(2, reverse=True, sequence=200, acknowledgment=102),
        ]
    )
    limited = replace(evidence, conversation_tracking_complete=False)
    report = _analyze([], collection=limited)

    assert "TCP_ONE_WAY_PAYLOAD_OBSERVED" not in {
        item.code for item in report.conversations[0].findings
    }


def test_one_way_payload_is_suppressed_for_ambiguous_tuple_identity() -> None:
    evidence = _collection(
        [
            _row(1, payload_length=20),
            _row(2, reverse=True, sequence=200, acknowledgment=102),
        ]
    )
    conversation = replace(
        evidence.conversations[0],
        collection_codes=("TCP_TUPLE_REUSE_AMBIGUOUS",),
    )
    ambiguous = replace(evidence, conversations=(conversation,))

    report = _analyze([], collection=ambiguous)

    assert "TCP_ONE_WAY_PAYLOAD_OBSERVED" not in {
        item.code for item in report.conversations[0].findings
    }


def test_findings_order_and_recommendations_deduplicate() -> None:
    rows = [
        _row(
            1,
            payload_length=20,
            indicators={
                "tcp.analysis.retransmission": "1",
                "tcp.analysis.duplicate_ack": "1",
            },
        ),
        _row(2, reverse=True, sequence=200, acknowledgment=102),
    ]
    report = _analyze(rows)
    codes = tuple(item.code for item in report.conversations[0].findings)

    assert codes == (
        "TCP_MIDSTREAM_CONVERSATION",
        "TCP_RETRANSMISSION_INDICATORS_OBSERVED",
        "TCP_DUPLICATE_ACKS_OBSERVED",
        "TCP_ONE_WAY_PAYLOAD_OBSERVED",
    )
    recommendation_codes = tuple(item.code for item in report.recommendations)
    assert len(recommendation_codes) == len(set(recommendation_codes))


def test_aggregation_preserves_conversation_order_and_finding_counts() -> None:
    evidence = _collection(
        [
            _row(1, stream_id="99", payload_length=10),
            _row(2, stream_id="1", payload_length=10),
        ]
    )

    report = _analyze([], collection=evidence)

    assert tuple(item.identity.conversation_id for item in report.conversations) == (
        "tcp-000001",
        "tcp-000002",
    )
    assert report.analysis_statistics.finding_counts["TCP_MIDSTREAM_CONVERSATION"] == 2


def test_analyzer_bounds_representative_frames_with_first_and_recent_policy() -> None:
    evidence = _collection([_row(1)])
    conversation = evidence.conversations[0]
    symptom_evidence = replace(
        conversation.symptom_evidence,
        counts=tuple(
            (
                name,
                10 if name == "duplicate_ack" else count,
            )
            for name, count in conversation.symptom_evidence.counts
        ),
        representative_frames=tuple(
            (
                name,
                tuple(range(1, 11)) if name == "duplicate_ack" else frames,
            )
            for name, frames in conversation.symptom_evidence.representative_frames
        ),
    )
    assert isinstance(symptom_evidence, TCPSymptomEvidence)
    modified = replace(
        evidence,
        conversations=(replace(conversation, symptom_evidence=symptom_evidence),),
    )

    finding = next(
        item
        for item in _analyze([], collection=modified).conversations[0].findings
        if item.code == "TCP_DUPLICATE_ACKS_OBSERVED"
    )

    assert finding.evidence.representative_frames == (1, 2, 3, 4, 7, 8, 9, 10)


def test_empty_collection_is_insufficient() -> None:
    report = _analyze([], collection=_collection([]))

    assert report.status is TCPAnalysisStatus.INSUFFICIENT
    assert report.conversations == ()


def test_tracking_limit_creates_report_limitation_and_limited_status() -> None:
    evidence = replace(
        _collection(_complete_rows()),
        conversation_tracking_complete=False,
        untracked_conversation_rows=1,
        collection_codes=("TCP_FLOW_TRACKING_LIMIT_REACHED",),
    )
    report = _analyze([], collection=evidence)

    assert report.status is TCPAnalysisStatus.LIMITED
    assert tuple(item.code for item in report.limitations)[0] == (
        "TCP_FLOW_TRACKING_LIMIT_REACHED"
    )


def test_stream_tuple_conflict_limits_each_affected_conversation() -> None:
    evidence = _collection(
        [
            *_complete_rows(),
            _row(8, stream_id="0", source_port=49_153, payload_length=10),
        ]
    )

    report = _analyze([], collection=evidence)

    assert all(
        conversation.status is TCPConversationStatus.LIMITED
        for conversation in report.conversations
    )
    assert all(
        "TCP_STREAM_IDENTITY_CONFLICT"
        in {limitation.code for limitation in conversation.limitations}
        for conversation in report.conversations
    )
    assert report.status is TCPAnalysisStatus.LIMITED


def test_capture_quality_limited_sets_report_floor() -> None:
    report = _analyze(
        _complete_rows(),
        quality_status=CaptureQualityStatus.LIMITED,
    )

    assert report.status is TCPAnalysisStatus.LIMITED


def test_capture_quality_limitations_are_preserved_and_affect_report_status() -> None:
    report = analyze_tcp_conversations(
        _collection(_complete_rows()),
        capture=_capture(),
        capture_quality_status=CaptureQualityStatus.USABLE_WITH_LIMITATIONS,
        capture_quality_limitation_codes=("MULTIPLE_INTERFACES_OBSERVED",),
    )

    assert report.capture_quality_limitation_codes == ("MULTIPLE_INTERFACES_OBSERVED",)
    assert report.status is TCPAnalysisStatus.ANALYZED_WITH_FINDINGS


def test_missing_raw_sequence_capability_limits_exact_handshake_matching() -> None:
    evidence = _collection(_complete_rows())
    supported_raw = tuple(
        item
        for item in evidence.capabilities.supported_optional_raw
        if item not in {"tcp.seq_raw", "tcp.ack_raw"}
    )
    limited = replace(
        evidence,
        capabilities=replace(
            evidence.capabilities,
            supported_optional_raw=supported_raw,
            unsupported_optional_raw=("tcp.seq_raw", "tcp.ack_raw"),
        ),
    )

    report = _analyze([], collection=limited)

    assert report.conversations[0].handshake.state is TCPHandshakeState.INCOMPLETE
    assert "TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE" in {
        item.code for item in report.limitations
    }
    assert report.conversations[0].status is TCPConversationStatus.LIMITED
    assert report.status is TCPAnalysisStatus.LIMITED


def test_missing_row_sequence_context_is_visible_and_material() -> None:
    conversation = _analyze(
        [_row(1, sequence=None, flags=0x02, syn=True, ack=False)]
    ).conversations[0]

    assert "TCP_RAW_SEQUENCE_FIELDS_UNAVAILABLE" in {
        limitation.code for limitation in conversation.limitations
    }
    assert conversation.status is TCPConversationStatus.LIMITED


def test_parser_warnings_are_consolidated_as_report_limitation() -> None:
    evidence = replace(
        _collection(_complete_rows()),
        total_parser_warnings=3,
    )

    report = _analyze([], collection=evidence)

    assert (
        sum(item.code == "TCP_UNUSABLE_ROWS_SKIPPED" for item in report.limitations)
        == 1
    )


def test_optional_parse_warning_is_not_a_material_conversation_limit() -> None:
    evidence = _collection(_complete_rows())
    conversation = replace(evidence.conversations[0], optional_parse_errors=1)
    warned = replace(
        evidence,
        conversations=(conversation,),
        malformed_optional_fields=1,
        total_parser_warnings=1,
    )

    report = _analyze([], collection=warned)

    assert (
        report.conversations[0].status is TCPConversationStatus.COMPLETE_WITH_FINDINGS
    )
    assert report.status is TCPAnalysisStatus.ANALYZED_WITH_FINDINGS


def test_one_limited_conversation_does_not_force_report_limited() -> None:
    evidence = _collection(
        [
            *_complete_rows(),
            _row(8, stream_id="1", source_port=49_153, payload_length=10),
        ]
    )

    report = _analyze([], collection=evidence)

    assert report.conversations[0].status is TCPConversationStatus.COMPLETE
    assert report.conversations[1].status is TCPConversationStatus.LIMITED
    assert report.status is TCPAnalysisStatus.ANALYZED_WITH_FINDINGS


def test_warning_finding_does_not_make_complete_analysis_limited() -> None:
    rows = _complete_rows()
    rows[2] = _row(
        3,
        sequence=101,
        acknowledgment=201,
        indicators={"tcp.analysis.duplicate_ack": "1"},
    )

    report = _analyze(rows)

    assert (
        report.conversations[0].status is TCPConversationStatus.COMPLETE_WITH_FINDINGS
    )
    assert report.status is TCPAnalysisStatus.ANALYZED_WITH_FINDINGS


def test_partial_conversation_with_finding_remains_partial() -> None:
    rows = _complete_rows()[:3]
    rows[2] = _row(
        3,
        sequence=101,
        acknowledgment=201,
        indicators={"tcp.analysis.duplicate_ack": "1"},
    )

    conversation = _analyze(rows).conversations[0]

    assert conversation.status is TCPConversationStatus.PARTIAL
    assert "TCP_DUPLICATE_ACKS_OBSERVED" in {
        finding.code for finding in conversation.findings
    }


def test_limited_conversation_with_finding_remains_limited() -> None:
    conversation = _analyze(
        [
            _row(
                1,
                payload_length=10,
                indicators={"tcp.analysis.duplicate_ack": "1"},
            )
        ]
    ).conversations[0]

    assert conversation.status is TCPConversationStatus.LIMITED
    assert "TCP_DUPLICATE_ACKS_OBSERVED" in {
        finding.code for finding in conversation.findings
    }


def test_analysis_is_pure_equal_and_deterministic() -> None:
    evidence = _collection(_complete_rows())
    before = repr(evidence)

    first = _analyze([], collection=evidence)
    second = _analyze([], collection=evidence)

    assert repr(evidence) == before
    assert first == second
    assert first.model_dump_json() == second.model_dump_json()
    assert first.schema_version == "1.0"
    with pytest.raises(ValidationError):
        first.status = TCPAnalysisStatus.LIMITED


def test_path_privacy_is_preserved(tmp_path: Path) -> None:
    without_path = _analyze(_complete_rows())
    explicit_path = _analyze(
        _complete_rows(),
        path=(tmp_path / "synthetic.pcapng").resolve(),
    )

    assert "path" not in without_path.model_dump()["capture"]
    assert explicit_path.capture.path is not None
    assert "path" in explicit_path.model_dump()["capture"]


def test_timestamp_regression_remains_visible_without_analysis_failure() -> None:
    evidence = _collection(
        [
            _row(1, timestamp_offset=1.0),
            _row(2, timestamp_offset=0.5),
        ]
    )

    report = _analyze([], collection=evidence)
    conversation = report.conversations[0]

    assert conversation.statistics.duration_seconds is None
    assert "timing_limited_by_timestamp_quality" in {
        item.value for item in conversation.timings.availability
    }
    assert "TCP_TIMING_INTERPRETATION_LIMITED" in {
        item.code for item in report.limitations
    }


def test_regressing_handshake_timestamps_make_intervals_unavailable() -> None:
    rows = [
        _row(
            1,
            timestamp_offset=1.0,
            sequence=100,
            flags=0x02,
            syn=True,
            ack=False,
        ),
        _row(
            2,
            reverse=True,
            timestamp_offset=0.5,
            sequence=200,
            acknowledgment=101,
            flags=0x12,
            syn=True,
        ),
        _row(
            3,
            timestamp_offset=0.25,
            sequence=101,
            acknowledgment=201,
        ),
    ]

    handshake = _analyze(rows).conversations[0].handshake

    assert handshake.state is TCPHandshakeState.COMPLETE
    assert handshake.syn_to_syn_ack_seconds is None
    assert handshake.syn_ack_to_ack_seconds is None


def test_payload_timing_is_unavailable_when_timestamp_precedes_first_frame() -> None:
    rows = [
        _row(1, timestamp_offset=1.0),
        _row(2, timestamp_offset=0.5, payload_length=20),
        _row(
            3,
            reverse=True,
            timestamp_offset=0.25,
            sequence=200,
            acknowledgment=102,
            payload_length=10,
        ),
    ]

    timings = _analyze(rows).conversations[0].timings

    assert timings.time_to_first_payload_a_to_b_seconds is None
    assert timings.time_to_first_payload_b_to_a_seconds is None


def test_tshark_initial_rtt_is_preserved_during_timestamp_regression() -> None:
    rows = [
        _row(
            1,
            timestamp_offset=1.0,
            indicators={"tcp.analysis.initial_rtt": "0.025"},
        ),
        _row(2, timestamp_offset=0.5),
    ]

    timings = _analyze(rows).conversations[0].timings

    assert timings.tshark_initial_rtt_seconds == 0.025
    assert "timing_tshark_derived" in {
        availability.value for availability in timings.availability
    }


def test_complete_report_round_trips_through_schema_model() -> None:
    report = _analyze(_complete_rows())

    restored = TCPAnalysisReport.model_validate_json(report.model_dump_json())

    assert restored == report
