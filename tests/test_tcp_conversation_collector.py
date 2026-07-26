"""Tests for streaming TCP conversation evidence collection."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Iterator
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest

from packet_investigator.models.tcp_conversations import (
    TCPDirection,
    TCPGroupingBasis,
)
from packet_investigator.parsers import tcp_conversations, tshark

if TYPE_CHECKING:
    from pytest import MonkeyPatch


def _row(
    *,
    supported_fields: frozenset[str] | None = None,
    frame_number: int = 1,
    timestamp: str = "1785592800.0",
    protocols: str = "eth:ip:tcp",
    interface_id: str = "0",
    ip_source: str = "192.0.2.10",
    ip_destination: str = "198.51.100.20",
    ipv6_source: str = "",
    ipv6_destination: str = "",
    source_port: str = "49152",
    destination_port: str = "443",
    stream_id: str = "0",
    captured_length: str = "64",
    original_length: str = "64",
    payload_length: str = "0",
    header_length: str = "20",
    sequence_number: str = "1000",
    acknowledgment_number: str = "0",
    window_value: str = "64240",
    effective_window: str = "64240",
    flags: str = "0x0010",
    syn: str = "0",
    ack: str = "1",
    fin: str = "0",
    reset: str = "0",
    initial_rtt: str = "",
    indicators: dict[str, str] | None = None,
) -> str:
    capabilities = (
        frozenset(tcp_conversations._ALL_FIELDS)
        if supported_fields is None
        else supported_fields
    )
    projection = tcp_conversations._build_projection(capabilities)
    values = {
        "frame.number": str(frame_number),
        "frame.time_epoch": timestamp,
        "frame.interface_id": interface_id,
        "frame.cap_len": captured_length,
        "frame.len": original_length,
        "frame.protocols": protocols,
        "ip.src": ip_source,
        "ip.dst": ip_destination,
        "ipv6.src": ipv6_source,
        "ipv6.dst": ipv6_destination,
        "tcp.stream": stream_id,
        "tcp.srcport": source_port,
        "tcp.dstport": destination_port,
        "tcp.seq_raw": sequence_number,
        "tcp.ack_raw": acknowledgment_number,
        "tcp.len": payload_length,
        "tcp.hdr_len": header_length,
        "tcp.window_size_value": window_value,
        "tcp.window_size": effective_window,
        "tcp.flags": flags,
        "tcp.flags.syn": syn,
        "tcp.flags.ack": ack,
        "tcp.flags.fin": fin,
        "tcp.flags.reset": reset,
        "tcp.analysis.initial_rtt": initial_rtt,
    }
    values.update(indicators or {})
    return tcp_conversations._projected_row(values, projection)


def _collect(
    rows: Iterable[str],
    *,
    supported_fields: frozenset[str] | None = None,
) -> tcp_conversations.TCPConversationCollection:
    return tcp_conversations._collect_tcp_rows(
        rows,
        supported_fields=supported_fields,
    )


def _event_frames(
    conversation: tcp_conversations.TCPCollectedConversation,
    category: str,
) -> tuple[int, ...]:
    events = dict(conversation.flag_observations)
    return tuple(event.frame_number for event in events[category])


def _symptom_counts(
    conversation: tcp_conversations.TCPCollectedConversation,
) -> dict[str, int]:
    return dict(conversation.symptom_evidence.counts)


def test_empty_stream_returns_empty_immutable_collection() -> None:
    result = _collect(iter(()))

    assert result.conversations == ()
    assert result.rows_processed == 0
    assert result.usable_tcp_rows == 0
    assert result.conversation_tracking_complete
    with pytest.raises((AttributeError, TypeError)):
        result.rows_processed = 1  # type: ignore[misc]


def test_ipv4_reverse_rows_share_canonical_conversation() -> None:
    rows = [
        _row(frame_number=1, syn="1", ack="0", flags="0x0002"),
        _row(
            frame_number=2,
            ip_source="198.51.100.20",
            ip_destination="192.0.2.10",
            source_port="443",
            destination_port="49152",
            sequence_number="2000",
            acknowledgment_number="1001",
            syn="1",
            ack="1",
            flags="0x0012",
        ),
    ]

    result = _collect(rows)
    conversation = result.conversations[0]

    assert len(result.conversations) == 1
    assert str(conversation.identity.endpoint_a.address) == "192.0.2.10"
    assert conversation.identity.endpoint_a.port == 49_152
    assert conversation.a_to_b.packets == 1
    assert conversation.b_to_a.packets == 1
    assert _event_frames(conversation, "syn") == (1,)
    assert _event_frames(conversation, "syn_ack") == (2,)


def test_ipv6_uses_packed_address_ordering() -> None:
    result = _collect(
        [
            _row(
                protocols="eth:ipv6:tcp",
                ip_source="",
                ip_destination="",
                ipv6_source="2001:db8::ff",
                ipv6_destination="2001:db8::10",
                source_port="443",
                destination_port="50000",
            )
        ]
    )

    identity = result.conversations[0].identity
    assert str(identity.endpoint_a.address) == "2001:db8::10"
    assert str(identity.endpoint_b.address) == "2001:db8::ff"
    assert result.conversations[0].first_observed_direction is TCPDirection.B_TO_A


def test_verified_stream_groups_rows_and_stream_is_not_public_identity() -> None:
    result = _collect(
        [
            _row(frame_number=5, stream_id="77"),
            _row(frame_number=6, stream_id="77"),
        ]
    )

    identity = result.conversations[0].identity
    assert identity.conversation_id == "tcp-000001"
    assert identity.grouping_basis is TCPGroupingBasis.STREAM_AND_TUPLE
    assert "77" not in identity.model_dump_json()


def test_stream_tuple_conflict_creates_separate_groups() -> None:
    result = _collect(
        [
            _row(frame_number=1, stream_id="4"),
            _row(
                frame_number=2,
                stream_id="4",
                ip_source="192.0.2.30",
                source_port="50000",
            ),
        ]
    )

    assert len(result.conversations) == 2
    assert result.stream_tuple_conflicts == 1
    assert "TCP_STREAM_IDENTITY_CONFLICT" in result.collection_codes


def test_missing_stream_creates_and_then_joins_unique_fallback() -> None:
    result = _collect(
        [
            _row(frame_number=1, stream_id=""),
            _row(frame_number=2, stream_id=""),
        ]
    )

    assert len(result.conversations) == 1
    assert (
        result.conversations[0].identity.grouping_basis is TCPGroupingBasis.TUPLE_EPOCH
    )
    assert result.conversations[0].a_to_b.packets == 2


def test_later_stream_binds_unique_fallback_group() -> None:
    result = _collect(
        [
            _row(frame_number=1, stream_id=""),
            _row(frame_number=2, stream_id="9"),
        ]
    )

    assert len(result.conversations) == 1
    assert (
        result.conversations[0].identity.grouping_basis
        is TCPGroupingBasis.STREAM_AND_TUPLE
    )


def test_missing_stream_with_multiple_active_groups_is_ambiguous() -> None:
    result = _collect(
        [
            _row(frame_number=1, stream_id="1"),
            _row(frame_number=2, stream_id="2"),
            _row(frame_number=3, stream_id=""),
        ]
    )

    assert len(result.conversations) == 2
    assert result.unusable_tcp_rows == 1
    assert result.untracked_conversation_rows == 1
    assert "TCP_TUPLE_IDENTITY_AMBIGUOUS" in result.collection_codes


def test_distinct_streams_assign_epochs_by_frame_not_stream_number() -> None:
    result = _collect(
        [
            _row(frame_number=10, stream_id="99"),
            _row(frame_number=20, stream_id="1"),
        ]
    )

    assert [item.identity.epoch for item in result.conversations] == [1, 2]
    assert [item.identity.conversation_id for item in result.conversations] == [
        "tcp-000001",
        "tcp-000002",
    ]


def test_fallback_new_syn_sequence_creates_visible_ambiguous_epoch() -> None:
    result = _collect(
        [
            _row(
                frame_number=1,
                stream_id="",
                syn="1",
                ack="0",
                flags="0x0002",
                sequence_number="100",
            ),
            _row(
                frame_number=2,
                stream_id="",
                syn="1",
                ack="0",
                flags="0x0002",
                sequence_number="200",
            ),
        ]
    )

    assert len(result.conversations) == 2
    assert all(
        "TCP_TUPLE_REUSE_AMBIGUOUS" in item.collection_codes
        for item in result.conversations
    )


def test_midstream_rows_are_retained_without_inference() -> None:
    result = _collect([_row(payload_length="40")])

    conversation = result.conversations[0]
    assert conversation.a_to_b.payload_bytes == 40
    assert conversation.identity.grouping_basis is TCPGroupingBasis.STREAM_AND_TUPLE
    assert not hasattr(conversation, "handshake")
    assert not hasattr(conversation, "status")


@pytest.mark.parametrize(
    "protocols",
    ["eth:ip:gre:ip:tcp", "eth:ip:tcp:tcp", "eth:ip:ipv6:tcp"],
)
def test_tunneled_or_repeated_stack_is_excluded(protocols: str) -> None:
    result = _collect([_row(protocols=protocols)])

    assert result.conversations == ()
    assert result.ambiguous_encapsulation_rows == 1
    assert "TCP_ENCAPSULATED_IDENTITY_UNSUPPORTED" in result.collection_codes


def test_directional_aggregation_and_windows() -> None:
    rows = [
        _row(
            frame_number=1,
            captured_length="60",
            original_length="80",
            payload_length="20",
            window_value="4000",
            effective_window="8000",
        ),
        _row(
            frame_number=2,
            timestamp="1785592801.0",
            captured_length="70",
            original_length="90",
            payload_length="10",
            window_value="2000",
            effective_window="6000",
        ),
    ]

    result = _collect(rows)
    evidence = result.conversations[0].a_to_b

    assert evidence.packets == 2
    assert evidence.captured_bytes == 130
    assert evidence.original_frame_bytes == 170
    assert evidence.payload_bytes == 30
    assert evidence.first_frame == 1
    assert evidence.last_frame == 2
    assert evidence.first_payload_frame == 1
    assert evidence.minimum_window_value == 2000
    assert evidence.maximum_window_value == 4000
    assert evidence.minimum_effective_window == 6000
    assert evidence.maximum_effective_window == 8000


def test_fin_reset_and_ack_observations_remain_raw() -> None:
    result = _collect(
        [
            _row(frame_number=1),
            _row(frame_number=2, ack="0", fin="1", flags="0x0001"),
            _row(frame_number=3, ack="0", reset="1", flags="0x0004"),
        ]
    )
    conversation = result.conversations[0]

    assert _event_frames(conversation, "ack") == (1,)
    assert _event_frames(conversation, "fin") == (2,)
    assert _event_frames(conversation, "reset") == (3,)


def test_fin_acknowledgment_matching_retains_bounded_raw_evidence() -> None:
    result = _collect(
        [
            _row(
                frame_number=1,
                ack="0",
                fin="1",
                flags="0x0001",
                sequence_number="1000",
            ),
            _row(
                frame_number=2,
                ip_source="198.51.100.20",
                ip_destination="192.0.2.10",
                source_port="443",
                destination_port="49152",
                sequence_number="2000",
                acknowledgment_number="1001",
            ),
        ]
    )

    conversation = result.conversations[0]
    assert _event_frames(conversation, "fin") == (1,)
    assert _event_frames(conversation, "fin_ack_a_to_b") == (2,)
    assert not hasattr(conversation, "closure")


def test_derived_indicators_and_initial_rtt_are_aggregated_separately() -> None:
    indicators = {
        "tcp.analysis.retransmission": "1",
        "tcp.analysis.duplicate_ack": "1",
        "tcp.analysis.out_of_order": "0",
    }
    result = _collect([_row(indicators=indicators, initial_rtt="0.025")])
    conversation = result.conversations[0]
    counts = _symptom_counts(conversation)

    assert counts["retransmission"] == 1
    assert counts["duplicate_ack"] == 1
    assert counts["out_of_order"] == 0
    assert conversation.initial_rtt_seconds == 0.025


def test_retransmission_subtype_increments_aggregate_once() -> None:
    result = _collect(
        [
            _row(
                indicators={
                    "tcp.analysis.fast_retransmission": "1",
                    "tcp.analysis.spurious_retransmission": "1",
                }
            )
        ]
    )
    counts = _symptom_counts(result.conversations[0])

    assert counts["retransmission"] == 1
    assert counts["fast_retransmission"] == 1
    assert counts["spurious_retransmission"] == 1


def test_strict_boolean_parsing_rejects_required_and_warns_for_optional() -> None:
    with pytest.raises(tshark.TsharkOutputError, match="tcp.flags.syn"):
        _collect([_row(syn="true")])

    result = _collect(
        [
            _row(
                indicators={"tcp.analysis.retransmission": "true"},
            )
        ]
    )
    assert result.malformed_optional_fields == 1
    assert result.total_parser_warnings == 1
    assert _symptom_counts(result.conversations[0])["retransmission"] == 0


@pytest.mark.parametrize(
    ("field_name", "value"),
    [
        ("frame.number", "0"),
        ("frame.time_epoch", "not-a-time"),
        ("tcp.len", "-1"),
        ("tcp.flags", "invalid"),
    ],
)
def test_malformed_required_values_fail(field_name: str, value: str) -> None:
    projection = tcp_conversations._build_projection(
        frozenset(tcp_conversations._ALL_FIELDS)
    )
    base = _row()
    columns = base.rstrip("\n").split("\t")
    columns[projection.indices[field_name]] = value

    with pytest.raises(tshark.TsharkOutputError):
        _collect(["\t".join(columns) + "\n"])


def test_missing_identity_is_counted_without_synthetic_values() -> None:
    result = _collect([_row(ip_source="", source_port="")])

    assert result.conversations == ()
    assert result.unusable_tcp_rows == 1
    assert result.total_parser_warnings == 1


def test_optional_values_remain_absent_and_malformed_values_warn() -> None:
    result = _collect(
        [
            _row(
                captured_length="",
                original_length="invalid",
                sequence_number="",
                window_value="70000",
            )
        ]
    )
    evidence = result.conversations[0].a_to_b

    assert evidence.captured_bytes == 0
    assert evidence.original_frame_bytes == 0
    assert evidence.minimum_window_value is None
    assert result.malformed_optional_fields == 2
    assert result.conversations[0].optional_parse_errors == 2


def test_timestamp_regression_is_counted_without_reordering() -> None:
    result = _collect(
        [
            _row(frame_number=1, timestamp="100.0"),
            _row(frame_number=2, timestamp="99.0"),
        ]
    )

    assert result.timestamp_regressions == 1
    assert result.conversations[0].first_frame == 1
    assert result.conversations[0].last_frame == 2


def test_interfaces_are_deduplicated_and_deterministically_sorted() -> None:
    result = _collect(
        [
            _row(frame_number=1, interface_id="10"),
            _row(frame_number=2, interface_id="2"),
            _row(frame_number=3, interface_id="alpha"),
        ]
    )

    assert result.interfaces == ("2", "10", "alpha")
    assert result.conversations[0].interfaces == ("2", "10", "alpha")


def test_evidence_sampling_keeps_first_four_and_most_recent_four() -> None:
    rows = [
        _row(
            frame_number=index,
            syn="1",
            ack="0",
            flags="0x0002",
            sequence_number="100",
        )
        for index in range(1, 11)
    ]

    frames = _event_frames(_collect(rows).conversations[0], "syn")

    assert frames == (1, 2, 3, 4, 7, 8, 9, 10)


def test_warning_retention_is_bounded_but_total_continues() -> None:
    rows = [
        _row(frame_number=index, original_length="invalid") for index in range(1, 106)
    ]

    result = _collect(rows)

    assert len(result.parser_warnings) == 100
    assert result.total_parser_warnings == 105
    assert result.malformed_optional_fields == 105


def test_production_collection_limits_match_the_specification() -> None:
    assert tcp_conversations.MAX_TRACKED_CONVERSATIONS == 50_000
    assert tcp_conversations.MAX_REPRESENTATIVE_FRAMES == 8
    assert tcp_conversations.MAX_RETAINED_WARNINGS == 100


def test_conversation_cap_has_no_eviction_and_existing_state_continues(
    monkeypatch: MonkeyPatch,
) -> None:
    monkeypatch.setattr(tcp_conversations, "MAX_TRACKED_CONVERSATIONS", 2)
    rows = [
        _row(frame_number=1, stream_id="1"),
        _row(
            frame_number=2,
            stream_id="2",
            ip_source="192.0.2.11",
        ),
        _row(
            frame_number=3,
            stream_id="3",
            ip_source="192.0.2.12",
        ),
        _row(frame_number=4, stream_id="1", payload_length="10"),
    ]

    result = _collect(rows)

    assert len(result.conversations) == 2
    assert not result.conversation_tracking_complete
    assert result.untracked_conversation_rows == 1
    assert result.usable_tcp_rows == 4
    assert result.conversations[0].a_to_b.packets == 2
    assert result.conversations[0].a_to_b.payload_bytes == 10
    assert "TCP_FLOW_TRACKING_LIMIT_REACHED" in result.collection_codes


def test_lazy_row_source_is_consumed_once() -> None:
    class OnePass:
        def __init__(self) -> None:
            self.iterations = 0

        def __iter__(self) -> Iterator[str]:
            self.iterations += 1
            if self.iterations > 1:
                raise AssertionError("row source iterated more than once")
            yield _row()

    rows = OnePass()
    result = _collect(rows)

    assert result.rows_processed == 1
    assert rows.iterations == 1


def test_required_field_capability_is_enforced() -> None:
    supported = frozenset(tcp_conversations._ALL_FIELDS) - {"tcp.flags.syn"}

    with pytest.raises(tshark.TsharkOutputError, match="tcp.flags.syn"):
        tcp_conversations._build_projection(supported)


def test_optional_capabilities_disable_only_dependent_fields() -> None:
    supported = frozenset(tcp_conversations._REQUIRED_FIELDS)
    result = _collect([_row(supported_fields=supported)], supported_fields=supported)

    assert len(result.conversations) == 1
    assert result.capabilities.supported_derived == ()
    assert "retransmission" in result.capabilities.unsupported_derived
    assert result.conversations[0].initial_rtt_seconds is None


def test_public_collector_reuses_safe_tshark_boundaries(
    monkeypatch: MonkeyPatch,
    tmp_path: Path,
) -> None:
    capture = tmp_path / "synthetic.pcapng"
    capture.touch()
    calls: dict[str, object] = {}

    monkeypatch.setattr(
        tcp_conversations,
        "find_tshark",
        lambda: "/usr/bin/tshark",
    )
    monkeypatch.setattr(
        tcp_conversations,
        "get_tshark_field_capabilities",
        lambda executable, timeout, fields: (
            calls.update(
                executable=executable,
                timeout=timeout,
                capability_fields=tuple(fields),
            )
            or frozenset(tcp_conversations._ALL_FIELDS)
        ),
    )

    def fake_stream(
        executable: str,
        capture_path: Path,
        fields: tuple[str, ...],
        timeout: float,
        consume_rows: Callable[
            [Iterable[str]],
            tcp_conversations.TCPConversationCollection,
        ],
        *,
        operation: str,
        display_filter: str | None = None,
    ) -> tcp_conversations.TCPConversationCollection:
        calls.update(
            stream_executable=executable,
            capture_path=capture_path,
            fields=fields,
            timeout=timeout,
            operation=operation,
            display_filter=display_filter,
        )
        return consume_rows(iter(()))

    monkeypatch.setattr(tcp_conversations, "stream_tshark_fields", fake_stream)

    result = tcp_conversations.collect_tcp_conversation_evidence(
        capture,
        timeout_seconds=5.0,
    )

    assert result.conversations == ()
    assert calls["stream_executable"] == "/usr/bin/tshark"
    assert calls["capture_path"] == capture.resolve()
    assert calls["display_filter"] == "tcp"
    assert calls["timeout"] == 5.0
    requested_fields = cast(tuple[str, ...], calls["fields"])
    assert "tcp.payload" not in requested_fields
    assert "data.data" not in requested_fields


@pytest.mark.parametrize("timeout", [0.0, -1.0, True])
def test_public_collector_validates_timeout(
    timeout: float,
    tmp_path: Path,
) -> None:
    capture = tmp_path / "synthetic.pcapng"
    capture.touch()

    with pytest.raises(ValueError, match="greater than zero"):
        tcp_conversations.collect_tcp_conversation_evidence(
            capture,
            timeout_seconds=timeout,
        )
