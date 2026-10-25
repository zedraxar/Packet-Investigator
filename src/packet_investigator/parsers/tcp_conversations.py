"""Streaming, bounded collection of normalized TCP conversation evidence."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Literal

from packet_investigator.models.tcp_conversations import (
    Endpoint,
    TCPConversationIdentity,
    TCPDirection,
    TCPGroupingBasis,
)
from packet_investigator.parsers.tshark import (
    DEFAULT_TIMEOUT_SECONDS,
    TsharkOutputError,
    find_tshark,
    get_tshark_field_capabilities,
    stream_tshark_fields,
    validate_capture_path,
)

MAX_TRACKED_CONVERSATIONS = 50_000
MAX_REPRESENTATIVE_FRAMES = 8
MAX_RETAINED_WARNINGS = 100
_FIRST_REPRESENTATIVE_FRAMES = 4
_RECENT_REPRESENTATIVE_FRAMES = MAX_REPRESENTATIVE_FRAMES - _FIRST_REPRESENTATIVE_FRAMES

_REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.protocols",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.len",
    "tcp.flags",
    "tcp.flags.syn",
    "tcp.flags.ack",
    "tcp.flags.fin",
    "tcp.flags.reset",
)
_OPTIONAL_RAW_FIELDS = (
    "frame.interface_id",
    "frame.cap_len",
    "frame.len",
    "tcp.seq_raw",
    "tcp.ack_raw",
    "tcp.hdr_len",
    "tcp.window_size_value",
)
_DERIVED_FIELDS = {
    "tcp.stream": "stream_identity",
    "tcp.window_size": "effective_window",
    "tcp.analysis.retransmission": "retransmission",
    "tcp.analysis.fast_retransmission": "fast_retransmission",
    "tcp.analysis.spurious_retransmission": "spurious_retransmission",
    "tcp.analysis.lost_segment": "lost_segment",
    "tcp.analysis.duplicate_ack": "duplicate_ack",
    "tcp.analysis.out_of_order": "out_of_order",
    "tcp.analysis.zero_window": "zero_window",
    "tcp.analysis.window_full": "window_full",
    "tcp.analysis.keep_alive": "keepalive",
    "tcp.analysis.keep_alive_ack": "keepalive_ack",
    "tcp.analysis.ack_lost_segment": "ack_lost_segment",
    "tcp.analysis.initial_rtt": "initial_rtt",
}
_ALL_FIELDS = (*_REQUIRED_FIELDS, *_OPTIONAL_RAW_FIELDS, *_DERIVED_FIELDS)
_UINT32_MAX = (1 << 32) - 1
_IPV6_EXTENSION_PROTOCOLS = {
    "ipv6.hopopts",
    "ipv6.routing",
    "ipv6.fraghdr",
    "ipv6.dstopts",
    "ipv6.shim6",
    "ipv6.ah",
}
_SYMPTOM_FIELDS = {
    "tcp.analysis.retransmission": "retransmission",
    "tcp.analysis.fast_retransmission": "fast_retransmission",
    "tcp.analysis.spurious_retransmission": "spurious_retransmission",
    "tcp.analysis.lost_segment": "lost_segment",
    "tcp.analysis.ack_lost_segment": "ack_lost_segment",
    "tcp.analysis.duplicate_ack": "duplicate_ack",
    "tcp.analysis.out_of_order": "out_of_order",
    "tcp.analysis.zero_window": "zero_window",
    "tcp.analysis.window_full": "window_full",
    "tcp.analysis.keep_alive": "keepalive",
    "tcp.analysis.keep_alive_ack": "keepalive_ack",
}
_EVENT_CATEGORIES = (
    "syn",
    "syn_ack",
    "ack",
    "fin",
    "fin_ack_a_to_b",
    "fin_ack_b_to_a",
    "reset",
    "raw_zero_window",
)


@dataclass(frozen=True, slots=True)
class TCPParserWarning:
    """One bounded, privacy-safe optional-field parsing warning."""

    row_number: int
    reason_code: str
    field_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TCPFieldCapabilities:
    """Packet Investigator capability identifiers for one collection run."""

    supported_derived: tuple[str, ...]
    unsupported_derived: tuple[str, ...]
    supported_optional_raw: tuple[str, ...]
    unsupported_optional_raw: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TCPFlagObservation:
    """Bounded raw TCP flag and sequence evidence from one frame."""

    frame_number: int
    timestamp: datetime
    direction: TCPDirection
    sequence_number: int | None
    acknowledgment_number: int | None
    payload_length: int
    syn: bool
    ack: bool
    fin: bool
    reset: bool


@dataclass(frozen=True, slots=True)
class TCPDirectionalEvidence:
    """Mechanically aggregated raw evidence for one canonical direction."""

    direction: TCPDirection
    packets: int
    captured_bytes: int
    original_frame_bytes: int
    payload_bytes: int
    first_frame: int | None
    last_frame: int | None
    first_timestamp: datetime | None
    last_timestamp: datetime | None
    first_payload_frame: int | None
    first_payload_timestamp: datetime | None
    minimum_window_value: int | None
    maximum_window_value: int | None
    minimum_effective_window: int | None
    maximum_effective_window: int | None


@dataclass(frozen=True, slots=True)
class TCPSymptomEvidence:
    """Counts and bounded frames for normalized TShark-derived indicators."""

    counts: tuple[tuple[str, int], ...]
    representative_frames: tuple[tuple[str, tuple[int, ...]], ...]


@dataclass(frozen=True, slots=True)
class TCPCollectedConversation:
    """Immutable parser-neutral evidence for one tracked tuple epoch."""

    identity: TCPConversationIdentity
    first_frame: int
    last_frame: int
    first_timestamp: datetime
    last_timestamp: datetime
    first_observed_direction: TCPDirection
    interfaces: tuple[str, ...]
    a_to_b: TCPDirectionalEvidence
    b_to_a: TCPDirectionalEvidence
    initial_syn_observation: TCPFlagObservation | None
    syn_acknowledging_initial_syn: TCPFlagObservation | None
    acknowledgment_of_initial_syn_ack: TCPFlagObservation | None
    opposite_syn_before_syn_ack: bool
    conflicting_syn_ack_signature_observed: bool
    repeated_initial_syn_observations: int
    repeated_matching_syn_ack_observations: int
    flag_counts: tuple[tuple[str, int], ...]
    flag_observations: tuple[tuple[str, tuple[TCPFlagObservation, ...]], ...]
    symptom_evidence: TCPSymptomEvidence
    initial_rtt_seconds: float | None
    optional_parse_errors: int
    collection_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TCPConversationCollection:
    """Immutable bounded result of one streamed TCP evidence pass."""

    conversations: tuple[TCPCollectedConversation, ...]
    rows_processed: int
    usable_tcp_rows: int
    unusable_tcp_rows: int
    malformed_optional_fields: int
    tracked_conversation_limit: int
    conversation_tracking_complete: bool
    untracked_conversation_rows: int
    stream_tuple_conflicts: int
    ambiguous_encapsulation_rows: int
    timestamp_regressions: int
    interfaces: tuple[str, ...]
    capabilities: TCPFieldCapabilities
    parser_warnings: tuple[TCPParserWarning, ...]
    total_parser_warnings: int
    collection_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Projection:
    fields: tuple[str, ...]
    indices: dict[str, int]
    capabilities: TCPFieldCapabilities


@dataclass(frozen=True, slots=True)
class _TupleKey:
    ip_version: Literal[4, 6]
    address_a: IPv4Address | IPv6Address
    port_a: int
    address_b: IPv4Address | IPv6Address
    port_b: int


@dataclass(frozen=True, slots=True)
class _NormalizedRow:
    frame_number: int
    timestamp: datetime
    interface_id: str | None
    tuple_key: _TupleKey
    direction: TCPDirection
    stream_id: int | None
    captured_length: int | None
    original_length: int | None
    payload_length: int
    header_length: int | None
    sequence_number: int | None
    acknowledgment_number: int | None
    window_value: int | None
    effective_window: int | None
    flags_value: int
    syn: bool
    ack: bool
    fin: bool
    reset: bool
    indicators: tuple[str, ...]
    initial_rtt_seconds: float | None
    optional_errors: tuple[str, ...]


class _FrameSample:
    """Keep first four and most recent four unique frames."""

    __slots__ = ("_first", "_recent")

    def __init__(self) -> None:
        self._first: list[int] = []
        self._recent: deque[int] = deque(maxlen=_RECENT_REPRESENTATIVE_FRAMES)

    def add(self, frame_number: int) -> None:
        if frame_number in self._first or frame_number in self._recent:
            return
        if len(self._first) < _FIRST_REPRESENTATIVE_FRAMES:
            self._first.append(frame_number)
        else:
            self._recent.append(frame_number)

    def finish(self) -> tuple[int, ...]:
        return tuple(sorted((*self._first, *self._recent)))


@dataclass(slots=True)
class _DirectionalState:
    packets: int = 0
    captured_bytes: int = 0
    original_frame_bytes: int = 0
    payload_bytes: int = 0
    first_frame: int | None = None
    last_frame: int | None = None
    first_timestamp: datetime | None = None
    last_timestamp: datetime | None = None
    first_payload_frame: int | None = None
    first_payload_timestamp: datetime | None = None
    minimum_window_value: int | None = None
    maximum_window_value: int | None = None
    minimum_effective_window: int | None = None
    maximum_effective_window: int | None = None

    def update(self, row: _NormalizedRow) -> None:
        self.packets += 1
        self.captured_bytes += row.captured_length or 0
        self.original_frame_bytes += row.original_length or 0
        self.payload_bytes += row.payload_length
        if self.first_frame is None:
            self.first_frame = row.frame_number
            self.first_timestamp = row.timestamp
        self.last_frame = row.frame_number
        self.last_timestamp = row.timestamp
        if row.payload_length > 0 and self.first_payload_frame is None:
            self.first_payload_frame = row.frame_number
            self.first_payload_timestamp = row.timestamp
        self.minimum_window_value = _minimum(
            self.minimum_window_value,
            row.window_value,
        )
        self.maximum_window_value = _maximum(
            self.maximum_window_value,
            row.window_value,
        )
        self.minimum_effective_window = _minimum(
            self.minimum_effective_window,
            row.effective_window,
        )
        self.maximum_effective_window = _maximum(
            self.maximum_effective_window,
            row.effective_window,
        )


@dataclass(slots=True)
class _ConversationState:
    tuple_key: _TupleKey
    grouping_basis: TCPGroupingBasis
    stream_id: int | None
    creation_index: int
    first_frame: int
    last_frame: int
    first_timestamp: datetime
    last_timestamp: datetime
    first_observed_direction: TCPDirection
    a_to_b: _DirectionalState = field(default_factory=_DirectionalState)
    b_to_a: _DirectionalState = field(default_factory=_DirectionalState)
    interfaces: set[str] = field(default_factory=set)
    event_samples: dict[str, _FrameSample] = field(default_factory=dict)
    event_rows: dict[str, dict[int, TCPFlagObservation]] = field(default_factory=dict)
    event_counts: dict[str, int] = field(default_factory=dict)
    symptom_counts: dict[str, int] = field(default_factory=dict)
    symptom_samples: dict[str, _FrameSample] = field(default_factory=dict)
    initial_rtt_seconds: float | None = None
    initial_rtt_inconsistent: bool = False
    optional_parse_errors: int = 0
    collection_codes: set[str] = field(default_factory=set)
    first_syn_sequence: int | None = None
    first_syn_direction: TCPDirection | None = None
    initial_syn_observation: TCPFlagObservation | None = None
    syn_acknowledging_initial_syn: TCPFlagObservation | None = None
    acknowledgment_of_initial_syn_ack: TCPFlagObservation | None = None
    opposite_syn_before_syn_ack: bool = False
    conflicting_syn_ack_signature_observed: bool = False
    repeated_initial_syn_observations: int = 0
    matching_syn_ack_sequence: int | None = None
    matching_syn_ack_direction: TCPDirection | None = None
    repeated_matching_syn_ack_observations: int = 0
    matching_final_ack_seen: bool = False
    fin_directions: set[TCPDirection] = field(default_factory=set)
    fin_expected_ack: dict[TCPDirection, int] = field(default_factory=dict)
    reset_observed: bool = False

    def __post_init__(self) -> None:
        self.event_samples = {name: _FrameSample() for name in _EVENT_CATEGORIES}
        self.event_rows = {name: {} for name in _EVENT_CATEGORIES}
        self.event_counts = dict.fromkeys(_EVENT_CATEGORIES, 0)
        self.symptom_counts = {name: 0 for name in _SYMPTOM_FIELDS.values()}
        self.symptom_samples = {
            name: _FrameSample() for name in _SYMPTOM_FIELDS.values()
        }

    @property
    def terminal(self) -> bool:
        return self.reset_observed or self.fin_directions == {
            TCPDirection.A_TO_B,
            TCPDirection.B_TO_A,
        }

    def add(self, row: _NormalizedRow) -> None:
        self.last_frame = row.frame_number
        self.last_timestamp = row.timestamp
        if row.interface_id is not None:
            self.interfaces.add(row.interface_id)
        directional = (
            self.a_to_b if row.direction is TCPDirection.A_TO_B else self.b_to_a
        )
        directional.update(row)
        self.optional_parse_errors += len(row.optional_errors)

        observation = TCPFlagObservation(
            frame_number=row.frame_number,
            timestamp=row.timestamp,
            direction=row.direction,
            sequence_number=row.sequence_number,
            acknowledgment_number=row.acknowledgment_number,
            payload_length=row.payload_length,
            syn=row.syn,
            ack=row.ack,
            fin=row.fin,
            reset=row.reset,
        )
        self._track_opening_sequence_evidence(row, observation)
        categories: list[str] = []
        if row.ack and row.acknowledgment_number is not None:
            acknowledged_fin_direction = _opposite_direction(row.direction)
            if (
                self.fin_expected_ack.get(acknowledged_fin_direction)
                == row.acknowledgment_number
            ):
                categories.append(
                    "fin_ack_a_to_b"
                    if acknowledged_fin_direction is TCPDirection.A_TO_B
                    else "fin_ack_b_to_a"
                )
        if row.syn and row.ack:
            categories.append("syn_ack")
        elif row.syn:
            categories.append("syn")
            if self.initial_syn_observation is None:
                self.first_syn_sequence = row.sequence_number
                self.first_syn_direction = row.direction
                self.initial_syn_observation = observation
        elif row.ack:
            categories.append("ack")
        if row.fin:
            categories.append("fin")
            self.fin_directions.add(row.direction)
            if row.sequence_number is not None:
                self.fin_expected_ack[row.direction] = (
                    row.sequence_number + row.payload_length + 1
                ) & _UINT32_MAX
        if row.reset:
            categories.append("reset")
            self.reset_observed = True
        if row.window_value == 0:
            categories.append("raw_zero_window")
        for category in categories:
            self._add_event(category, observation)

        for indicator in row.indicators:
            self.symptom_counts[indicator] += 1
            self.symptom_samples[indicator].add(row.frame_number)
        if row.initial_rtt_seconds is not None and not self.initial_rtt_inconsistent:
            if self.initial_rtt_seconds is None:
                self.initial_rtt_seconds = row.initial_rtt_seconds
            elif self.initial_rtt_seconds != row.initial_rtt_seconds:
                self.initial_rtt_seconds = None
                self.initial_rtt_inconsistent = True
                self.collection_codes.add("TCP_TIMING_INTERPRETATION_LIMITED")

    def _track_opening_sequence_evidence(
        self,
        row: _NormalizedRow,
        observation: TCPFlagObservation,
    ) -> None:
        # These are exact ordered signature repetitions, not retry findings.
        # The analyzer owns retry qualification, wording, and suppression.
        if row.syn and not row.ack:
            if self.first_syn_direction is None:
                return
            if (
                self.matching_syn_ack_sequence is None
                and row.direction is _opposite_direction(self.first_syn_direction)
            ):
                self.opposite_syn_before_syn_ack = True
                return
            if (
                not self.terminal
                and self.matching_syn_ack_sequence is None
                and row.direction is self.first_syn_direction
                and row.sequence_number is not None
                and row.sequence_number == self.first_syn_sequence
            ):
                self.repeated_initial_syn_observations += 1
            return
        if row.syn and row.ack:
            if (
                self.first_syn_direction is None
                or self.first_syn_sequence is None
                or row.direction is not _opposite_direction(self.first_syn_direction)
                or not _ack_matches_sequence(
                    row.acknowledgment_number,
                    self.first_syn_sequence,
                )
            ):
                return
            if self.matching_syn_ack_sequence is None:
                self.matching_syn_ack_sequence = row.sequence_number
                self.matching_syn_ack_direction = row.direction
                self.syn_acknowledging_initial_syn = observation
            elif (
                not self.matching_final_ack_seen
                and row.sequence_number == self.matching_syn_ack_sequence
            ):
                self.repeated_matching_syn_ack_observations += 1
            elif not self.matching_final_ack_seen:
                self.conflicting_syn_ack_signature_observed = True
            return
        if (
            row.ack
            and self.matching_syn_ack_sequence is not None
            and self.matching_syn_ack_direction is not None
            and row.direction is _opposite_direction(self.matching_syn_ack_direction)
            and _ack_matches_sequence(
                row.acknowledgment_number,
                self.matching_syn_ack_sequence,
            )
        ):
            self.matching_final_ack_seen = True
            if self.acknowledgment_of_initial_syn_ack is None:
                self.acknowledgment_of_initial_syn_ack = observation

    def _add_event(self, category: str, observation: TCPFlagObservation) -> None:
        self.event_counts[category] += 1
        sample = self.event_samples[category]
        sample.add(observation.frame_number)
        rows = self.event_rows[category]
        rows[observation.frame_number] = observation
        retained = set(sample.finish())
        for frame_number in tuple(rows):
            if frame_number not in retained:
                del rows[frame_number]


class _TCPAccumulator:
    """Mutable bounded state for a single pass over normalized field rows."""

    def __init__(self, projection: _Projection) -> None:
        self._projection = projection
        self._groups: list[_ConversationState] = []
        self._stream_groups: dict[tuple[int, _TupleKey], _ConversationState] = {}
        self._stream_tuples: dict[int, set[_TupleKey]] = {}
        self._tuple_groups: dict[_TupleKey, list[_ConversationState]] = {}
        self._rows_processed = 0
        self._usable_tcp_rows = 0
        self._unusable_tcp_rows = 0
        self._malformed_optional_fields = 0
        self._untracked_conversation_rows = 0
        self._stream_tuple_conflicts = 0
        self._ambiguous_encapsulation_rows = 0
        self._timestamp_regressions = 0
        self._previous_timestamp: datetime | None = None
        self._interfaces: set[str] = set()
        self._warnings: list[TCPParserWarning] = []
        self._total_warnings = 0
        self._collection_codes: set[str] = set()
        self._tracking_complete = True

    def consume(self, rows: Iterable[str]) -> TCPConversationCollection:
        """Consume a row iterator once and finalize immutable evidence."""
        for row_number, line in enumerate(rows, start=1):
            if not line.rstrip("\r\n"):
                continue
            self._rows_processed += 1
            columns = line.rstrip("\r\n").split("\t")
            if len(columns) != len(self._projection.fields):
                raise TsharkOutputError(
                    f"Unexpected TShark output at row {row_number}: "
                    f"expected {len(self._projection.fields)} fields, "
                    f"received {len(columns)}."
                )
            row = self._normalize_row(columns, row_number)
            if row is None:
                continue
            self._consume_normalized(row)
        return self._finish()

    def _normalize_row(
        self,
        columns: list[str],
        row_number: int,
    ) -> _NormalizedRow | None:
        def value(name: str) -> str:
            index = self._projection.indices.get(name)
            return "" if index is None else columns[index]

        frame_number = _parse_required_int(
            value("frame.number"),
            row_number,
            "frame.number",
            minimum=1,
        )
        timestamp = _parse_required_timestamp(value("frame.time_epoch"), row_number)
        self._track_timestamp(timestamp)
        interface_id = value("frame.interface_id") or None
        if interface_id is not None:
            self._interfaces.add(interface_id)

        protocols = tuple(
            protocol.lower()
            for protocol in value("frame.protocols").split(":")
            if protocol
        )
        identity = _parse_identity(value, protocols)
        if identity is None:
            self._unusable_tcp_rows += 1
            if _has_ambiguous_encapsulation(protocols):
                self._ambiguous_encapsulation_rows += 1
                self._collection_codes.add("TCP_ENCAPSULATED_IDENTITY_UNSUPPORTED")
            else:
                self._warn(row_number, "TCP_IDENTITY_UNUSABLE", ("identity",))
            return None
        tuple_key, direction = identity

        optional_errors: list[str] = []

        def optional_int(
            name: str,
            *,
            minimum: int = 0,
            maximum: int | None = None,
        ) -> int | None:
            parsed, malformed = _parse_optional_int(
                value(name),
                minimum=minimum,
                maximum=maximum,
            )
            if malformed:
                optional_errors.append(name)
                self._optional_warning(row_number, name)
            return parsed

        stream_id = optional_int("tcp.stream")
        captured_length = optional_int("frame.cap_len")
        original_length = optional_int("frame.len")
        sequence_number = optional_int("tcp.seq_raw", maximum=_UINT32_MAX)
        acknowledgment_number = optional_int("tcp.ack_raw", maximum=_UINT32_MAX)
        header_length = optional_int("tcp.hdr_len")
        window_value = optional_int("tcp.window_size_value", maximum=65_535)
        effective_window = optional_int("tcp.window_size")
        initial_rtt = _parse_optional_float(value("tcp.analysis.initial_rtt"))
        if initial_rtt[1]:
            optional_errors.append("tcp.analysis.initial_rtt")
            self._optional_warning(row_number, "tcp.analysis.initial_rtt")

        payload_length = _parse_required_int(
            value("tcp.len"),
            row_number,
            "tcp.len",
            minimum=0,
        )
        flags_value = _parse_required_flags(value("tcp.flags"), row_number)
        syn = _parse_required_bool(value("tcp.flags.syn"), row_number, "tcp.flags.syn")
        ack = _parse_required_bool(value("tcp.flags.ack"), row_number, "tcp.flags.ack")
        fin = _parse_required_bool(value("tcp.flags.fin"), row_number, "tcp.flags.fin")
        reset = _parse_required_bool(
            value("tcp.flags.reset"),
            row_number,
            "tcp.flags.reset",
        )
        _validate_flag_consistency(
            flags_value,
            syn=syn,
            ack=ack,
            fin=fin,
            reset=reset,
            row_number=row_number,
        )

        indicators: list[str] = []
        for field_name, capability in _SYMPTOM_FIELDS.items():
            indicator, malformed = _parse_optional_bool(value(field_name))
            if malformed:
                optional_errors.append(field_name)
                self._optional_warning(row_number, field_name)
            elif indicator:
                indicators.append(capability)
        if (
            "fast_retransmission" in indicators
            or "spurious_retransmission" in indicators
        ) and "retransmission" not in indicators:
            indicators.insert(0, "retransmission")

        return _NormalizedRow(
            frame_number=frame_number,
            timestamp=timestamp,
            interface_id=interface_id,
            tuple_key=tuple_key,
            direction=direction,
            stream_id=stream_id,
            captured_length=captured_length,
            original_length=original_length,
            payload_length=payload_length,
            header_length=header_length,
            sequence_number=sequence_number,
            acknowledgment_number=acknowledgment_number,
            window_value=window_value,
            effective_window=effective_window,
            flags_value=flags_value,
            syn=syn,
            ack=ack,
            fin=fin,
            reset=reset,
            indicators=tuple(indicators),
            initial_rtt_seconds=initial_rtt[0],
            optional_errors=tuple(optional_errors),
        )

    def _consume_normalized(self, row: _NormalizedRow) -> None:
        unusable_before = self._unusable_tcp_rows
        state = self._locate_group(row)
        if state is None:
            self._untracked_conversation_rows += 1
            if self._unusable_tcp_rows == unusable_before:
                self._usable_tcp_rows += 1
            return
        self._usable_tcp_rows += 1
        state.add(row)

    def _locate_group(self, row: _NormalizedRow) -> _ConversationState | None:
        if row.stream_id is not None:
            group = self._stream_groups.get((row.stream_id, row.tuple_key))
            if group is not None:
                return group

            seen_tuples = self._stream_tuples.get(row.stream_id, set())
            stream_conflict = bool(seen_tuples and row.tuple_key not in seen_tuples)
            if stream_conflict:
                self._stream_tuple_conflicts += 1
                self._collection_codes.add("TCP_STREAM_IDENTITY_CONFLICT")
                for (stream_id, _tuple_key), affected in self._stream_groups.items():
                    if stream_id == row.stream_id:
                        affected.collection_codes.add("TCP_STREAM_IDENTITY_CONFLICT")

            fallback = self._unique_active_fallback(row.tuple_key)
            if fallback is not None:
                if stream_conflict:
                    fallback.collection_codes.add("TCP_STREAM_IDENTITY_CONFLICT")
                self._stream_tuples.setdefault(row.stream_id, set()).add(row.tuple_key)
                fallback.stream_id = row.stream_id
                fallback.grouping_basis = TCPGroupingBasis.STREAM_AND_TUPLE
                self._stream_groups[(row.stream_id, row.tuple_key)] = fallback
                return fallback
            if len(self._groups) >= MAX_TRACKED_CONVERSATIONS:
                self._tracking_complete = False
                self._collection_codes.add("TCP_FLOW_TRACKING_LIMIT_REACHED")
                return None
            self._stream_tuples.setdefault(row.stream_id, set()).add(row.tuple_key)
            group = self._register(row, TCPGroupingBasis.STREAM_AND_TUPLE)
            if stream_conflict and group is not None:
                group.collection_codes.add("TCP_STREAM_IDENTITY_CONFLICT")
            return group

        candidates = [
            group
            for group in self._tuple_groups.get(row.tuple_key, ())
            if not group.terminal
        ]
        if len(candidates) == 1:
            group = candidates[0]
            if self._requires_new_fallback_epoch(group, row):
                group.collection_codes.add("TCP_TUPLE_REUSE_AMBIGUOUS")
                new_group = self._register(row, TCPGroupingBasis.TUPLE_EPOCH)
                if new_group is not None:
                    new_group.collection_codes.add("TCP_TUPLE_REUSE_AMBIGUOUS")
                return new_group
            return group
        if not candidates:
            return self._register(row, TCPGroupingBasis.TUPLE_EPOCH)

        self._unusable_tcp_rows += 1
        self._collection_codes.add("TCP_TUPLE_REUSE_AMBIGUOUS")
        for group in candidates:
            group.collection_codes.add("TCP_TUPLE_REUSE_AMBIGUOUS")
        return None

    def _unique_active_fallback(
        self,
        tuple_key: _TupleKey,
    ) -> _ConversationState | None:
        candidates = [
            group
            for group in self._tuple_groups.get(tuple_key, ())
            if group.stream_id is None and not group.terminal
        ]
        return candidates[0] if len(candidates) == 1 else None

    def _requires_new_fallback_epoch(
        self,
        group: _ConversationState,
        row: _NormalizedRow,
    ) -> bool:
        if not row.syn or row.ack:
            return False
        if group.initial_syn_observation is None:
            return True
        return (
            group.first_syn_sequence is not None
            and row.sequence_number is not None
            and row.sequence_number != group.first_syn_sequence
        )

    def _register(
        self,
        row: _NormalizedRow,
        grouping_basis: TCPGroupingBasis,
    ) -> _ConversationState | None:
        if len(self._groups) >= MAX_TRACKED_CONVERSATIONS:
            self._tracking_complete = False
            self._collection_codes.add("TCP_FLOW_TRACKING_LIMIT_REACHED")
            return None
        state = _ConversationState(
            tuple_key=row.tuple_key,
            grouping_basis=grouping_basis,
            stream_id=row.stream_id,
            creation_index=len(self._groups),
            first_frame=row.frame_number,
            last_frame=row.frame_number,
            first_timestamp=row.timestamp,
            last_timestamp=row.timestamp,
            first_observed_direction=row.direction,
        )
        self._groups.append(state)
        self._tuple_groups.setdefault(row.tuple_key, []).append(state)
        if row.stream_id is not None:
            self._stream_groups[(row.stream_id, row.tuple_key)] = state
        return state

    def _track_timestamp(self, timestamp: datetime) -> None:
        if (
            self._previous_timestamp is not None
            and timestamp < self._previous_timestamp
        ):
            self._timestamp_regressions += 1
        self._previous_timestamp = timestamp

    def _optional_warning(self, row_number: int, field_name: str) -> None:
        self._malformed_optional_fields += 1
        self._warn(row_number, "TCP_OPTIONAL_FIELD_MALFORMED", (field_name,))

    def _warn(
        self,
        row_number: int,
        reason_code: str,
        field_names: tuple[str, ...],
    ) -> None:
        self._total_warnings += 1
        if len(self._warnings) < MAX_RETAINED_WARNINGS:
            self._warnings.append(
                TCPParserWarning(
                    row_number=row_number,
                    reason_code=reason_code,
                    field_names=field_names[:2],
                )
            )

    def _finish(self) -> TCPConversationCollection:
        ordered = sorted(
            self._groups,
            key=lambda group: (
                group.first_frame,
                _tuple_sort_key(group.tuple_key),
                group.creation_index,
            ),
        )
        epoch_by_tuple: dict[_TupleKey, int] = {}
        conversations: list[TCPCollectedConversation] = []
        for index, group in enumerate(ordered, start=1):
            epoch = epoch_by_tuple.get(group.tuple_key, 0) + 1
            epoch_by_tuple[group.tuple_key] = epoch
            conversations.append(_freeze_group(group, index, epoch))
        return TCPConversationCollection(
            conversations=tuple(conversations),
            rows_processed=self._rows_processed,
            usable_tcp_rows=self._usable_tcp_rows,
            unusable_tcp_rows=self._unusable_tcp_rows,
            malformed_optional_fields=self._malformed_optional_fields,
            tracked_conversation_limit=MAX_TRACKED_CONVERSATIONS,
            conversation_tracking_complete=self._tracking_complete,
            untracked_conversation_rows=self._untracked_conversation_rows,
            stream_tuple_conflicts=self._stream_tuple_conflicts,
            ambiguous_encapsulation_rows=self._ambiguous_encapsulation_rows,
            timestamp_regressions=self._timestamp_regressions,
            interfaces=tuple(sorted(self._interfaces, key=_interface_sort_key)),
            capabilities=self._projection.capabilities,
            parser_warnings=tuple(self._warnings),
            total_parser_warnings=self._total_warnings,
            collection_codes=tuple(sorted(self._collection_codes)),
        )


def collect_tcp_conversation_evidence(
    capture_path: Path,
    *,
    timeout_seconds: float | None = None,
    tshark_executable: str = "tshark",
) -> TCPConversationCollection:
    """Collect bounded normalized TCP evidence from a validated capture."""
    timeout = DEFAULT_TIMEOUT_SECONDS if timeout_seconds is None else timeout_seconds
    if isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")
    path, _ = validate_capture_path(capture_path)
    executable = find_tshark(tshark_executable)
    supported = get_tshark_field_capabilities(executable, timeout, _ALL_FIELDS)
    projection = _build_projection(supported)
    return stream_tshark_fields(
        executable,
        path,
        projection.fields,
        timeout,
        _TCPAccumulator(projection).consume,
        operation="TCP conversation collection",
        display_filter="tcp",
    )


def _collect_tcp_rows(
    rows: Iterable[str],
    *,
    supported_fields: frozenset[str] | None = None,
) -> TCPConversationCollection:
    """Collect synthetic projected rows without invoking TShark."""
    capabilities = (
        frozenset(_ALL_FIELDS) if supported_fields is None else supported_fields
    )
    projection = _build_projection(capabilities)
    return _TCPAccumulator(projection).consume(rows)


def _build_projection(supported_fields: frozenset[str]) -> _Projection:
    missing_required = set(_REQUIRED_FIELDS) - supported_fields
    if missing_required:
        fields = ", ".join(sorted(missing_required))
        raise TsharkOutputError(f"TShark lacks required TCP fields: {fields}.")
    selected = tuple(field for field in _ALL_FIELDS if field in supported_fields)
    supported_derived = tuple(
        capability
        for field, capability in _DERIVED_FIELDS.items()
        if field in supported_fields
    )
    unsupported_derived = tuple(
        capability
        for field, capability in _DERIVED_FIELDS.items()
        if field not in supported_fields
    )
    supported_optional_raw = tuple(
        field for field in _OPTIONAL_RAW_FIELDS if field in supported_fields
    )
    unsupported_optional_raw = tuple(
        field for field in _OPTIONAL_RAW_FIELDS if field not in supported_fields
    )
    return _Projection(
        fields=selected,
        indices={field: index for index, field in enumerate(selected)},
        capabilities=TCPFieldCapabilities(
            supported_derived=supported_derived,
            unsupported_derived=unsupported_derived,
            supported_optional_raw=supported_optional_raw,
            unsupported_optional_raw=unsupported_optional_raw,
        ),
    )


def _parse_identity(
    value: Callable[[str], str],
    protocols: tuple[str, ...],
) -> tuple[_TupleKey, TCPDirection] | None:
    if _has_ambiguous_encapsulation(protocols):
        return None
    tcp_index = protocols.index("tcp") if "tcp" in protocols else -1
    if tcp_index < 1:
        return None
    ip_protocols = [
        (index, protocol)
        for index, protocol in enumerate(protocols[:tcp_index])
        if protocol in {"ip", "ipv6"}
    ]
    if len(ip_protocols) != 1:
        return None
    ip_index, protocol = ip_protocols[0]
    between = protocols[ip_index + 1 : tcp_index]
    if any(item not in _IPV6_EXTENSION_PROTOCOLS for item in between):
        return None

    if protocol == "ip":
        source_text = value("ip.src")
        destination_text = value("ip.dst")
        expected_version: Literal[4, 6] = 4
    else:
        source_text = value("ipv6.src")
        destination_text = value("ipv6.dst")
        expected_version = 6
    try:
        source = ip_address(source_text)
        destination = ip_address(destination_text)
    except ValueError:
        return None
    if source.version != expected_version or destination.version != expected_version:
        return None
    source_port, source_bad = _parse_optional_int(
        value("tcp.srcport"),
        minimum=0,
        maximum=65_535,
    )
    destination_port, destination_bad = _parse_optional_int(
        value("tcp.dstport"),
        minimum=0,
        maximum=65_535,
    )
    if source_bad or destination_bad or source_port is None or destination_port is None:
        return None
    source_key = (expected_version, source.packed, source_port)
    destination_key = (expected_version, destination.packed, destination_port)
    if source_key == destination_key:
        return None
    if source_key < destination_key:
        return (
            _TupleKey(
                expected_version,
                source,
                source_port,
                destination,
                destination_port,
            ),
            TCPDirection.A_TO_B,
        )
    return (
        _TupleKey(
            expected_version,
            destination,
            destination_port,
            source,
            source_port,
        ),
        TCPDirection.B_TO_A,
    )


def _has_ambiguous_encapsulation(protocols: tuple[str, ...]) -> bool:
    return (
        protocols.count("tcp") != 1
        or sum(protocol in {"ip", "ipv6"} for protocol in protocols) != 1
    )


def _parse_required_int(
    value: str,
    row_number: int,
    field_name: str,
    *,
    minimum: int,
) -> int:
    try:
        parsed = int(value, 10)
    except ValueError as error:
        raise TsharkOutputError(
            f"Invalid required field {field_name} at row {row_number}."
        ) from error
    if parsed < minimum:
        raise TsharkOutputError(
            f"Invalid required field {field_name} at row {row_number}."
        )
    return parsed


def _parse_required_timestamp(value: str, row_number: int) -> datetime:
    try:
        epoch = Decimal(value)
    except InvalidOperation as error:
        raise TsharkOutputError(
            f"Invalid packet timestamp at row {row_number}."
        ) from error
    if not epoch.is_finite():
        raise TsharkOutputError(f"Invalid packet timestamp at row {row_number}.")
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise TsharkOutputError(
            f"Invalid packet timestamp at row {row_number}."
        ) from error


def _parse_optional_int(
    value: str,
    *,
    minimum: int = 0,
    maximum: int | None = None,
) -> tuple[int | None, bool]:
    if value == "":
        return None, False
    try:
        parsed = int(value, 10)
    except ValueError:
        return None, True
    if parsed < minimum or (maximum is not None and parsed > maximum):
        return None, True
    return parsed, False


def _parse_required_flags(value: str, row_number: int) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise TsharkOutputError(
            f"Invalid required field tcp.flags at row {row_number}."
        ) from error
    if parsed < 0 or parsed > 0x1FF:
        raise TsharkOutputError(
            f"Invalid required field tcp.flags at row {row_number}."
        )
    return parsed


def _parse_required_bool(value: str, row_number: int, field_name: str) -> bool:
    if value in {"1", "True"}:
        return True
    if value in {"0", "False"}:
        return False
    raise TsharkOutputError(f"Invalid required field {field_name} at row {row_number}.")


def _validate_flag_consistency(
    flags_value: int,
    *,
    syn: bool,
    ack: bool,
    fin: bool,
    reset: bool,
    row_number: int,
) -> None:
    expected = ((0x02, syn), (0x10, ack), (0x01, fin), (0x04, reset))
    if any(bool(flags_value & bit) is not value for bit, value in expected):
        raise TsharkOutputError(f"Inconsistent required TCP flags at row {row_number}.")


def _parse_optional_bool(value: str) -> tuple[bool | None, bool]:
    if value == "":
        return None, False
    if value in {"1", "True"}:
        return True, False
    if value in {"0", "False"}:
        return False, False
    return None, True


def _parse_optional_float(value: str) -> tuple[float | None, bool]:
    if value == "":
        return None, False
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return None, True
    if not parsed.is_finite() or parsed < 0:
        return None, True
    return float(parsed), False


def _freeze_group(
    group: _ConversationState,
    public_index: int,
    epoch: int,
) -> TCPCollectedConversation:
    endpoint_a = Endpoint(
        ip_version=group.tuple_key.ip_version,
        address=group.tuple_key.address_a,
        port=group.tuple_key.port_a,
    )
    endpoint_b = Endpoint(
        ip_version=group.tuple_key.ip_version,
        address=group.tuple_key.address_b,
        port=group.tuple_key.port_b,
    )
    identity = TCPConversationIdentity(
        conversation_id=f"tcp-{public_index:06d}",
        endpoint_a=endpoint_a,
        endpoint_b=endpoint_b,
        protocol="tcp",
        epoch=epoch,
        grouping_basis=group.grouping_basis,
    )
    return TCPCollectedConversation(
        identity=identity,
        first_frame=group.first_frame,
        last_frame=group.last_frame,
        first_timestamp=group.first_timestamp,
        last_timestamp=group.last_timestamp,
        first_observed_direction=group.first_observed_direction,
        interfaces=tuple(sorted(group.interfaces, key=_interface_sort_key)),
        a_to_b=_freeze_direction(group.a_to_b, TCPDirection.A_TO_B),
        b_to_a=_freeze_direction(group.b_to_a, TCPDirection.B_TO_A),
        initial_syn_observation=group.initial_syn_observation,
        syn_acknowledging_initial_syn=group.syn_acknowledging_initial_syn,
        acknowledgment_of_initial_syn_ack=(group.acknowledgment_of_initial_syn_ack),
        opposite_syn_before_syn_ack=group.opposite_syn_before_syn_ack,
        conflicting_syn_ack_signature_observed=(
            group.conflicting_syn_ack_signature_observed
        ),
        repeated_initial_syn_observations=(group.repeated_initial_syn_observations),
        repeated_matching_syn_ack_observations=(
            group.repeated_matching_syn_ack_observations
        ),
        flag_counts=tuple(
            (category, group.event_counts[category]) for category in _EVENT_CATEGORIES
        ),
        flag_observations=tuple(
            (
                category,
                tuple(
                    group.event_rows[category][frame]
                    for frame in group.event_samples[category].finish()
                ),
            )
            for category in _EVENT_CATEGORIES
        ),
        symptom_evidence=TCPSymptomEvidence(
            counts=tuple(
                (name, group.symptom_counts[name]) for name in _SYMPTOM_FIELDS.values()
            ),
            representative_frames=tuple(
                (name, group.symptom_samples[name].finish())
                for name in _SYMPTOM_FIELDS.values()
            ),
        ),
        initial_rtt_seconds=group.initial_rtt_seconds,
        optional_parse_errors=group.optional_parse_errors,
        collection_codes=tuple(sorted(group.collection_codes)),
    )


def _freeze_direction(
    state: _DirectionalState,
    direction: TCPDirection,
) -> TCPDirectionalEvidence:
    return TCPDirectionalEvidence(
        direction=direction,
        packets=state.packets,
        captured_bytes=state.captured_bytes,
        original_frame_bytes=state.original_frame_bytes,
        payload_bytes=state.payload_bytes,
        first_frame=state.first_frame,
        last_frame=state.last_frame,
        first_timestamp=state.first_timestamp,
        last_timestamp=state.last_timestamp,
        first_payload_frame=state.first_payload_frame,
        first_payload_timestamp=state.first_payload_timestamp,
        minimum_window_value=state.minimum_window_value,
        maximum_window_value=state.maximum_window_value,
        minimum_effective_window=state.minimum_effective_window,
        maximum_effective_window=state.maximum_effective_window,
    )


def _tuple_sort_key(key: _TupleKey) -> tuple[int, bytes, int, bytes, int]:
    return (
        key.ip_version,
        key.address_a.packed,
        key.port_a,
        key.address_b.packed,
        key.port_b,
    )


def _minimum(current: int | None, value: int | None) -> int | None:
    if value is None:
        return current
    return value if current is None else min(current, value)


def _maximum(current: int | None, value: int | None) -> int | None:
    if value is None:
        return current
    return value if current is None else max(current, value)


def _opposite_direction(direction: TCPDirection) -> TCPDirection:
    return (
        TCPDirection.B_TO_A if direction is TCPDirection.A_TO_B else TCPDirection.A_TO_B
    )


def _ack_matches_sequence(
    acknowledgment_number: int | None,
    sequence_number: int,
) -> bool:
    return acknowledgment_number is not None and acknowledgment_number == (
        (sequence_number + 1) & _UINT32_MAX
    )


def _interface_sort_key(interface_id: str) -> tuple[int, int | str]:
    try:
        return 0, int(interface_id)
    except ValueError:
        return 1, interface_id


def _projected_row(
    values: dict[str, str],
    projection: _Projection,
) -> str:
    """Build a synthetic row for focused collector tests."""
    return "\t".join(values.get(field, "") for field in projection.fields) + "\n"


__all__ = [
    "TCPCollectedConversation",
    "TCPConversationCollection",
    "TCPDirectionalEvidence",
    "TCPFieldCapabilities",
    "TCPFlagObservation",
    "TCPParserWarning",
    "TCPSymptomEvidence",
    "collect_tcp_conversation_evidence",
]
