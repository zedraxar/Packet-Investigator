"""Streaming, bounded collection of normalized DNS transaction evidence."""

from __future__ import annotations

from collections import deque
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from decimal import Decimal, InvalidOperation
from ipaddress import IPv4Address, IPv6Address, ip_address
from pathlib import Path
from typing import Literal, cast

from packet_investigator.models.dns_transactions import (
    DNS_MAX_ANSWERS_PER_MESSAGE,
    DNS_MAX_RETAINED_ANSWERS,
    DNS_TRANSACTION_TRACKING_LIMIT,
    DNSAnswerSummary,
    DNSEndpoint,
    DNSEvidenceProvenance,
    DNSMatchBasis,
    DNSMessageEvidence,
    DNSQueryKey,
    DNSTransactionEvidence,
    DNSTransactionIdentity,
    DNSTransport,
)
from packet_investigator.parsers.tshark import (
    DEFAULT_TIMEOUT_SECONDS,
    TsharkOutputError,
    find_tshark,
    get_tshark_field_capabilities,
    stream_tshark_fields,
    validate_capture_path,
)

MAX_TRACKED_TRANSACTIONS = DNS_TRANSACTION_TRACKING_LIMIT
MAX_REPRESENTATIVE_FRAMES = 8
MAX_RETAINED_WARNINGS = 100
MAX_RETAINED_ANSWERS = DNS_MAX_RETAINED_ANSWERS
_OCCURRENCE_SEPARATOR = "\x1e"

_REQUIRED_FIELDS = (
    "frame.number",
    "frame.time_epoch",
    "frame.interface_id",
    "ip.src",
    "ip.dst",
    "ipv6.src",
    "ipv6.dst",
    "udp.srcport",
    "udp.dstport",
    "tcp.srcport",
    "tcp.dstport",
    "tcp.stream",
    "dns.id",
    "dns.flags.response",
    "dns.flags.opcode",
    "dns.flags.rcode",
    "dns.flags.truncated",
    "dns.flags.recdesired",
    "dns.flags.recavail",
    "dns.count.queries",
    "dns.count.answers",
    "dns.qry.name",
    "dns.qry.type",
    "dns.qry.class",
)
_OPTIONAL_FIELDS = {
    "dns.response_in": "dns_response_in",
    "dns.response_to": "dns_response_to",
    "dns.time": "dns_time",
    "dns.retransmission": "dns_retransmission",
    "dns.retransmit_request": "dns_retransmit_request",
    "dns.retransmit_response": "dns_retransmit_response",
    "dns.unsolicited": "dns_unsolicited",
    "dns.resp.name": "dns_resp_name",
    "dns.resp.type": "dns_resp_type",
    "dns.resp.ttl": "dns_resp_ttl",
    "dns.a": "dns_a",
    "dns.aaaa": "dns_aaaa",
    "dns.cname": "dns_cname",
}
_ALL_FIELDS = (*_REQUIRED_FIELDS, *_OPTIONAL_FIELDS)
_ValueGetter = Callable[[str], str]


@dataclass(frozen=True, slots=True)
class DNSParserWarning:
    """One bounded privacy-safe optional or incomplete-row warning."""

    row_number: int
    reason_code: str
    field_names: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DNSFieldCapabilities:
    """Stable optional DNS capabilities for one collection run."""

    supported_optional: tuple[str, ...]
    unsupported_optional: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DNSCollectionResult:
    """Immutable bounded result of one streamed DNS evidence pass."""

    transactions: tuple[DNSTransactionEvidence, ...]
    representative_messages: tuple[DNSMessageEvidence, ...]
    unmatched_messages: tuple[DNSMessageEvidence, ...]
    ambiguous_messages: tuple[DNSMessageEvidence, ...]
    retained_answers: tuple[DNSAnswerSummary, ...]
    rows_processed: int
    dns_messages: int
    standard_query_messages: int
    query_messages: int
    response_messages: int
    tracked_transactions: int
    transaction_tracking_limit: int
    transaction_tracking_complete: bool
    untracked_transaction_messages: int
    matched_transactions: int
    unmatched_query_messages: int
    unmatched_response_messages: int
    ambiguous_message_matches: int
    response_code_counts: tuple[tuple[int, int], ...]
    repeated_query_observations: int
    repeated_response_observations: int
    tshark_retry_indicator_messages: int
    truncated_response_messages: int
    unsolicited_indicator_messages: int
    answer_records_observed: int
    answer_records_retained: int
    out_of_scope_dns_messages: int
    malformed_optional_fields: int
    incomplete_observations: int
    timestamp_regressions: int
    interfaces: tuple[str, ...]
    capabilities: DNSFieldCapabilities
    parser_warnings: tuple[DNSParserWarning, ...]
    total_parser_warnings: int
    collection_codes: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class _Projection:
    fields: tuple[str, ...]
    indices: dict[str, int]
    capabilities: DNSFieldCapabilities


@dataclass(frozen=True, slots=True)
class _NormalizedRow:
    message: DNSMessageEvidence
    response_in: int | None
    response_to: int | None
    answers_complete: bool


@dataclass(frozen=True, slots=True)
class _ParsedAnswers:
    summaries: tuple[DNSAnswerSummary, ...]
    approved_records_observed: int


class _FrameSample:
    """Keep first four and most recent four unique frame numbers."""

    __slots__ = ("_first", "_recent")

    def __init__(self) -> None:
        self._first: list[int] = []
        self._recent: deque[int] = deque(maxlen=4)

    def add(self, frame_number: int) -> None:
        if frame_number in self._first or frame_number in self._recent:
            return
        if len(self._first) < 4:
            self._first.append(frame_number)
        else:
            self._recent.append(frame_number)

    def finish(self) -> tuple[int, ...]:
        return tuple(sorted((*self._first, *self._recent)))


class _MessageSample:
    """Retain immutable messages selected by a frame sample."""

    __slots__ = ("_frames", "_messages")

    def __init__(self) -> None:
        self._frames = _FrameSample()
        self._messages: dict[int, DNSMessageEvidence] = {}

    def add(self, message: DNSMessageEvidence) -> None:
        self._frames.add(message.frame_number)
        self._messages[message.frame_number] = message
        retained = set(self._frames.finish())
        for frame_number in tuple(self._messages):
            if frame_number not in retained:
                del self._messages[frame_number]

    def finish(self) -> tuple[DNSMessageEvidence, ...]:
        return tuple(self._messages[frame] for frame in self._frames.finish())


@dataclass(slots=True)
class _TransactionState:
    requester: DNSEndpoint
    responder: DNSEndpoint
    transport: DNSTransport
    tcp_stream: int | None
    dns_id: int
    query: DNSQueryKey
    creation_index: int
    request_count: int = 0
    response_count: int = 0
    first_request_frame: int | None = None
    first_request_time: datetime | None = None
    first_response_frame: int | None = None
    first_response_time: datetime | None = None
    response_code_counts: dict[int, int] = field(default_factory=dict)
    retry_counts: dict[DNSEvidenceProvenance, int] = field(default_factory=dict)
    truncated_response_count: int = 0
    unsolicited_count: int = 0
    interface_ids: set[str] = field(default_factory=set)
    frames: _FrameSample = field(default_factory=_FrameSample)
    messages: _MessageSample = field(default_factory=_MessageSample)
    answers: list[DNSAnswerSummary] = field(default_factory=list)
    match_basis: DNSMatchBasis = DNSMatchBasis.UNMATCHED
    answer_collection_complete: bool = True
    elapsed_seconds: float | None = None
    elapsed_provenance: DNSEvidenceProvenance | None = None
    request_frames: set[int] = field(default_factory=set)
    expected_response_frames: set[int] = field(default_factory=set)

    def add_request(
        self,
        message: DNSMessageEvidence,
        response_in: int | None,
    ) -> None:
        if self.request_count:
            self._increment_retry(DNSEvidenceProvenance.RAW_HEADER)
        self.request_count += 1
        self.request_frames.add(message.frame_number)
        if response_in is not None:
            self.expected_response_frames.add(response_in)
        if self.first_request_frame is None:
            self.first_request_frame = message.frame_number
            self.first_request_time = message.timestamp
        self._add_common(message)

    def add_response(
        self,
        message: DNSMessageEvidence,
        basis: DNSMatchBasis,
    ) -> None:
        self.response_count += 1
        if self.first_response_frame is None:
            self.first_response_frame = message.frame_number
            self.first_response_time = message.timestamp
            self._set_elapsed(message)
        self.response_code_counts[message.response_code] = (
            self.response_code_counts.get(message.response_code, 0) + 1
        )
        self.truncated_response_count += int(message.truncated)
        self.unsolicited_count += int(message.tshark_unsolicited)
        if self.match_basis is not DNSMatchBasis.AMBIGUOUS:
            self.match_basis = basis
        self._add_common(message)

    def _add_common(self, message: DNSMessageEvidence) -> None:
        if message.interface_id is not None:
            self.interface_ids.add(message.interface_id)
        self.frames.add(message.frame_number)
        self.messages.add(message)
        self.answers.extend(message.answers)
        # Count marked messages, not overlapping flags on the same message.
        # Keep this unit consistent with the collection-wide retry statistic.
        if any(
            (
                message.tshark_retransmission,
                message.tshark_retransmit_request,
                message.tshark_retransmit_response,
            )
        ):
            self._increment_retry(DNSEvidenceProvenance.TSHARK_DERIVED)

    def _increment_retry(self, provenance: DNSEvidenceProvenance) -> None:
        self.retry_counts[provenance] = self.retry_counts.get(provenance, 0) + 1

    def _set_elapsed(self, response: DNSMessageEvidence) -> None:
        if response.tshark_response_time_seconds is not None:
            self.elapsed_seconds = response.tshark_response_time_seconds
            self.elapsed_provenance = DNSEvidenceProvenance.TSHARK_DERIVED
        elif self.first_request_time is not None:
            elapsed = (response.timestamp - self.first_request_time).total_seconds()
            if elapsed >= 0:
                self.elapsed_seconds = elapsed
                self.elapsed_provenance = (
                    DNSEvidenceProvenance.PACKET_INVESTIGATOR_DERIVED
                )


class _DNSAccumulator:
    """Mutable bounded state for one pass over projected DNS rows."""

    def __init__(self, projection: _Projection) -> None:
        self._projection = projection
        self._states: list[_TransactionState] = []
        self._rows_processed = 0
        self._dns_messages = 0
        self._standard_query_messages = 0
        self._query_messages = 0
        self._response_messages = 0
        self._untracked_transaction_messages = 0
        self._unmatched_response_messages = 0
        self._unmatched_query_observations = 0
        self._ambiguous_message_matches = 0
        self._repeated_query_observations = 0
        self._repeated_response_observations = 0
        self._tshark_retry_messages = 0
        self._truncated_response_messages = 0
        self._unsolicited_messages = 0
        self._answer_records_observed = 0
        self._retained_answers: list[DNSAnswerSummary] = []
        self._out_of_scope_messages = 0
        self._malformed_optional_fields = 0
        self._incomplete_observations = 0
        self._timestamp_regressions = 0
        self._previous_timestamp: datetime | None = None
        self._interfaces: set[str] = set()
        self._warnings: list[DNSParserWarning] = []
        self._total_warnings = 0
        self._collection_codes: set[str] = set()
        self._tracking_complete = True
        self._unmatched_sample = _MessageSample()
        self._ambiguous_sample = _MessageSample()

    def consume(self, rows: Iterable[str]) -> DNSCollectionResult:
        """Consume a row iterator once and finalize immutable evidence."""
        for row_number, line in enumerate(rows, start=1):
            if not line.rstrip("\r\n"):
                continue
            self._rows_processed += 1
            columns = line.rstrip("\r\n").split("\t")
            if len(columns) != len(self._projection.fields):
                raise TsharkOutputError(
                    f"Unexpected DNS output at row {row_number}: "
                    f"expected {len(self._projection.fields)} fields, "
                    f"received {len(columns)}."
                )
            row = self._normalize_row(columns, row_number)
            if row is not None:
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

        frame = _required_int(value("frame.number"), row_number, "frame.number", 1)
        timestamp = _required_timestamp(value("frame.time_epoch"), row_number)
        self._track_timestamp(timestamp)
        interface_id = _single_optional(value("frame.interface_id")) or None
        if interface_id is not None:
            self._interfaces.add(interface_id)
        endpoints = _parse_endpoints(value, row_number)
        if endpoints is None:
            self._incomplete(row_number, "DNS_TRANSPORT_SHAPE_UNSUPPORTED", ("ip",))
            return None
        source, destination, transport, tcp_stream = endpoints

        dns_id = _required_int(
            _single_required(value("dns.id"), row_number, "dns.id"),
            row_number,
            "dns.id",
            0,
            65_535,
        )
        is_response = _required_bool(
            _single_required(
                value("dns.flags.response"), row_number, "dns.flags.response"
            ),
            row_number,
            "dns.flags.response",
        )
        opcode = self._required_code(value, row_number, "dns.flags.opcode")
        # TShark may omit dns.flags.rcode on a query even though the
        # four wire RCODE bits are zero. A missing response RCODE remains
        # invalid; never silently substitute a successful response.
        raw_rcode = value("dns.flags.rcode")
        response_code = (
            0
            if not is_response and not raw_rcode
            else self._required_code(value, row_number, "dns.flags.rcode")
        )
        truncated = self._required_flag(value, row_number, "dns.flags.truncated")
        recursion_desired = self._required_flag(
            value, row_number, "dns.flags.recdesired"
        )
        raw_recavail = value("dns.flags.recavail")
        recursion_available = (
            False
            if not is_response and not raw_recavail
            else self._required_flag(value, row_number, "dns.flags.recavail")
        )
        query_count = self._required_code(value, row_number, "dns.count.queries")
        answer_count = self._required_code(value, row_number, "dns.count.answers")
        query = self._parse_query(value, query_count, row_number)

        response_in = self._optional_int(value, row_number, "dns.response_in")
        response_to = self._optional_int(value, row_number, "dns.response_to")
        tshark_time = self._optional_float(value, row_number, "dns.time")
        parsed_answers = self._parse_answers(value, answer_count, frame, row_number)
        self._answer_records_observed += answer_count
        remaining = max(0, MAX_RETAINED_ANSWERS - len(self._retained_answers))
        retained = parsed_answers.summaries[:remaining]
        self._retained_answers.extend(retained)
        answers_complete = (
            parsed_answers.approved_records_observed <= DNS_MAX_ANSWERS_PER_MESSAGE
            and len(retained) == len(parsed_answers.summaries)
        )
        if not answers_complete:
            self._collection_codes.add("DNS_ANSWER_RETENTION_LIMIT_REACHED")

        message = DNSMessageEvidence(
            frame_number=frame,
            timestamp=timestamp,
            interface_id=interface_id,
            source=source,
            destination=destination,
            transport=transport,
            tcp_stream=tcp_stream,
            transaction_id=dns_id,
            is_response=is_response,
            opcode=opcode,
            response_code=response_code,
            truncated=truncated,
            recursion_desired=recursion_desired,
            recursion_available=recursion_available,
            query=query,
            answer_record_count=answer_count,
            answers=retained,
            tshark_response_frame=response_in,
            tshark_request_frame=response_to,
            tshark_response_time_seconds=tshark_time,
            tshark_retransmission=self._optional_flag(
                value, row_number, "dns.retransmission"
            ),
            tshark_retransmit_request=self._optional_flag(
                value, row_number, "dns.retransmit_request"
            ),
            tshark_retransmit_response=self._optional_flag(
                value, row_number, "dns.retransmit_response"
            ),
            tshark_unsolicited=self._optional_flag(
                value, row_number, "dns.unsolicited"
            ),
        )
        if not answers_complete and message.query is not None:
            for state in self._states:
                if _state_matches_message_context(state, message):
                    state.answer_collection_complete = False
        return _NormalizedRow(message, response_in, response_to, answers_complete)

    def _required_code(
        self,
        value: _ValueGetter,
        row_number: int,
        field_name: str,
    ) -> int:
        return _required_int(
            _single_required(value(field_name), row_number, field_name),
            row_number,
            field_name,
            0,
            65_535,
        )

    def _required_flag(
        self,
        value: _ValueGetter,
        row_number: int,
        field_name: str,
    ) -> bool:
        return _required_bool(
            _single_required(value(field_name), row_number, field_name),
            row_number,
            field_name,
        )

    def _optional_int(
        self,
        value: _ValueGetter,
        row_number: int,
        field_name: str,
    ) -> int | None:
        parsed, malformed = _optional_int(_single_optional(value(field_name)))
        if malformed:
            self._optional_warning(row_number, field_name)
        return parsed

    def _optional_float(
        self,
        value: _ValueGetter,
        row_number: int,
        field_name: str,
    ) -> float | None:
        parsed, malformed = _optional_float(_single_optional(value(field_name)))
        if malformed:
            self._optional_warning(row_number, field_name)
            if field_name == "dns.time":
                self._collection_codes.add("DNS_TIMESTAMP_LIMITATION")
        return parsed

    def _optional_flag(
        self,
        value: _ValueGetter,
        row_number: int,
        field_name: str,
    ) -> bool:
        parsed, malformed = _optional_bool(_single_optional(value(field_name)))
        if malformed:
            self._optional_warning(row_number, field_name)
        return bool(parsed)

    def _parse_query(
        self,
        value: _ValueGetter,
        query_count: int,
        row_number: int,
    ) -> DNSQueryKey | None:
        names = _occurrences(value("dns.qry.name"))
        types = _occurrences(value("dns.qry.type"))
        classes = _occurrences(value("dns.qry.class"))
        if query_count != 1 or not (len(names) == len(types) == len(classes) == 1):
            self._incomplete(
                row_number,
                "DNS_QUESTION_UNAVAILABLE",
                ("dns.qry.name", "dns.qry.type", "dns.qry.class"),
            )
            return None
        display_name = names[0]
        normalized = display_name.lower().removesuffix(".")
        try:
            return DNSQueryKey(
                name=normalized,
                display_name=display_name,
                query_type=_required_int(
                    types[0], row_number, "dns.qry.type", 0, 65_535
                ),
                query_class=_required_int(
                    classes[0], row_number, "dns.qry.class", 0, 65_535
                ),
            )
        except ValueError:
            self._incomplete(
                row_number,
                "DNS_QUESTION_UNAVAILABLE",
                ("dns.qry.name",),
            )
            return None

    def _parse_answers(
        self,
        value: _ValueGetter,
        answer_count: int,
        frame: int,
        row_number: int,
    ) -> _ParsedAnswers:
        types = _occurrences(value("dns.resp.type"))[:answer_count]
        names = _occurrences(value("dns.resp.name"))[:answer_count]
        ttls = _occurrences(value("dns.resp.ttl"))[:answer_count]
        values_by_type = {
            1: deque(_occurrences(value("dns.a"))),
            5: deque(_occurrences(value("dns.cname"))),
            28: deque(_occurrences(value("dns.aaaa"))),
        }
        summaries: list[DNSAnswerSummary] = []
        approved_records_observed = 0
        for index, type_text in enumerate(types):
            try:
                record_type = _required_int(
                    type_text, row_number, "dns.resp.type", 0, 65_535
                )
                if record_type not in (1, 5, 28):
                    continue
                approved_record_type = cast(Literal[1, 5, 28], record_type)
                approved_records_observed += 1
                if len(summaries) >= DNS_MAX_ANSWERS_PER_MESSAGE:
                    continue
                owner = names[index] if index < len(names) and names[index] else None
                ttl = (
                    _required_int(ttls[index], row_number, "dns.resp.ttl", 0)
                    if index < len(ttls) and ttls[index]
                    else None
                )
                answer_value = self._approved_answer_value(
                    values_by_type, approved_record_type
                )
                summaries.append(
                    DNSAnswerSummary(
                        record_type=approved_record_type,
                        owner_name=owner,
                        ttl_seconds=ttl,
                        value=answer_value,
                        representative_frame=frame,
                        provenance=DNSEvidenceProvenance.RAW_HEADER,
                    )
                )
            except (TsharkOutputError, ValueError):
                self._optional_warning(row_number, "dns.answer")
        return _ParsedAnswers(
            summaries=tuple(sorted(summaries, key=_answer_sort_key)),
            approved_records_observed=approved_records_observed,
        )

    @staticmethod
    def _approved_answer_value(
        values_by_type: dict[int, deque[str]],
        record_type: int,
    ) -> str | None:
        values = values_by_type.get(record_type)
        if not values:
            return None
        value = values.popleft()
        if record_type == 1:
            return str(IPv4Address(value))
        if record_type == 28:
            return str(IPv6Address(value))
        return value

    def _consume_normalized(self, row: _NormalizedRow) -> None:
        message = row.message
        self._dns_messages += 1
        if message.opcode != 0:
            self._out_of_scope_messages += 1
            self._collection_codes.add("DNS_UNSUPPORTED_OPCODE_LIMITATION")
            return
        self._standard_query_messages += 1
        if message.is_response:
            self._response_messages += 1
            self._truncated_response_messages += int(message.truncated)
            self._unsolicited_messages += int(message.tshark_unsolicited)
            self._consume_response(row)
        else:
            self._query_messages += 1
            self._consume_query(row)
        if any(
            (
                message.tshark_retransmission,
                message.tshark_retransmit_request,
                message.tshark_retransmit_response,
            )
        ):
            self._tshark_retry_messages += 1

    def _consume_query(self, row: _NormalizedRow) -> None:
        message = row.message
        if message.query is None:
            self._unmatched_query_observations += 1
            self._unmatched_sample.add(message)
            return
        candidates = [
            state
            for state in self._states
            if state.response_count == 0 and _state_matches_request(state, message)
        ]
        if len(candidates) == 1:
            candidates[0].add_request(message, row.response_in)
            if not row.answers_complete:
                candidates[0].answer_collection_complete = False
            self._repeated_query_observations += 1
            return
        state = self._register(message.source, message.destination, message)
        if state is not None:
            state.add_request(message, row.response_in)
            state.answer_collection_complete = row.answers_complete

    def _consume_response(self, row: _NormalizedRow) -> None:
        message = row.message
        candidates = self._linked_candidates(row)
        basis = DNSMatchBasis.TSHARK_LINKAGE
        if not candidates:
            candidates = [
                state
                for state in self._states
                if state.response_count == 0 and _state_matches_response(state, message)
            ]
            basis = DNSMatchBasis.EXACT_QUERY_KEY
        if not candidates:
            candidates = [
                state
                for state in self._states
                if _state_matches_response(state, message)
            ]
        if len(candidates) > 1:
            self._ambiguous_message_matches += 1
            self._ambiguous_sample.add(message)
            self._collection_codes.add("DNS_MATCH_AMBIGUOUS_LIMITATION")
            for state in candidates:
                state.match_basis = DNSMatchBasis.AMBIGUOUS
            return
        if len(candidates) == 1:
            state = candidates[0]
            if state.response_count:
                self._repeated_response_observations += 1
            state.add_response(message, basis)
            if not row.answers_complete:
                state.answer_collection_complete = False
            if (
                state.first_request_time is not None
                and message.timestamp < state.first_request_time
            ):
                self._collection_codes.add("DNS_TIMESTAMP_LIMITATION")
            return
        self._unmatched_response_messages += 1
        self._unmatched_sample.add(message)
        if message.query is None:
            return
        registered = self._register(message.destination, message.source, message)
        if registered is not None:
            registered.add_response(message, DNSMatchBasis.UNMATCHED)
            registered.answer_collection_complete = row.answers_complete

    def _linked_candidates(self, row: _NormalizedRow) -> list[_TransactionState]:
        return [
            state
            for state in self._states
            if (
                (
                    row.response_to is not None
                    and row.response_to in state.request_frames
                )
                or row.message.frame_number in state.expected_response_frames
            )
            and _state_matches_response(state, row.message)
        ]

    def _register(
        self,
        requester: DNSEndpoint,
        responder: DNSEndpoint,
        message: DNSMessageEvidence,
    ) -> _TransactionState | None:
        if len(self._states) >= MAX_TRACKED_TRANSACTIONS:
            self._tracking_complete = False
            self._untracked_transaction_messages += 1
            self._collection_codes.add("DNS_TRANSACTION_TRACKING_LIMIT_REACHED")
            return None
        assert message.query is not None
        state = _TransactionState(
            requester=requester,
            responder=responder,
            transport=message.transport,
            tcp_stream=message.tcp_stream,
            dns_id=message.transaction_id,
            query=message.query,
            creation_index=len(self._states),
        )
        self._states.append(state)
        return state

    def _track_timestamp(self, timestamp: datetime) -> None:
        if (
            self._previous_timestamp is not None
            and timestamp < self._previous_timestamp
        ):
            self._timestamp_regressions += 1
            self._collection_codes.add("DNS_TIMESTAMP_LIMITATION")
        self._previous_timestamp = timestamp

    def _optional_warning(self, row_number: int, field_name: str) -> None:
        self._malformed_optional_fields += 1
        self._warn(row_number, "DNS_OPTIONAL_FIELD_MALFORMED", (field_name,))

    def _incomplete(
        self,
        row_number: int,
        reason_code: str,
        fields: tuple[str, ...],
    ) -> None:
        self._incomplete_observations += 1
        self._collection_codes.add(reason_code)
        self._warn(row_number, reason_code, fields)

    def _warn(
        self,
        row_number: int,
        reason_code: str,
        fields: tuple[str, ...],
    ) -> None:
        self._total_warnings += 1
        if len(self._warnings) < MAX_RETAINED_WARNINGS:
            self._warnings.append(DNSParserWarning(row_number, reason_code, fields[:3]))

    def _finish(self) -> DNSCollectionResult:
        states = sorted(self._states, key=_state_sort_key)
        transactions = tuple(
            _freeze_state(state, index, self._tracking_complete)
            for index, state in enumerate(states, start=1)
        )
        messages = tuple(
            sorted(
                (message for state in states for message in state.messages.finish()),
                key=lambda message: message.frame_number,
            )
        )
        response_counts: dict[int, int] = {}
        for state in states:
            for code, count in state.response_code_counts.items():
                response_counts[code] = response_counts.get(code, 0) + count
        unmatched_queries = sum(
            state.request_count for state in states if state.response_count == 0
        )
        return DNSCollectionResult(
            transactions=transactions,
            representative_messages=messages,
            unmatched_messages=self._unmatched_sample.finish(),
            ambiguous_messages=self._ambiguous_sample.finish(),
            retained_answers=tuple(self._retained_answers),
            rows_processed=self._rows_processed,
            dns_messages=self._dns_messages,
            standard_query_messages=self._standard_query_messages,
            query_messages=self._query_messages,
            response_messages=self._response_messages,
            tracked_transactions=len(transactions),
            transaction_tracking_limit=MAX_TRACKED_TRANSACTIONS,
            transaction_tracking_complete=self._tracking_complete,
            untracked_transaction_messages=self._untracked_transaction_messages,
            matched_transactions=sum(
                item.request_count > 0
                and item.response_count > 0
                and item.identity.match_basis
                in {DNSMatchBasis.TSHARK_LINKAGE, DNSMatchBasis.EXACT_QUERY_KEY}
                for item in transactions
            ),
            unmatched_query_messages=(
                unmatched_queries + self._unmatched_query_observations
            ),
            unmatched_response_messages=self._unmatched_response_messages,
            ambiguous_message_matches=self._ambiguous_message_matches,
            response_code_counts=tuple(sorted(response_counts.items())),
            repeated_query_observations=self._repeated_query_observations,
            repeated_response_observations=self._repeated_response_observations,
            tshark_retry_indicator_messages=self._tshark_retry_messages,
            truncated_response_messages=self._truncated_response_messages,
            unsolicited_indicator_messages=self._unsolicited_messages,
            answer_records_observed=self._answer_records_observed,
            answer_records_retained=len(self._retained_answers),
            out_of_scope_dns_messages=self._out_of_scope_messages,
            malformed_optional_fields=self._malformed_optional_fields,
            incomplete_observations=self._incomplete_observations,
            timestamp_regressions=self._timestamp_regressions,
            interfaces=tuple(sorted(self._interfaces, key=_interface_sort_key)),
            capabilities=self._projection.capabilities,
            parser_warnings=tuple(self._warnings),
            total_parser_warnings=self._total_warnings,
            collection_codes=tuple(sorted(self._collection_codes)),
        )


def collect_dns_transaction_evidence(
    capture_path: Path,
    *,
    timeout: float = DEFAULT_TIMEOUT_SECONDS,
    executable: str = "tshark",
) -> DNSCollectionResult:
    """Collect bounded normalized DNS evidence from a validated capture."""
    if isinstance(timeout, bool) or timeout <= 0:
        raise ValueError("Timeout must be greater than zero.")
    path, _ = validate_capture_path(capture_path)
    resolved_executable = find_tshark(executable)
    supported = get_tshark_field_capabilities(resolved_executable, timeout, _ALL_FIELDS)
    projection = _build_projection(supported)
    return stream_tshark_fields(
        resolved_executable,
        path,
        projection.fields,
        timeout,
        _DNSAccumulator(projection).consume,
        operation="DNS transaction collection",
        display_filter="dns && !(mdns || llmnr || nbns)",
        field_occurrence="a",
        aggregator=_OCCURRENCE_SEPARATOR,
    )


def _collect_dns_rows(
    rows: Iterable[str],
    *,
    supported_fields: frozenset[str] | None = None,
) -> DNSCollectionResult:
    """Collect synthetic projected rows without invoking TShark."""
    capabilities = (
        frozenset(_ALL_FIELDS) if supported_fields is None else supported_fields
    )
    projection = _build_projection(capabilities)
    return _DNSAccumulator(projection).consume(rows)


def _build_projection(supported_fields: frozenset[str]) -> _Projection:
    missing = set(_REQUIRED_FIELDS) - supported_fields
    if missing:
        raise TsharkOutputError(
            f"TShark lacks required DNS fields: {', '.join(sorted(missing))}."
        )
    selected = tuple(field for field in _ALL_FIELDS if field in supported_fields)
    return _Projection(
        fields=selected,
        indices={field: index for index, field in enumerate(selected)},
        capabilities=DNSFieldCapabilities(
            supported_optional=tuple(
                capability
                for field, capability in _OPTIONAL_FIELDS.items()
                if field in supported_fields
            ),
            unsupported_optional=tuple(
                capability
                for field, capability in _OPTIONAL_FIELDS.items()
                if field not in supported_fields
            ),
        ),
    )


def _freeze_state(
    state: _TransactionState,
    index: int,
    tracking_complete: bool,
) -> DNSTransactionEvidence:
    identity = DNSTransactionIdentity(
        transaction_id=f"dns-{index:06d}",
        requester=state.requester,
        responder=state.responder,
        transport=state.transport,
        dns_id=state.dns_id,
        query=state.query,
        match_basis=state.match_basis,
    )
    return DNSTransactionEvidence(
        identity=identity,
        request_count=state.request_count,
        response_count=state.response_count,
        first_request_frame=state.first_request_frame,
        first_request_time=state.first_request_time,
        first_response_frame=state.first_response_frame,
        first_response_time=state.first_response_time,
        response_code_counts=tuple(sorted(state.response_code_counts.items())),
        retry_indicator_counts=tuple(
            (provenance, state.retry_counts[provenance])
            for provenance in DNSEvidenceProvenance
            if state.retry_counts.get(provenance, 0)
        ),
        truncated_response_count=state.truncated_response_count,
        unsolicited_response_indicator_count=state.unsolicited_count,
        elapsed_to_first_response_seconds=state.elapsed_seconds,
        elapsed_provenance=state.elapsed_provenance,
        interface_ids=tuple(sorted(state.interface_ids, key=_interface_sort_key)),
        representative_frames=state.frames.finish(),
        answers=tuple(sorted(state.answers, key=_answer_sort_key)),
        tracking_complete=tracking_complete,
        answer_collection_complete=state.answer_collection_complete,
    )


def _parse_endpoints(
    value: _ValueGetter,
    row_number: int,
) -> tuple[DNSEndpoint, DNSEndpoint, DNSTransport, int | None] | None:
    address_pairs = [
        (4, _single_optional(value("ip.src")), _single_optional(value("ip.dst"))),
        (
            6,
            _single_optional(value("ipv6.src")),
            _single_optional(value("ipv6.dst")),
        ),
    ]
    present_addresses = [item for item in address_pairs if item[1] and item[2]]
    transports = [
        (
            DNSTransport.UDP,
            _single_optional(value("udp.srcport")),
            _single_optional(value("udp.dstport")),
        ),
        (
            DNSTransport.TCP,
            _single_optional(value("tcp.srcport")),
            _single_optional(value("tcp.dstport")),
        ),
    ]
    present_transports = [item for item in transports if item[1] and item[2]]
    if len(present_addresses) != 1 or len(present_transports) != 1:
        return None
    version, source_text, destination_text = present_addresses[0]
    transport, source_port_text, destination_port_text = present_transports[0]
    try:
        source_address = ip_address(source_text)
        destination_address = ip_address(destination_text)
    except ValueError as error:
        raise TsharkOutputError(
            f"Invalid DNS endpoint address at row {row_number}."
        ) from error
    if source_address.version != version or destination_address.version != version:
        raise TsharkOutputError(f"Inconsistent DNS address family at row {row_number}.")
    source_port = _required_int(
        source_port_text, row_number, f"{transport.value}.srcport", 0, 65_535
    )
    destination_port = _required_int(
        destination_port_text, row_number, f"{transport.value}.dstport", 0, 65_535
    )
    stream = None
    if transport is DNSTransport.TCP:
        stream_text = _single_optional(value("tcp.stream"))
        if stream_text:
            stream = _required_int(stream_text, row_number, "tcp.stream", 0)
    return (
        DNSEndpoint(ip_version=version, address=source_address, port=source_port),
        DNSEndpoint(
            ip_version=version,
            address=destination_address,
            port=destination_port,
        ),
        transport,
        stream,
    )


def _state_matches_message_context(
    state: _TransactionState,
    message: DNSMessageEvidence,
) -> bool:
    return (
        message.query == state.query
        and message.transaction_id == state.dns_id
        and message.transport is state.transport
        and _streams_compatible(state.tcp_stream, message.tcp_stream)
    )


def _state_matches_request(
    state: _TransactionState,
    message: DNSMessageEvidence,
) -> bool:
    return (
        _state_matches_message_context(state, message)
        and message.source == state.requester
        and message.destination == state.responder
    )


def _state_matches_response(
    state: _TransactionState,
    message: DNSMessageEvidence,
) -> bool:
    return (
        (message.query is None or message.query == state.query)
        and message.transaction_id == state.dns_id
        and message.transport is state.transport
        and message.source == state.responder
        and message.destination == state.requester
        and _streams_compatible(state.tcp_stream, message.tcp_stream)
    )


def _streams_compatible(first: int | None, second: int | None) -> bool:
    return first is None or second is None or first == second


def _required_timestamp(value: str, row_number: int) -> datetime:
    text = _single_required(value, row_number, "frame.time_epoch")
    try:
        epoch = Decimal(text)
    except InvalidOperation as error:
        raise TsharkOutputError(
            f"Invalid DNS timestamp at row {row_number}."
        ) from error
    if not epoch.is_finite() or epoch < 0:
        raise TsharkOutputError(f"Invalid DNS timestamp at row {row_number}.")
    try:
        return datetime.fromtimestamp(float(epoch), tz=UTC)
    except (OverflowError, OSError, ValueError) as error:
        raise TsharkOutputError(
            f"DNS timestamp is outside the supported range at row {row_number}."
        ) from error


def _required_int(
    value: str,
    row_number: int,
    field_name: str,
    minimum: int,
    maximum: int | None = None,
) -> int:
    try:
        parsed = int(value, 0)
    except ValueError as error:
        raise TsharkOutputError(
            f"Invalid required DNS field {field_name} at row {row_number}."
        ) from error
    if parsed < minimum or (maximum is not None and parsed > maximum):
        raise TsharkOutputError(
            f"Invalid required DNS field {field_name} at row {row_number}."
        )
    return parsed


def _required_bool(value: str, row_number: int, field_name: str) -> bool:
    parsed, malformed = _optional_bool(value)
    if parsed is None or malformed:
        raise TsharkOutputError(
            f"Invalid required DNS field {field_name} at row {row_number}."
        )
    return parsed


def _optional_bool(value: str) -> tuple[bool | None, bool]:
    if not value:
        return None, False
    if value in {"1", "True"}:
        return True, False
    if value in {"0", "False"}:
        return False, False
    return None, True


def _optional_int(value: str) -> tuple[int | None, bool]:
    if not value:
        return None, False
    try:
        parsed = int(value, 0)
    except ValueError:
        return None, True
    return (parsed, False) if parsed >= 0 else (None, True)


def _optional_float(value: str) -> tuple[float | None, bool]:
    if not value:
        return None, False
    try:
        parsed = Decimal(value)
    except InvalidOperation:
        return None, True
    if not parsed.is_finite() or parsed < 0:
        return None, True
    return float(parsed), False


def _single_required(value: str, row_number: int, field_name: str) -> str:
    occurrences = _occurrences(value)
    if len(occurrences) != 1 or not occurrences[0]:
        raise TsharkOutputError(
            f"Invalid required DNS field {field_name} at row {row_number}."
        )
    return occurrences[0]


def _single_optional(value: str) -> str:
    occurrences = _occurrences(value)
    return occurrences[0] if len(occurrences) == 1 else ""


def _occurrences(value: str) -> tuple[str, ...]:
    return tuple(value.split(_OCCURRENCE_SEPARATOR)) if value else ()


def _state_sort_key(
    state: _TransactionState,
) -> tuple[int, tuple[int, bytes, int], tuple[int, bytes, int], str, int, str, int]:
    return (
        min(state.frames.finish(), default=0),
        _endpoint_sort_key(state.requester),
        _endpoint_sort_key(state.responder),
        state.transport.value,
        state.dns_id,
        state.query.name,
        state.creation_index,
    )


def _answer_sort_key(
    answer: DNSAnswerSummary,
) -> tuple[int, str, str, int, int, str]:
    return (
        answer.record_type,
        answer.owner_name or "",
        answer.value or "",
        answer.ttl_seconds if answer.ttl_seconds is not None else -1,
        answer.representative_frame,
        answer.provenance.value,
    )


def _endpoint_sort_key(endpoint: DNSEndpoint) -> tuple[int, bytes, int]:
    return endpoint.ip_version, endpoint.address.packed, endpoint.port


def _interface_sort_key(interface_id: str) -> tuple[int, int | str]:
    try:
        return (0, int(interface_id))
    except ValueError:
        return (1, interface_id)


__all__ = [
    "DNSCollectionResult",
    "DNSFieldCapabilities",
    "DNSParserWarning",
    "collect_dns_transaction_evidence",
]
